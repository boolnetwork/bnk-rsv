use pallets_api::client::SubClient;
use pallets_api::version_list;
use pallets_api::{self, bool::runtime_types::pallet_facility::pallet::DIdentity};
use ringvrf::ed25519::{Keypair, Public, Secret, Signature};

use crate::sgx_key::{get_did, get_secret_key_dcap};
use crate::utils::sha3_hash256;
use crate::{ONLINESK, RELATEDEVICEIDS};

pub async fn register_sgx_2(
    subclient_url: String,
    subclient_warn_time: u128,
    config_version: u16,
    device_owner: String,
    watcher_device_id: String,
    reg_type: u16,
) -> Result<u16, String> {
    let subclient =
        SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(subclient_warn_time))
            .await?;

    let secret_key = get_secret_key_dcap().await.map_err(|e| e.to_string())?;
    let secret_key = reg_key(secret_key, reg_type);
    let public_key: Public = secret_key.into();
    let key_pair = Keypair::from_secret(&secret_key);
    let pk_vec = public_key.as_bytes();

    *ONLINESK.write().unwrap() = Some(secret_key);
    #[cfg(feature = "occlum-enclave")]
    let (report, enclave_hash) = {
        use occlum_ra::attestation::{AttestationReport, AttestationStyle, DcapAttestation};
        use occlum_ra::dcap::DcapAttestationReport;

        let (report_payload, enclave_hash) = {
            let dcap_report = DcapAttestation::create_report(&pk_vec)
                .map_err(|_| "Dcap create_report failed".to_string())?;
            let dar = DcapAttestationReport::from_bytes(dcap_report.quote.clone())
                .map_err(|_| "Dcap from_bytes failed".to_string())?;
            let enclave: Vec<u8> = dar.quote.inner.report_body.mr_enclave.m.to_vec();
            (dcap_report.into_payload(), enclave)
        };
        (
            AttestationReport {
                style: AttestationStyle::DCAP,
                data: report_payload,
            }
            .into_payload(),
            enclave_hash,
        )
    };
    #[cfg(not(feature = "occlum-enclave"))]
    let (report, enclave_hash) = (pk_vec.clone(), vec![0u8; 32]);
    tracing::info!(
        "enclave hash: 0x{}, attestation: 0x{}",
        hex::encode(&enclave_hash),
        hex::encode(&report)
    );

    let sub_client = subclient.clone();
    let current_version = version_list(&sub_client, None)
        .await
        .ok_or("get version list".to_string())?
        .pop()
        .ok_or("version list empty".to_string())?;
    let msg = [report.clone(), current_version.to_be_bytes().to_vec()].concat();
    let signature = key_pair
        .sign(&msg)
        .map_err(|e| format!("ed25519 sign {e:?}"))?
        .as_bytes()
        .to_vec();
    let config_owner = device_owner.clone();
    tracing::info!("device owner: {}", config_owner);
    tracing::info!("device id pk: {}", hex::encode(&pk_vec));

    // Check whether the device has been registered or registered by others
    let did = get_did(config_version).await;
    let device_id = DIdentity {
        version: did.0,
        pk: did.1,
    };
    let device = pallets_api::device_info_rpc(&sub_client, device_id.pk.clone(), None).await;
    if let Some(d) = device {
        println!("registered");
        let sub_client2 = sub_client.clone();
        let id = d.watcher_deviceid.clone();
        tokio::spawn(async move {
            loop {
                println!("=======relate_deviceid_rpc==spawn======");
                let res = pallets_api::relate_deviceid_rpc(&sub_client2, id.clone(), None).await;
                *RELATEDEVICEIDS.write().unwrap() = res.clone();
                for device in res.unwrap_or(vec![vec![0]]){
                    println!("relate device list : {}", hex::encode(&device));
                }
    
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });

        return Err("registered".to_string());
    }
    // try to register device
    if !crate::utils::verify_enclave_hash(&sub_client, current_version, enclave_hash.clone())
        .await?
    {
        return Err(
            "register device failed due to invalid enclave_hash: {:?enclave_hash}".to_string(),
        );
    }
    let sub_client2 = sub_client.clone();
    let watcher_device_id2 = watcher_device_id.clone();
    tokio::spawn(async move {
        loop {
            let mut did = get_did(config_version).await;
            did.0 = current_version;
            match crate::utils::call_register_rpc(
                &sub_client.clone(),
                &config_owner,
                did,
                report.clone(),
                signature.clone(),
                &watcher_device_id,
            )
            .await
            {
                Ok(res) => {
                    tracing::info!(target: "key_server", "register sgx: {:?}", res);
                    return;
                }
                Err(e) => tracing::info!(target: "key_server", "register failed for {:?}", e),
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });

    tokio::spawn(async move {
        loop {
            let id = hex::decode(crate::utils::no_prefix(&watcher_device_id2))
                .map_err(|e| e.to_string())
                .unwrap();

            let res = pallets_api::relate_deviceid_rpc(&sub_client2, id, None).await;
            tracing::info!(target: "key_server", "relate device list : {:?}", res);

            *RELATEDEVICEIDS.write().unwrap() = res;

            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });

    Ok(current_version)
}

pub async fn fetch_relate_device_id(watcher_device_id: Vec<u8>, subclient_url: String) {
    let subclient = SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(30))
        .await
        .unwrap();

    tokio::spawn(async move {
        loop {
            let res = pallets_api::relate_deviceid_rpc(&subclient,
                 watcher_device_id.clone(), None).await;
            tracing::info!(target: "key_server", "relate device list : {:?}", res);

            *RELATEDEVICEIDS.write().unwrap() = res;

            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
}

pub fn sign_with_device_sgx_key(msg: Vec<u8>) -> Result<Vec<u8>, String> {
    let key_pair = Keypair::from_secret(ONLINESK.read().unwrap().as_ref().unwrap());
    let msg = sha3_hash256(&msg);
    let sig = key_pair
        .sign(&msg)
        .map_err(|_| "sign error".to_string())?
        .as_bytes()
        .to_vec();

    Ok(sig)
}

pub fn verify_sig(msg: Vec<u8>, signature: Vec<u8>, pubkey: Vec<u8>) -> Result<bool, String> {
    let key_pair = Keypair::from_secret(ONLINESK.read().unwrap().as_ref().unwrap());
    let msg = sha3_hash256(&msg);

    if pubkey != key_pair.public.as_bytes() {
        return Err("pubkey isnt match".to_string());
    }

    match key_pair.verify(&msg, &Signature::from_bytes(&signature).unwrap()) {
        Ok(()) => return Ok(true),
        Err(e) => return Err(format!("verify error {e:?}")),
    }
}

pub fn verify_sig_from_string_public(
    msg: Vec<u8>,
    signature: Vec<u8>,
    pubkey: String,
) -> Result<bool, String> {
    if !relate_device(&pubkey) {
        return Err(format!("not relate_device"));
    }

    let msg = sha3_hash256(&msg);

    let keypair = Keypair {
        secret: Secret::random(), // TODO:: fix it
        public: Public::from_bytes(&hex::decode(pubkey).unwrap()).unwrap(),
    };

    match keypair.verify(&msg, &Signature::from_bytes(&signature).unwrap()) {
        Ok(()) => return Ok(true),
        Err(e) => return Err(format!("verify error {e:?}")),
    }
}

pub fn relate_device(pubkey: &str) -> bool {
    let list = RELATEDEVICEIDS.read().unwrap().as_ref().unwrap().clone();
    let pk = hex::decode(pubkey).unwrap();
    tracing::info!(target: "key_server", "relate device list : {:?}", list);
    tracing::info!(target: "key_server", "pubkey : {:?}", pk);

    list.contains(&pk)
}

pub fn reg_key(deviceidkey: Secret, reg_type: u16) -> Secret {
    let type_bytes = match reg_type {
        1u16 => crate::BTCD.clone(),
        2 => crate::ELECTRS.clone(),
        3 => crate::MONITOR.clone(),
        _ => crate::UNKNOWN.clone(),
    };

    let type_key = Secret::from_bytes(&type_bytes).unwrap();

    let new_secret_key = deviceidkey.0 + type_key.0;

    Secret::from_bytes(new_secret_key.as_bytes()).unwrap()
}
