use node_visitor::node_proxy;
use pallets_api::bool::runtime_types::pallet_facility::pallet::DIdentity;
use pallets_api::client::SubClient;
use ringvrf::ed25519::{Keypair, Public, Secret, Signature};

use crate::sgx_key::{get_did, get_secret_key};
use crate::utils::sha3_hash256;
use crate::ONLINESK;

pub async fn register_sgx_2(
    subclient_url: String,
    subclient_warn_time: u128,
    config_version: u16,
) -> Result<(), String> {
    let subclient =
        SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(subclient_warn_time))
            .await?;

    let secret_key = get_secret_key().await.map_err(|e| e.to_string())?;
    let public_key: Public = secret_key.into();
    let key_pair = Keypair::from_secret(&secret_key);
    let pk_vec = public_key.as_bytes();

    *ONLINESK.write().unwrap() = Some(secret_key);

    #[cfg(feature = "occlum-enclave")]
    let (report, enclave_hash) = {
        use occlum_ra::attestation::{AttestationReport, AttestationStyle, DcapAttestation};
        use occlum_ra::dcap::DcapAttestationReport;

        let dcap_report = DcapAttestation::create_report(&pk_vec)
            .map_err(|_| "Dcap create_report failed".to_string())?;
        let dar = DcapAttestationReport::from_bytes(dcap_report.quote.clone()).unwrap();
        let enclave: Vec<u8> = dar.quote.inner.report_body.mr_enclave.m.to_vec();
        let (report_payload, enclave_hash) = (dcap_report.into_payload(), enclave);
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
    log::info!(
        "enclave hash: 0x{}, attestation: 0x{}",
        hex::encode(&enclave_hash),
        hex::encode(&report)
    );
    let msg = [report.clone(), config_version.to_be_bytes().to_vec()].concat();
    let signature = key_pair
        .sign(&msg)
        .map_err(|_| "Dcap create_report failed".to_string())?
        .as_bytes()
        .to_vec();
    let eth_owner = subclient.account_id().await.0;
    log::info!("device owner: 0x{}", hex::encode(&eth_owner));

    let did = get_did(config_version).await;
    let device_id = DIdentity {
        version: did.0,
        pk: did.1,
    };
    let device = pallets_api::device_info(&subclient, &device_id, None).await;

    if let Some(dv) = device {
        let pk = "0x".to_string() + &hex::encode(&device_id.pk);
        if hex::encode(dv.owner.0).to_lowercase() != hex::encode(&eth_owner).to_lowercase() {
            log::info!(target: "key_server", "start register sgx");
        } else {
            let msg = format!(
                "device has been registered for version: {:?}, pk: {:?}",
                device_id.version, pk
            );
            log::info!(target: "key_server", "register sgx: {:?}", msg);
            return Ok(());
        }
    }

    tokio::spawn(async move {
        loop {
            let did = get_did(config_version).await;
            match node_proxy::call_register(&subclient, did, report.clone(), signature.clone())
                .await
            {
                Ok(res) => {
                    log::info!(target: "key_server", "register sgx: {:?}", res);
                    return Ok::<(), String>(());
                }
                Err(e) => log::info!(target: "key_server", "register failed for {:?}", e),
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });

    Ok(())
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
        Err(e) => return Err("verify error {:?e}".to_string()),
    }
}

pub fn verify_sig_from_string_public(
    msg: Vec<u8>,
    signature: Vec<u8>,
    pubkey: String,
) -> Result<bool, String> {
    let msg = sha3_hash256(&msg);

    let keypair = Keypair {
        secret: Secret::random(), // TODO:: fix it 
        public: Public::from_bytes(&hex::decode(pubkey).unwrap()).unwrap(),
    };

    match keypair.verify(&msg, &Signature::from_bytes(&signature).unwrap()) {
        Ok(()) => return Ok(true),
        Err(e) => return Err("verify error {:?e}".to_string()),
    }
}
