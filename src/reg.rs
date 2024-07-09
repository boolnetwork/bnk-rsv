use node_visitor::pallets_api::{
    device_votes_for_current_epoch, device_votes_for_next_epoch, hash_to_version,
    update_device_version, version_list, BoolSubClient,
};
use node_visitor::{
    node_proxy,
    pallets_api::{
        self,
        bool::runtime_types::{
            pallet_facility::pallet::DIdentity, pallet_mining::pallet::DeviceState,
        },
    },
};
use pallets_api::client::SubClient;
use ringvrf::ed25519::{Keypair, Public, Secret, Signature};

use crate::sgx_key::{get_did, get_secret_key_dcap};
use crate::utils::sha3_hash256;
use crate::ONLINESK;

pub async fn register_sgx_2(
    subclient_url: String,
    subclient_warn_time: u128,
    config_version: u16,
    device_owner: String,
) -> Result<u16, String> {
    let subclient =
        SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(subclient_warn_time))
            .await?;

    let secret_key = get_secret_key_dcap().await.map_err(|e| e.to_string())?;
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
    log::info!(
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
        .map_err(|e| "ed25519 sign {:?e}".to_string())?
        .as_bytes()
        .to_vec();
    let config_owner = device_owner.clone();
    log::info!("device owner: {}", config_owner);

    // Check whether the device has been registered or registered by others
    let did = get_did(config_version).await;
    let device_id = DIdentity {
        version: did.0,
        pk: did.1,
    };
    let device = pallets_api::device_info_v2(&sub_client, device_id.pk.clone(), None).await;
    // need register: owner != sender && owner's lock is zero && device's state == standby
    if let Some(dv) = device {
        let mut update_version = dv.version;
        let pk = "0x".to_string() + &hex::encode(&device_id.pk);
        if dv.state == DeviceState::Working || dv.state == DeviceState::Exiting {
            if !verify_enclave_hash(&sub_client, dv.version, enclave_hash.clone()).await? {
                return Err(
                    "Verify working device's enclave hash failed: {:?enclave_hash}".to_string(),
                );
            }
        }
        if "0x".to_string() + &hex::encode(dv.owner.0).to_lowercase() == config_owner.to_lowercase()
        {
            if dv.state == DeviceState::Standby && dv.version != current_version {
                // update version
                if !verify_enclave_hash(&sub_client, current_version, enclave_hash.clone()).await? {
                    return Err(
                        "update version failed due to invalid enclave_hash: {:?enclave_hash}"
                            .to_string(),
                    );
                }
                log::info!(target: "key_server", "device: {:?} will update version to bool", pk);
                update_version = current_version;
                update_device_version(
                    &sub_client,
                    report.clone(),
                    current_version,
                    signature.clone(),
                )
                .await
                .map_err(|_| "update_device_version failed".to_string())?;
            } else if dv.state == DeviceState::Standby {
                if !verify_enclave_hash(&sub_client, dv.version, enclave_hash.clone()).await? {
                    return Err("verify_enclave_hash failed".to_string());
                }
            }
            log::info!(target: "key_server", "device: {:?} has been registered for account: {:?}", pk, config_owner);
            return Ok(update_version);
        }

        if let Some(current_votes) =
            device_votes_for_current_epoch(&sub_client, device_id.pk.clone(), None).await
        {
            if let Some(owner_vote) = current_votes.iter().find(|v| v.0 == dv.owner) {
                if owner_vote.1 != 0 {
                    return Err(
                        "[{:?pk}] device owner {:?dv.owner} has current vote {:?owner_vote.1}"
                            .to_string(),
                    );
                }
            }
        }

        if let Some(current_votes) =
            device_votes_for_next_epoch(&sub_client, device_id.pk.clone(), None).await
        {
            if let Some(owner_vote) = current_votes.iter().find(|v| v.0 == dv.owner) {
                if owner_vote.1 != 0 {
                    return Err(
                        "[{:?pk}] device owner {:?dv.owner} has current vote {:?owner_vote.1}"
                            .to_string(),
                    );
                }
            }
        }
    }
    // try to register device
    if !verify_enclave_hash(&sub_client, current_version, enclave_hash.clone()).await? {
        return Err(
            "register device failed due to invalid enclave_hash: {:?enclave_hash}".to_string(),
        );
    }
    tokio::spawn(async move {
        loop {
            let mut did = get_did(config_version).await;
            did.0 = current_version;
            match node_proxy::call_register_v2(
                &sub_client,
                &config_owner,
                did,
                report.clone(),
                signature.clone(),
            )
            .await
            {
                Ok(res) => {
                    log::info!(target: "key_server", "register sgx: {:?}", res);
                    return;
                }
                Err(e) => log::info!(target: "key_server", "register failed for {:?}", e),
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
    Ok(current_version)
}

pub async fn verify_enclave_hash(
    sub_client: &BoolSubClient,
    version: u16,
    enclave_hash: Vec<u8>,
) -> Result<bool, String> {
    if version == 0 {
        return Ok(true);
    }
    let online_enclave_list = hash_to_version(sub_client, version, None)
        .await
        .ok_or("hash_to_version failed".to_string())?;

    let online_enclave_hashs: Vec<Vec<u8>> = online_enclave_list
        .as_slice()
        .chunks(32)
        .map(|c| c.to_vec())
        .collect();
    Ok(online_enclave_hashs.contains(&enclave_hash))
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
