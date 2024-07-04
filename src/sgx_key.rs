

use ringvrf::ed25519::{Keypair, Public, Secret, Signature};
use crate::ONLINESK;

#[cfg(feature = "occlum-enclave")]
pub async fn get_secret_key() -> Result<Secret, String> {
    let mut identity = occlum_ra::get_fingerprint_epid(crate::worker::SGX_KEYPOLICY_MRSIGNER);
    identity.resize(32, 1);
    let secret_key = Secret::from_bytes(&identity).map_err(|e| {
        log::error!("get secret error: {:?}", e);
        return Err(format!("get identity failed : {:?}", e));
    })?;
    Ok(secret_key)
}


#[cfg(feature = "occlum-enclave")]
pub async fn get_secret_key_dcap() -> Result<Secret, String> {
    let mut identity = occlum_ra::get_fingerprint(crate::worker::SGX_KEYPOLICY_MRSIGNER);
    identity.resize(32, 1);
    let secret_key = Secret::from_bytes(&identity).map_err(|e| {
        log::error!("get secret error: {:?}", e);
        return Err(format!("get identity failed : {:?}", e));
    })?;
    Ok(secret_key)
}


pub async fn get_did(config_version: u16) -> (u16, Vec<u8>) {
    let online_sk = ONLINESK.read().await.as_ref().unwrap().clone();
    let online_pk: ringvrf::ed25519::Public = online_sk.into();
    (config_version, online_pk.as_bytes())
}