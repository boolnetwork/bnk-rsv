use crate::ONLINESK;
use ringvrf::ed25519::Secret;

#[allow(dead_code)]
#[cfg(feature = "occlum-enclave")]
pub const SGX_KEYPOLICY_MRENCLAVE: u16 = 0x0001;
#[cfg(feature = "occlum-enclave")]
pub const SGX_KEYPOLICY_MRSIGNER: u16 = 0x0002;

#[allow(dead_code)]
#[cfg(feature = "occlum-enclave")]
pub async fn get_secret_key() -> Result<Secret, String> {
    let mut identity = occlum_ra::get_fingerprint_epid(SGX_KEYPOLICY_MRSIGNER);
    identity.resize(32, 1);
    let secret_key = Secret::from_bytes(&identity).map_err(|e| {
        log::error!("get secret error: {:?}", e);
        format!("get identity failed : {:?}", e)
    })?;
    Ok(secret_key)
}

#[cfg(feature = "occlum-enclave")]
pub async fn get_secret_key_dcap() -> Result<Secret, String> {
    let mut identity = occlum_ra::get_fingerprint(SGX_KEYPOLICY_MRSIGNER);
    identity.resize(32, 1);
    let secret_key = Secret::from_bytes(&identity).map_err(|e| {
        log::error!("get secret error: {:?}", e);
        format!("get identity failed : {:?}", e)
    })?;
    Ok(secret_key)
}

pub async fn get_did(config_version: u16) -> (u16, Vec<u8>) {
    let online_sk = ONLINESK.read().unwrap().as_ref().unwrap().clone();
    let online_pk: ringvrf::ed25519::Public = online_sk.into();
    (config_version, online_pk.as_bytes())
}
