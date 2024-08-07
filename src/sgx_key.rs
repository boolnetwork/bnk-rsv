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

#[test]
fn test_secret_addition() {
    let bytes = vec![2u8; 32];
    let s1 = Secret::from_bytes(&bytes).unwrap();

    let btcd_type = crate::BTCD.clone();

    let s2 = Secret::from_bytes(&btcd_type).unwrap();

    let s3_s = s1.0 + s2.0;

    let s3: Secret = Secret::from_bytes(s3_s.as_bytes()).unwrap();

    println!("s3 {:?}", s3);

    let key_pair = ringvrf::ed25519::Keypair::from_secret(&s3);
    let s3_pubkey = key_pair.public.as_bytes();
    println!("s3_pubkey {:?}", s3_pubkey);

    let key_pair = ringvrf::ed25519::Keypair::from_secret(&s1);
    let s1_pubkey = key_pair.public.as_bytes();
    let key_pair = ringvrf::ed25519::Keypair::from_secret(&s2);
    let s2_pubkey = key_pair.public.as_bytes();
    let s1_2 = ringvrf::ed25519::Public::from_bytes(&s1_pubkey).unwrap();
    let s2_2 = ringvrf::ed25519::Public::from_bytes(&s2_pubkey).unwrap();
    let s3_2 = s1_2.0 + s2_2.0;
    let new = ringvrf::ed25519::Public { 0: s3_2 };
    println!("new {:?}", new.as_bytes());
}
