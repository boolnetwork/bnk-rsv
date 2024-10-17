use crate::ONLINESK;
use crate::ed25519::Secret;

#[allow(dead_code)]
pub const SGX_KEYPOLICY_MRENCLAVE: u16 = 0x0001;
pub const SGX_KEYPOLICY_MRSIGNER: u16 = 0x0002;

#[allow(dead_code)]
pub async fn get_secret_key() -> Result<Secret, String> {
    let mut identity = occlum_ra::get_fingerprint_epid(SGX_KEYPOLICY_MRSIGNER);
    identity.resize(32, 1);
    let secret_key = Secret::from_bytes(&identity).map_err(|e| {
        log::error!("get secret error: {:?}", e);
        format!("get identity failed : {:?}", e)
    })?;
    Ok(secret_key)
}

pub async fn get_secret_key_dcap() -> Result<Secret, String> {
    let mut identity = occlum_ra::get_fingerprint(SGX_KEYPOLICY_MRSIGNER);
    identity.resize(32, 1);
    let secret_key = Secret::from_bytes(&identity).map_err(|e| {
        log::error!("get secret error: {:?}", e);
        format!("get identity failed : {:?}", e)
    })?;
    Ok(secret_key)
}

pub async fn get_secret_key_dcap_enclave() -> Result<Secret, String> {
    let mut identity = occlum_ra::get_fingerprint(SGX_KEYPOLICY_MRENCLAVE);
    identity.resize(32, 1);
    let secret_key = Secret::from_bytes(&identity).map_err(|e| {
        log::error!("get secret error: {:?}", e);
        format!("get identity failed : {:?}", e)
    })?;
    Ok(secret_key)
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

pub async fn get_signer_puls_enclave_key() -> Result<Secret, String> {
    let secret_key_signer = get_secret_key_dcap().await.map_err(|e| e.to_string())?;
    let secret_key_enclave = get_secret_key_dcap_enclave()
        .await
        .map_err(|e| e.to_string())?;

    let new_secret_key = secret_key_signer.0 + secret_key_enclave.0;

    Secret::from_bytes(new_secret_key.as_bytes())
}

pub async fn get_did(config_version: u16) -> (u16, Vec<u8>) {
    let online_sk = ONLINESK.read().unwrap().as_ref().unwrap().clone();
    let online_pk: crate::ed25519::Public = online_sk.into();
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

    let key_pair = crate::ed25519::Keypair::from_secret(&s3);
    let s3_pubkey = key_pair.public.as_bytes();
    println!("s3_pubkey {:?}", s3_pubkey);

    let key_pair = crate::ed25519::Keypair::from_secret(&s1);
    let s1_pubkey = key_pair.public.as_bytes();
    let key_pair = crate::ed25519::Keypair::from_secret(&s2);
    let s2_pubkey = key_pair.public.as_bytes();
    let s1_2 = crate::ed25519::Public::from_bytes(&s1_pubkey).unwrap();
    let s2_2 = crate::ed25519::Public::from_bytes(&s2_pubkey).unwrap();
    let s3_2 = s1_2.0 + s2_2.0;
    let new = crate::ed25519::Public { 0: s3_2 };
    println!("new {:?}", new.as_bytes());
}
