use crate::{utils::sha3_hash256, RELATEDEVICEIDS, TESTSK};
use ringvrf::ed25519::{Keypair, Secret, Signature};

pub async fn register_sgx_test() {
    let secret_key = crate::sgx_key::reg_key(Secret::random(), 4u16);

    *TESTSK.write().unwrap() = Some(secret_key);

    let key_pair = Keypair::from_secret(&secret_key);
    let pubkey = key_pair.public.as_bytes();
    *RELATEDEVICEIDS.write().unwrap() = Some(vec![pubkey]);
}

pub fn sign_with_device_sgx_key_test(msg: Vec<u8>) -> Result<Vec<u8>, String> {
    let key_pair = Keypair::from_secret(TESTSK.read().unwrap().as_ref().unwrap());
    let msg = sha3_hash256(&msg);
    let sig = key_pair
        .sign(&msg)
        .map_err(|_| "sign error".to_string())?
        .as_bytes()
        .to_vec();

    Ok(sig)
}

pub fn verify_sig_test(msg: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
    let key_pair = Keypair::from_secret(TESTSK.read().unwrap().as_ref().unwrap());
    let msg = sha3_hash256(&msg);

    match key_pair.verify(&msg, &Signature::from_bytes(&signature).unwrap()) {
        Ok(()) => return Ok(true),
        Err(_) => return Err("".to_string()),
    }
}

#[test]
fn test_sign_verify() {
    use crate::ONLINESK;
    use crate::*;
    use ringvrf::ed25519::Public;

    let secret_key = Secret::from_bytes(&[8u8; 32]).unwrap();
    *ONLINESK.write().unwrap() = Some(secret_key);
    let key_pair = Keypair::from_secret(&secret_key);
    let pubkey = key_pair.public.as_bytes();
    *RELATEDEVICEIDS.write().unwrap() = Some(vec![pubkey]);

    let msg = vec![8u8, 7u8, 9u8];

    let sig = sign_with_device_sgx_key(msg.clone()).unwrap();

    let public_key: Public = secret_key.into();
    let pk_vec = public_key.as_bytes();
    let result = verify_sig(msg, sig, pk_vec).unwrap();
    assert!(result)
}

#[test]
fn test_sign_verify_2() {
    use crate::ONLINESK;
    use crate::*;

    let secret_key = Secret::from_bytes(&[8u8; 32]).unwrap();
    *ONLINESK.write().unwrap() = Some(secret_key);
    let key_pair = Keypair::from_secret(&secret_key);
    let pubkey = key_pair.public.as_bytes();
    *RELATEDEVICEIDS.write().unwrap() = Some(vec![pubkey]);

    let msg = vec![8u8, 7u8, 9u8];

    let sig = sign_with_device_sgx_key(msg.clone()).unwrap();

    let public_string = get_public(KeyType::SGX);

    let result = verify_sig_from_string_public(msg, sig, public_string).unwrap();
    assert!(result)
}
