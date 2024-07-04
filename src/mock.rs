
use ringvrf::ed25519::{Keypair, Public, Secret, Signature};
use crate::{TESTSK, ONLINESK};
use crate::utils::sha3_hash256;

pub async fn register_sgx_test(){
    let secret_key = Secret::random();
    *TESTSK.write().await = Some(secret_key);
}

pub async fn sign_with_device_sgx_key_test(msg: Vec<u8>) -> Result<Vec<u8>, String> {
    let key_pair = Keypair::from_secret(TESTSK.read().await.as_ref().unwrap());
    let msg = sha3_hash256(&msg);
    let sig = key_pair
        .sign(&msg)
        .map_err(|_| "sign error".to_string())?
        .as_bytes()
        .to_vec();

    Ok(sig)
}

pub async fn verify_sig_test(msg: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
    let key_pair = Keypair::from_secret(TESTSK.read().await.as_ref().unwrap());
    let msg = sha3_hash256(&msg);

    match key_pair.verify(&msg, &Signature::from_bytes(&signature).unwrap()) {
        Ok(()) => return Ok(true),
        Err(_) => return Err("".to_string()),
    }
}

#[tokio::test]
async fn test_sign_verify() {
    let secret_key = Secret::from_bytes(&[8u8; 32]).unwrap();
    *ONLINESK.write().await = Some(secret_key);

    let msg = vec![8u8, 7u8, 9u8];

    let sig = sign_with_device_sgx_key(msg.clone()).await.unwrap();

    let public_key: Public = secret_key.into();
    let pk_vec = public_key.as_bytes();
    let result = verify_sig(msg, sig, pk_vec).await.unwrap();
    assert!(result)
}