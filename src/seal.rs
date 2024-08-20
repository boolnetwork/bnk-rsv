use aes::cipher::generic_array::GenericArray;
use aes::cipher::NewBlockCipher;
use aes::{Aes256, BlockCipher};
use std::vec::Vec;

use crate::{ONLINESK, TESTSK};

pub const BLOCK_LEN: usize = 16;

pub fn encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    let key = GenericArray::from_slice(&key);
    let cipher = Aes256::new(key);
    let mut enc_data = plaintext;
    let mut ciphertext: Vec<u8> = vec![];
    let mut pad_len = 0u8;
    loop {
        let block_slice = if enc_data.len() >= BLOCK_LEN {
            let block_slice = enc_data[0..BLOCK_LEN].to_vec();
            enc_data = enc_data[BLOCK_LEN..].to_vec();
            block_slice
        } else if !enc_data.is_empty() {
            let mut block_slice = [1u8; BLOCK_LEN];
            block_slice[..enc_data.len()].clone_from_slice(&enc_data[..]);
            pad_len += (BLOCK_LEN - enc_data.len()) as u8;
            enc_data = vec![];
            block_slice.to_vec()
        } else {
            let mut pad_slice = vec![1u8; 15];
            pad_slice.push(pad_len + 16);
            let mut block = GenericArray::clone_from_slice(&pad_slice);
            cipher.encrypt_block(&mut block);
            ciphertext.extend_from_slice(&block);
            break;
        };
        let mut block = GenericArray::clone_from_slice(&block_slice);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }
    ciphertext
}

pub fn decrypt(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let key = GenericArray::from_slice(&key);
    let cipher = Aes256::new(key);
    let mut enc_data = ciphertext;
    let mut plaintext: Vec<u8> = vec![];
    loop {
        let block_slice = if enc_data.len() >= BLOCK_LEN {
            let block_slice = enc_data[0..BLOCK_LEN].to_vec();
            enc_data = enc_data[BLOCK_LEN..].to_vec();
            block_slice
        } else {
            break;
        };
        let mut block = GenericArray::clone_from_slice(&block_slice);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }
    let last_len = plaintext[plaintext.len() - 1];
    plaintext.truncate(plaintext.len() - last_len as usize);
    plaintext
}

pub fn sealing(value: Vec<u8>) -> Result<Vec<u8>, String> {
    let sk = match ONLINESK.read().unwrap().clone() {
        Some(sk) => sk.as_bytes(),
        None => return Err(String::from("seal key ONLINESK not found")),
    };

    Ok(encrypt(sk, value))
}

pub fn unsealing(value: Vec<u8>) -> Result<Vec<u8>, String> {
    let sk = match ONLINESK.read().unwrap().clone() {
        Some(sk) => sk.as_bytes(),
        None => return Err(String::from("unseal key ONLINESK not found")),
    };

    Ok(decrypt(sk, value))
}

pub fn sealing_test(value: Vec<u8>) -> Result<Vec<u8>, String> {
    let sk = match TESTSK.read().unwrap().clone() {
        Some(sk) => sk.as_bytes(),
        None => return Err(String::from("seal key TESTSK not found")),
    };

    Ok(encrypt(sk, value))
}

pub fn unsealing_test(value: Vec<u8>) -> Result<Vec<u8>, String> {
    let sk = match TESTSK.read().unwrap().clone() {
        Some(sk) => sk.as_bytes(),
        None => return Err(String::from("unseal key TESTSK not found")),
    };

    Ok(decrypt(sk, value))
}

#[test]
fn test_seal() {
    use ringvrf::ed25519::Secret;

    let secret_key = crate::sgx_key::reg_key(Secret::random(), 4u16);
    *ONLINESK.write().unwrap() = Some(secret_key);

    let value = "this is for encrypt.this is for encrypt.this is for encrypt.this is for encrypt."
        .as_bytes()
        .to_vec();
    let enc = sealing(value.clone()).unwrap();

    let de = unsealing(enc).unwrap();
    assert_eq!(value, de);
}
