mod mock;
mod reg;
mod sgx_key;
mod utils;
mod resp_verify;

use lazy_static::lazy_static;
use ringvrf::ed25519::{Keypair, Secret};
use std::{clone, sync::RwLock};

lazy_static! {
    pub static ref ONLINESK: RwLock<Option<Secret>> = RwLock::new(None);
    pub static ref TESTSK: RwLock<Option<Secret>> = RwLock::new(None);
}

pub use mock::{register_sgx_test, sign_with_device_sgx_key_test, verify_sig_test};
pub use reg::{
    register_sgx_2, sign_with_device_sgx_key, verify_sig, verify_sig_from_string_public,
};
pub use resp_verify::{create_sgx_response, ResponseSgx};

#[derive(Clone)]
pub enum KeyType {
    SGX,
    TEST,
}

pub fn get_public(key_type: KeyType) -> String {
    match key_type {
        KeyType::SGX => {
            let key_pair = Keypair::from_secret(ONLINESK.read().unwrap().as_ref().unwrap());
            let pubkey = key_pair.public.as_bytes();
            hex::encode(pubkey)
        }
        KeyType::TEST => {
            let key_pair = Keypair::from_secret(TESTSK.read().unwrap().as_ref().unwrap());
            let pubkey = key_pair.public.as_bytes();
            hex::encode(pubkey)
        }
    }
}
