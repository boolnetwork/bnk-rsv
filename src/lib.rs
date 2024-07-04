mod mock;
mod reg;
mod sgx_key;
mod utils;

use lazy_static::lazy_static;
use ringvrf::ed25519::Secret;
// use tokio::sync::RwLock;
use std::sync::RwLock;

lazy_static! {
    pub static ref ONLINESK: RwLock<Option<Secret>> = RwLock::new(None);
    pub static ref TESTSK: RwLock<Option<Secret>> = RwLock::new(None);
}

pub use mock::{register_sgx_test, sign_with_device_sgx_key_test, verify_sig_test};
pub use reg::{register_sgx_2, sign_with_device_sgx_key, verify_sig};
