mod sgx_key;
mod utils;
mod reg;
mod mock;

use lazy_static::lazy_static;
use tokio::sync::RwLock;

lazy_static! {
    pub static ref ONLINESK: RwLock<Option<Secret>> = RwLock::new(None);
    pub static ref TESTSK: RwLock<Option<Secret>> = RwLock::new(None);
}

pub use reg::{register_sgx_2, sign_with_device_sgx_key, verify_sig};