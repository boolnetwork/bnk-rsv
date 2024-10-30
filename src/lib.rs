// This file is part of BoolNetwork.

// Copyright (C) BoolNetwork (HK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod mock;
mod reg;
mod resp_verify;
mod seal;
mod sgx_key;
mod utils;
mod ed25519;

use lazy_static::lazy_static;
use ed25519::{Keypair, Secret};
use std::sync::RwLock;

lazy_static! {
    pub static ref ONLINESK: RwLock<Option<Secret>> = RwLock::new(None);
    pub static ref TESTSK: RwLock<Option<Secret>> = RwLock::new(None);
    pub static ref RELATEDEVICEIDS: RwLock<Option<Vec<Vec<u8>>>> = RwLock::new(None);
    pub static ref BTCD: Vec<u8> = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1
    ];
    pub static ref ELECTRS: Vec<u8> = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2
    ];
    pub static ref MONITOR: Vec<u8> = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3
    ];
    pub static ref UNKNOWN: Vec<u8> = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 4
    ];
}

pub use mock::{register_sgx_test, sign_with_device_sgx_key_test, verify_sig_test};
pub use reg::{
    fetch_relate_device_id, register_sgx_2, sign_with_device_sgx_key, verify_sig,
    verify_sig_from_string_public, register_sgx_2_not_fetch, update_relate_device_id_once,
    update_relate_device_id_once_string, fetch_eth_checkpoint
};
pub use resp_verify::{
    create_sgx_response, create_sgx_response_v2, create_sgx_response_v2_string, sgx_result_parse,
    verify_sgx_response, verify_sgx_response_and_restore_origin_response_v2, SGXResponseV2,
};
pub use seal::{sealing, unsealing};

#[derive(Clone)]
pub enum KeyType {
    SGX,
    TEST,
}

pub fn get_public(_key_type: KeyType) -> String {
    let key_pair = Keypair::from_secret(ONLINESK.read().unwrap().as_ref().unwrap());
    let pubkey = key_pair.public.as_bytes();
    hex::encode(pubkey)
}
