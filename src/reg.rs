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

use pallets_api::client::SubClient;
use pallets_api::version_list;
use pallets_api::{self, bool::runtime_types::pallet_facility::pallet::DIdentity};
use crate::ed25519::{Keypair, Public, Secret, Signature};

use crate::sgx_key::{get_did, get_signer_puls_enclave_key, reg_key};
use crate::utils::sha3_hash256;
use crate::{ONLINESK, RELATEDEVICEIDS};

pub async fn register_sgx_2(
    subclient_url: String,
    subclient_warn_time: u128,
    config_version: u16,
    device_owner: String,
    watcher_device_id: String,
    reg_type: u16,
) -> Result<u16, String> {
    let subclient =
        SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(subclient_warn_time))
            .await?;

    let secret_key = get_signer_puls_enclave_key()
        .await
        .map_err(|e| e.to_string())?;
    let secret_key = reg_key(secret_key, reg_type);
    let public_key: Public = secret_key.into();
    let key_pair = Keypair::from_secret(&secret_key);
    let pk_vec = public_key.as_bytes();

    *ONLINESK.write().unwrap() = Some(secret_key);
    #[cfg(feature = "occlum-enclave")]
    let (report, enclave_hash) = {
        use occlum_ra::attestation::{AttestationReport, AttestationStyle, DcapAttestation};
        use occlum_ra::dcap::DcapAttestationReport;

        let (report_payload, enclave_hash) = {
            let dcap_report = DcapAttestation::create_report(&pk_vec)
                .map_err(|_| "Dcap create_report failed".to_string())?;
            let dar = DcapAttestationReport::from_bytes(dcap_report.quote.clone())
                .map_err(|_| "Dcap from_bytes failed".to_string())?;
            let enclave: Vec<u8> = dar.quote.inner.report_body.mr_enclave.m.to_vec();
            (dcap_report.into_payload(), enclave)
        };
        (
            AttestationReport {
                style: AttestationStyle::DCAP,
                data: report_payload,
            }
            .into_payload(),
            enclave_hash,
        )
    };
    #[cfg(not(feature = "occlum-enclave"))]
    let (report, enclave_hash) = (pk_vec.clone(), vec![0u8; 32]);
    println!(
        "enclave hash: 0x{}, attestation: 0x{}",
        hex::encode(&enclave_hash),
        hex::encode(&report)
    );

    let sub_client = subclient.clone();
    let current_version = version_list(&sub_client, None)
        .await
        .ok_or("get version list".to_string())?
        .pop()
        .ok_or("version list empty".to_string())?;
    let msg = [report.clone(), current_version.to_be_bytes().to_vec()].concat();
    let signature = key_pair
        .sign(&msg)
        .map_err(|e| format!("ed25519 sign {e:?}"))?
        .as_bytes()
        .to_vec();
    let config_owner = device_owner.clone();
    println!("device owner: {}", config_owner);
    println!("device id pk: {}", hex::encode(&pk_vec));

    // Check whether the device has been registered or registered by others
    let did = get_did(config_version).await;
    let device_id = DIdentity {
        version: did.0,
        pk: did.1,
    };
    let device = pallets_api::device_info_rpc(&sub_client, device_id.pk.clone(), None).await;
    if let Some(d) = device {
        println!("registered");
        let sub_client2 = sub_client.clone();
        let id = d.watcher_deviceid.clone();
        tokio::spawn(async move {
            loop {
                println!("=======relate_deviceid_rpc======");
                let res = pallets_api::relate_deviceid_rpc(&sub_client2, id.clone(), None).await;
                *RELATEDEVICEIDS.write().unwrap() = res.clone();
                for device in res.unwrap_or(vec![vec![0]]) {
                    println!("relate device list : {}", hex::encode(&device));
                }

                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });

        return Err("registered".to_string());
    }
    // try to register device
    if !crate::utils::verify_enclave_hash(&sub_client, current_version, enclave_hash.clone())
        .await?
    {
        println!("hash mot match");
        return Err(
            "register device failed due to invalid enclave_hash: {:?enclave_hash}".to_string(),
        );
    }
    let sub_client2 = sub_client.clone();
    let watcher_device_id2 = watcher_device_id.clone();
    tokio::spawn(async move {
        loop {
            let mut did = get_did(config_version).await;
            did.0 = current_version;
            match crate::utils::call_register_rpc(
                &sub_client.clone(),
                &config_owner,
                did,
                report.clone(),
                signature.clone(),
                &watcher_device_id,
            )
            .await
            {
                Ok(res) => {
                    println!("register sgx: {:?}", res);
                    
                    return;
                }
                Err(e) => println!("register failed for {:?}", e),
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    tokio::spawn(async move {
        loop {
            println!("===registered====relate_deviceid_rpc======");
            let id = hex::decode(crate::utils::no_prefix(&watcher_device_id2))
                .map_err(|e| e.to_string())
                .unwrap();

            let res = pallets_api::relate_deviceid_rpc(&sub_client2, id, None).await;
            *RELATEDEVICEIDS.write().unwrap() = res.clone();
            for device in res.unwrap_or(vec![vec![0]]) {
                println!("relate device list : {}", hex::encode(&device));
            }

            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    Ok(current_version)
}

pub async fn register_sgx_2_not_fetch(
    subclient_url: String,
    subclient_warn_time: u128,
    config_version: u16,
    device_owner: String,
    watcher_device_id: String,
    reg_type: u16,
) -> Result<u16, String> {
    let subclient =
        SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(subclient_warn_time))
            .await?;

    let secret_key = get_signer_puls_enclave_key()
        .await
        .map_err(|e| e.to_string())?;
    let secret_key = reg_key(secret_key, reg_type);
    let public_key: Public = secret_key.into();
    let key_pair = Keypair::from_secret(&secret_key);
    let pk_vec = public_key.as_bytes();

    *ONLINESK.write().unwrap() = Some(secret_key);
    #[cfg(feature = "occlum-enclave")]
    let (report, enclave_hash) = {
        use occlum_ra::attestation::{AttestationReport, AttestationStyle, DcapAttestation};
        use occlum_ra::dcap::DcapAttestationReport;

        let (report_payload, enclave_hash) = {
            let dcap_report = DcapAttestation::create_report(&pk_vec)
                .map_err(|_| "Dcap create_report failed".to_string())?;
            let dar = DcapAttestationReport::from_bytes(dcap_report.quote.clone())
                .map_err(|_| "Dcap from_bytes failed".to_string())?;
            let enclave: Vec<u8> = dar.quote.inner.report_body.mr_enclave.m.to_vec();
            (dcap_report.into_payload(), enclave)
        };
        (
            AttestationReport {
                style: AttestationStyle::DCAP,
                data: report_payload,
            }
            .into_payload(),
            enclave_hash,
        )
    };
    #[cfg(not(feature = "occlum-enclave"))]
    let (report, enclave_hash) = (pk_vec.clone(), vec![0u8; 32]);
    println!(
        "enclave hash: 0x{}, attestation: 0x{}",
        hex::encode(&enclave_hash),
        hex::encode(&report)
    );

    let sub_client = subclient.clone();
    let current_version = version_list(&sub_client, None)
        .await
        .ok_or("get version list".to_string())?
        .pop()
        .ok_or("version list empty".to_string())?;
    let msg = [report.clone(), current_version.to_be_bytes().to_vec()].concat();
    let signature = key_pair
        .sign(&msg)
        .map_err(|e| format!("ed25519 sign {e:?}"))?
        .as_bytes()
        .to_vec();
    let config_owner = device_owner.clone();
    println!("device owner: {}", config_owner);
    println!("device id pk: {}", hex::encode(&pk_vec));

    // Check whether the device has been registered or registered by others
    let did = get_did(config_version).await;
    let device_id = DIdentity {
        version: did.0,
        pk: did.1,
    };
    let device = pallets_api::device_info_rpc(&sub_client, device_id.pk.clone(), None).await;
    if let Some(_) = device {
        println!("registered");
        return Err("registered".to_string());
    }
    // try to register device
    if !crate::utils::verify_enclave_hash(&sub_client, current_version, enclave_hash.clone())
        .await?
    {
        println!("hash mot match");
        return Err(
            "register device failed due to invalid enclave_hash: {:?enclave_hash}".to_string(),
        );
    }

    tokio::spawn(async move {
        loop {
            let mut did = get_did(config_version).await;
            did.0 = current_version;
            match crate::utils::call_register_rpc(
                &sub_client.clone(),
                &config_owner,
                did,
                report.clone(),
                signature.clone(),
                &watcher_device_id,
            )
            .await
            {
                Ok(res) => {
                    println!("register sgx: {:?}", res);
                    
                    return;
                }
                Err(e) => println!("register failed for {:?}", e),
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    Ok(current_version)
}

pub async fn fetch_relate_device_id(watcher_device_id: Vec<u8>, subclient_url: String) {
    let subclient = SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(30))
        .await
        .unwrap();

    tokio::spawn(async move {
        loop {
            let res =
                pallets_api::relate_deviceid_rpc(&subclient, watcher_device_id.clone(), None).await;
            tracing::info!(target: "key_server", "relate device list : {:?}", res);

            *RELATEDEVICEIDS.write().unwrap() = res;

            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
}

pub async fn update_relate_device_id_once(watcher_device_id: Vec<u8>, subclient_url: String) {
    let subclient = SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(30))
        .await
        .unwrap();

    let res =
        pallets_api::relate_deviceid_rpc(&subclient, watcher_device_id.clone(), None).await;
        tracing::info!(target: "key_server", "relate device list : {:?}", res);

    *RELATEDEVICEIDS.write().unwrap() = res;

}

pub async fn update_relate_device_id_once_string(watcher_device_id: String, subclient_url: String) {
    let id = hex::decode(crate::utils::no_prefix(&watcher_device_id))
    .map_err(|e| e.to_string())
    .unwrap();

    let subclient = SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(30))
        .await
        .unwrap();

    let res =
        pallets_api::relate_deviceid_rpc(&subclient, id.clone(), None).await;
        tracing::info!(target: "key_server", "relate device list : {:?}", res);

    *RELATEDEVICEIDS.write().unwrap() = res;
}

pub async fn fetch_eth_checkpoint(subclient_url: String) -> Option<Vec<u8>>{

    let subclient = SubClient::new_from_ecdsa_sk(subclient_url.to_string(), None, Some(30))
    .await
    .unwrap();

    pallets_api::eth_checkpoint(&subclient, None).await
}

pub fn sign_with_device_sgx_key(msg: Vec<u8>) -> Result<Vec<u8>, String> {
    let key_pair = Keypair::from_secret(ONLINESK.read().unwrap().as_ref().unwrap());
    let msg = sha3_hash256(&msg);
    let sig = key_pair
        .sign(&msg)
        .map_err(|_| "sign error".to_string())?
        .as_bytes()
        .to_vec();

    Ok(sig)
}

pub fn verify_sig(msg: Vec<u8>, signature: Vec<u8>, pubkey: Vec<u8>) -> Result<bool, String> {
    let key_pair = Keypair::from_secret(ONLINESK.read().unwrap().as_ref().unwrap());
    let msg = sha3_hash256(&msg);

    if pubkey != key_pair.public.as_bytes() {
        return Err("pubkey isnt match".to_string());
    }

    match key_pair.verify(&msg, &Signature::from_bytes(&signature).unwrap()) {
        Ok(()) => return Ok(true),
        Err(e) => return Err(format!("verify error {e:?}")),
    }
}

pub fn verify_sig_from_string_public(
    msg: Vec<u8>,
    signature: Vec<u8>,
    pubkey: String,
) -> Result<bool, String> {
    if !relate_device(&pubkey) {
        return Err(format!("not relate_device"));
    }

    let msg = sha3_hash256(&msg);

    let pk = hex::decode(pubkey).map_err(|e| format!("hex decode error {e:?}"))?;
    let public = Public::from_bytes(&pk).map_err(|e| format!("not pubkey error {e:?}"))?;
    let keypair = Keypair {
        secret: Secret::random(), // TODO:: fix it
        public,
    };

    match keypair.verify(&msg, &Signature::from_bytes(&signature).unwrap()) {
        Ok(()) => return Ok(true),
        Err(e) => return Err(format!("verify error {e:?}")),
    }
}

pub fn relate_device(pubkey: &str) -> bool {
    let list = RELATEDEVICEIDS.read().unwrap().clone();
    if list.is_none() {
        return false;
    }
    let pk = hex::decode(pubkey).unwrap_or_else(|_| {
        Vec::new()
    });
    list.unwrap().contains(&pk)
}
