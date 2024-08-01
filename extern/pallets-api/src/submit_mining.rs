use anyhow::Result;
use sp_core::H256 as Hash;
use crate::{BoolSubClient, handle_custom_error};
use crate::bool::runtime_types::pallet_mining::pallet::OnChainPayload;

pub async fn im_online(client: &BoolSubClient, payload: OnChainPayload) -> Result<Hash, String> {
    let call = crate::bool::tx().mining().im_online(payload);
    client.submit_extrinsic_without_signer(call).await.map_err(|e|
        handle_custom_error(e)
    )
}

pub async fn report_standby(
    client: &BoolSubClient,
    id: Vec<u8>,
    version: u16,
    enclave_hash: Vec<u8>,
    signature: Vec<u8>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().mining().report_standby(id, version, enclave_hash, signature);
    client.submit_extrinsic_without_signer(call).await.map_err(|e|
        handle_custom_error(e)
    )
}

pub async fn register_device(
    client: &BoolSubClient,
    owner: crate::bool::runtime_types::node_primitives::AccountId20,
    report: Vec<u8>,
    version: u16,
    signature: Vec<u8>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().mining().register_device(
        owner,
        report,
        version,
        signature
    );
    client.submit_extrinsic_without_signer(call).await.map_err(|e| e.to_string())
}

pub async fn update_votes(
    client: &BoolSubClient,
    changed_votes: Vec<(Vec<u8>, u128)>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().mining().update_votes(
        changed_votes,
    );
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn join_service(
    client: &BoolSubClient,
    id: Vec<u8>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().mining().join_service(id);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn exit_service(
    client: &BoolSubClient,
    id: Vec<u8>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().mining().exit_service(id);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn update_device_version(
    client: &BoolSubClient,
    report: Vec<u8>,
    version: u16,
    signature: Vec<u8>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().mining().update_device_version(
        report,
        version,
        signature
    );
    client.submit_extrinsic_without_signer(call).await.map_err(|e| e.to_string())
}