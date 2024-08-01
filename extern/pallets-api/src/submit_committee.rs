#![allow(clippy::too_many_arguments)]
use anyhow::Result;
use sp_core::H256 as Hash;
use crate::bool::runtime_types::pallet_facility::pallet::DIdentity;
use crate::bool::runtime_types::pallet_committee::pallet::{CryptoType, ExitParameters, OnChainPayloadVRF};
use crate::{BoolSubClient, handle_custom_error};

pub async fn join(
    client: &BoolSubClient,
    pids: Vec<u32>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().join(pids);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn part_join(
    client: &BoolSubClient,
    pids: Vec<u32>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().part_join(pids);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn exit(
    client: &BoolSubClient,
    exit_param: ExitParameters,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().exit(exit_param);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn part_exit(
    client: &BoolSubClient,
    exit_param: ExitParameters,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().part_exit(exit_param);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn part_devices_exit(
    client: &BoolSubClient,
    pid: u32,
    dids: Vec<DIdentity>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().part_devices_exit(pid, dids);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn create_committee(
    client: &BoolSubClient,
    t: u16,
    n: u16,
    crypto: CryptoType,
    fork: u8,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().create_committee(t, n, crypto, fork);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn enter(client: &BoolSubClient, payload: OnChainPayloadVRF) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().enter(payload);
    client.submit_extrinsic_without_signer(call).await.map_err(|e| {
        handle_custom_error(e)
    })
}

pub async fn expose(
    client: &BoolSubClient,
    cid: u32,
    epoch: u32,
    fork_id: u8,
    pk: Vec<u8>,
    device_id: Vec<u8>,
    sig: Vec<u8>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().expose(
        cid,
        epoch,
        fork_id,
        pk,
        device_id,
        sig
    );
    client.submit_extrinsic_without_signer(call).await.map_err(|e| {
        handle_custom_error(e)
    })
}

pub async fn active_committee(
    client: &BoolSubClient,
    cid: u32,
    chain_id: u32,
    address: Vec<u8>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().active_committee(cid, chain_id, address);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn report_change(
    client: &BoolSubClient,
    pk: Vec<u8>,
    sig: Vec<u8>,
    cid: u32,
    epoch: u32,
    fork_id: u8,
    signature: Vec<u8>,
    pubkey: Vec<u8>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().report_change(pk, sig, cid, epoch, fork_id, signature, pubkey);
    client.submit_extrinsic_without_signer(call).await.map_err(|e| {
        handle_custom_error(e)
    })
}

pub async fn update_assets(
    client: &BoolSubClient,
    cid: u32,
    block_number: u32,
    btc_asset: u128,
    brc20_assets: Vec<(Vec<u8>, u128)>,
    sender_pk: Vec<u8>,
    sender_sig: Vec<u8>,
    cmt_sig: Vec<u8>,
    fork_id: u8,
) -> Result<Hash, String> {
    let call = crate::bool::tx().committee().update_assets(cid, block_number, btc_asset, brc20_assets, sender_pk, sender_sig, cmt_sig, fork_id);
    client.submit_extrinsic_without_signer(call).await.map_err(|e| {
        handle_custom_error(e)
    })
}

