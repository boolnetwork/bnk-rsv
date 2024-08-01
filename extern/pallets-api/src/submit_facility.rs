use anyhow::Result;
use sp_core::H256 as Hash;
use crate::bool::runtime_types::pallet_facility::pallet::DIdentity;
use crate::BoolSubClient;

pub async fn config(
    client: &BoolSubClient,
    signer: Vec<u8>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().facility().config(signer);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn register(
    client: &BoolSubClient,
    report: Vec<u8>,
    version: u16,
    signature: Vec<u8>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().facility().register(report, version, signature);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn unregister(
    client: &BoolSubClient,
    did: DIdentity,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().facility().unregister(did);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}
