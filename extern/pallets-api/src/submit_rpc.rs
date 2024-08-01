use crate::BoolSubClient;
use anyhow::Result;
use sp_core::H256 as Hash;

pub async fn register_device_rpc(
    client: &BoolSubClient,
    owner: crate::bool::runtime_types::node_primitives::AccountId20,
    report: Vec<u8>,
    version: u16,
    signature: Vec<u8>,
) -> Result<Hash, String> {
    let call = crate::bool::tx()
        .rpc()
        .register_device(owner, report, version, signature);
    client
        .submit_extrinsic_without_signer(call)
        .await
        .map_err(|e| e.to_string())
}
