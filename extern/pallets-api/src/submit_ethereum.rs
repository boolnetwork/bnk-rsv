use anyhow::Result;
use sp_core::H256 as Hash;
use crate::BoolSubClient;
use crate::bool::runtime_types::ethereum::transaction::TransactionV2 as Transaction;

pub async fn transact(
    client: &BoolSubClient,
    transaction: Transaction,
) -> Result<Hash, String> {
    let call = crate::bool::tx().ethereum().transact(transaction);
    client.submit_extrinsic_without_signer(call).await.map_err(|e| e.to_string())
}

pub async fn transact_unsigned(
    client: &BoolSubClient,
    transaction: Transaction,
) -> Result<Hash, String> {
    let call = crate::bool::tx().ethereum().transact_unsigned(transaction);
    client.submit_extrinsic_without_signer(call).await.map_err(|e| e.to_string())
}

pub async fn evm_chain_id(
    sub_client: &BoolSubClient,
    at_block: Option<Hash>,
) -> Option<u64> {
    let store = crate::bool::storage().evm_chain_id().chain_id();
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query evm chain id return None");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query evm chain id failed for {:?}", e);
            return None;
        }
    }
}
