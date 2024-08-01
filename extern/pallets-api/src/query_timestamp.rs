use sp_core::H256 as Hash;
use crate::BoolSubClient;

pub async fn now(
    sub_client: &BoolSubClient,
    at_block: Option<Hash>,
) -> Option<u64> {
    let storage_query = crate::bool::storage().timestamp().now();
    match sub_client.query_storage(storage_query, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none timestamp at block: {:?}", at_block);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query timestamp failed for {:?}", e);
            return None;
        }
    }
}
