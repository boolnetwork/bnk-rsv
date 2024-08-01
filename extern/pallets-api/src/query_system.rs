use sp_core::H256 as Hash;
use crate::BoolSubClient;

pub async fn block_hash(
    sub_client: &BoolSubClient,
    height: u32,
    at_block: Option<Hash>,
) -> Option<Hash> {
    let storage_query = crate::bool::storage().system().block_hash(height);
    match sub_client.query_storage(storage_query, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none block hash for height: {:?}", height);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query block hash failed: height: {:?} for {:?}", height, e);
            return None;
        }
    }
}
