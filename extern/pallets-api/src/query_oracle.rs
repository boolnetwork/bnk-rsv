use sp_core::H256 as Hash;
use node_primitives::BlockNumber;
use crate::bool::runtime_types::pallet_oracle::pallet::{RandomNumberParams, Brc20StatusAtHeight, Brc20OracleLog};
use crate::BoolSubClient;

pub async fn random_number_params(
    sub_client: &BoolSubClient,
    ecdsa_cid: u32,
    nonce: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<RandomNumberParams<BlockNumber>> {
    let store = crate::bool::storage().oracle().chain_random_num(ecdsa_cid, nonce.clone());
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none param for ecdsa cid: {:?}, nonce: {:?}", ecdsa_cid, nonce);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query param failed: ecdsa cid: {:?} request_id: {:?} for {:?}", ecdsa_cid, nonce, e);
            return None;
        }
    }
}

pub async fn vrn_committees(
    sub_client: &BoolSubClient,
    chain_id: u32,
    at_block: Option<Hash>,
) -> Option<Vec<(u32, u32)>> {
    let store = crate::bool::storage().oracle().vrn_committees(chain_id);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none vrn_committees for chain id: {:?}", chain_id);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query vrn_committees failed: chain_id: {:?} for {:?}", chain_id, e);
            return None;
        }
    }
}

pub async fn find_ecdsa_committee(
    sub_client: &BoolSubClient,
    chain_id: u32,
    bls_cid: u32,
    at_block: Option<Hash>,
)-> Option<u32> {
    match vrn_committees(sub_client, chain_id, at_block).await {
        Some(cmts) => {
            match cmts
                .iter()
                .find(|(bls_cmt_cid, _)| bls_cmt_cid == &bls_cid)
                .map(|(_, ecdsa_cid)| *ecdsa_cid)
            {
                Some(ecdsa_cid) => return Some(ecdsa_cid),
                None => {
                    log::info!(target: "event_watcher", "fetch ecdsa committee none for chain id: {:?}, bls cid: {:?}", chain_id, bls_cid);
                    return None;
                }
            }
        },
        None => return None,
    }
}

pub async fn brc20_consensus_status(
    sub_client: &BoolSubClient,
    height: u64,
    at_block: Option<Hash>,
) -> Option<Brc20StatusAtHeight<BlockNumber>> {
    let store = crate::bool::storage().oracle().brc20_consensus_status(height);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none status for btc height: {:?}", height);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query status for height {:?} failed for {:?}", height, e);
            return None;
        }
    }
}


pub async fn brc20_current_height(
    sub_client: &BoolSubClient,
    at_block: Option<Hash>,
) -> Option<(u64, u32)> {
    let store = crate::bool::storage().oracle().brc20_current_height();
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none btc current height");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query btc current height failed for {:?}", e);
            return None;
        }
    }
}

pub async fn brc20_consensus_pool(
    sub_client: &BoolSubClient,
    at_block: Option<Hash>,
) -> Option<Vec<(u64, u32)>> {
    let store = crate::bool::storage().oracle().brc20_consensus_pool();
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none brc20 consensus pool");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query brc20 current pool failed for {:?}", e);
            return None;
        }
    }
}

pub async fn brc20_indexer_path(
    sub_client: &BoolSubClient,
    at_block: Option<Hash>,
) -> Option<Vec<(u32, Vec<u8>)>> {
    let store = crate::bool::storage().oracle().brc20_indexer_path();
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none brc20 dst path");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query brc20 dst path failed for {:?}", e);
            return None;
        }
    }
}

pub async fn brc20_pool_limit(
    sub_client: &BoolSubClient,
    at_block: Option<Hash>,
)-> Option<u8> {
    let store = crate::bool::storage().oracle().brc20_pool_limit();
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none brc20 pool limit");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query brc20 pool limit failed for {:?}", e);
            return None;
        }
    }
}

pub async fn brc20_oracle_committee(
    sub_client: &BoolSubClient,
    chain_id: u32,
    oracle: Vec<u8>,
    at_block: Option<Hash>,
)-> Option<u32> {
    let store = crate::bool::storage().oracle().brc20_oracle_committees(chain_id, oracle);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none brc20 oracle committee");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query brc20 oracle committee failed for {:?}", e);
            return None;
        }
    }
}

pub async fn brc20_oracle_request(
    sub_client: &BoolSubClient,
    chain_id: u32,
    oracle: Vec<u8>,
    uid: u64,
    at_block: Option<Hash>,
) -> Option<Brc20OracleLog<BlockNumber>> {
    let store = crate::bool::storage().oracle().brc20_oracle_request_logs(&(chain_id, oracle), &uid);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none brc20 oracle request");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query brc20 oracle request failed for {:?}", e);
            return None;
        }
    }
}

pub async fn brc20_oracle_result(
    sub_client: &BoolSubClient,
    chain_id: u32,
    oracle: Vec<u8>,
    uid: u64,
    at_block: Option<Hash>,
) -> Option<Brc20OracleLog<BlockNumber>> {
    let store = crate::bool::storage().oracle().brc20_oracle_result_logs(&(chain_id, oracle), &uid);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none brc20 oracle result");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query brc20 oracle result failed for {:?}", e);
            return None;
        }
    }
}
