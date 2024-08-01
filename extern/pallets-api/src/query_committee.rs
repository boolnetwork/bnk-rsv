use crate::bool::runtime_types::node_primitives::AccountId20;
use crate::bool::runtime_types::pallet_committee::pallet::Committee;
use crate::bool::runtime_types::pallet_facility::pallet::DIdentity;
use sp_core::H256 as Hash;
use crate::BoolSubClient;

pub async fn committees(
    sub_client: &BoolSubClient,
    cid: u32,
    at_block: Option<Hash>,
) -> Option<Committee<AccountId20, u32>> {
    let store = crate::bool::storage().committee().committees(cid);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query committee info for cid: {}", cid);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query committee failed: cid: {} for {:?}", cid, e);
            return None;
        }
    }
}

pub async fn committees_iter(
    sub_client: &BoolSubClient,
    page_size: u32,
    at_block: Option<Hash>,
) -> Result<Vec<Committee<AccountId20, u32>>, subxt::Error> {
    let store = crate::bool::storage().committee().committees_root();
    sub_client.query_storage_value_iter(store, page_size, at_block).await
}

pub async fn registers(sub_client: &BoolSubClient, at_block: Option<Hash>) -> Option<Vec<DIdentity>> {
    let store = crate::bool::storage().committee().registers();
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none registers");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query registers failed for {:?}", e);
            return None;
        }
    }
}

pub async fn snapshot(sub_client: &BoolSubClient, at_block: Option<Hash>) -> Option<Vec<Vec<u8>>> {
    let store = crate::bool::storage().committee().snapshot();

    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none snapshot");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query snapshot failed for {:?}", e);
            return None;
        }
    }
}

pub async fn committee_members(
    sub_client: &BoolSubClient,
    cid: u32,
    epoch: u32,
    fork_id: u8,
    at_block: Option<Hash>,
) -> Option<Vec<Vec<u8>>> {
    let store = crate::bool::storage().committee().committee_members(cid, (epoch, fork_id));
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none members for cid: {}, epoch: {}, fork_id: {}", cid, epoch, fork_id);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query members failed:cid: {}, epoch: {}, fork_id: {}, for {:?}", cid, epoch, fork_id, e);
            return None;
        }
    }
}

pub async fn candidates(
    sub_client: &BoolSubClient,
    cid: u32,
    fork: u8,
    at_block: Option<Hash>,
) -> Option<Vec<Vec<u8>>> {
    let store = crate::bool::storage().committee().candidates(cid, fork);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none candidates for cid: {}, fork: {}", cid, fork);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query candidates failed for cid: {}, fork: {}, for: {:?}", cid, fork, e);
            return None;
        }
    }
}

pub async fn committee_randomness(sub_client: &BoolSubClient, cid: u32, at_block: Option<Hash>) -> Option<u64> {
    let store = crate::bool::storage().committee().c_randomness(cid);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none randomness for cid: {}", cid);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query randomness failed: cid: {}, for {:?}", cid, e);
            return None;
        }
    }
}

pub async fn unpaid_sign_fee(
    sub_client: &BoolSubClient,
    pk: Vec<u8>,
    epoch: u32,
    at_block: Option<Hash>,
) -> Result<Option<u128>, String> {
    let store = crate::bool::storage().committee().unpaid_sign_fee(pk.clone(), epoch);
    let pk = "0x".to_string() + &hex::encode(&pk);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => Ok(res),
        Err(e) => {
            log::error!(target: "pallets_api", "query unpaid_sign_fee failed for pk: {pk}, epoch: {epoch}, for: {e:?}");
            Err(format!("query unpaid_sign_fee failed for pk: {pk}, epoch: {epoch}, for: {e:?}"))
        }
    }
}

pub async fn rewards_for_fork(
    sub_client: &BoolSubClient,
    cid: u32,
    epoch: u32,
    fork_id: u8,
    at_block: Option<Hash>,
) -> Option<(u128, Vec<Vec<u8>>)> {
    let store = crate::bool::storage().committee().rewards_for_fork(cid, epoch, fork_id);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none rewards for cid: {}, epoch: {}, fork_id: {}", cid, epoch, fork_id);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query rewards failed for cid: {}, epoch: {}, fork_id: {}, for: {:?}", cid, epoch, fork_id, e);
            return None;
        }
    }
}

pub async fn all_concerned_brc20(
    sub_client: &BoolSubClient,
    at_block: Option<Hash>,
) -> Option<Vec<Vec<u8>>> {
    let store = crate::bool::storage().committee().all_concerned_brc20();
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none brc20 list");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query brc20 list failed for {:?}", e);
            return None;
        }
    }
}

pub async fn brc20_decimals(
    sub_client: &BoolSubClient,
    tick: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<u8> {
    let store = crate::bool::storage().committee().brc20_decimals(tick);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none brc20 decimal");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query brc20 decimal failed for {:?}", e);
            return None;
        }
    }
}

pub async fn committee_assets_consensus(
    sub_client: &BoolSubClient,
    cid: u32,
    at_block: Option<Hash>,
) -> Option<(Vec<u16>, u64, Vec<u8>)> {
    let store = crate::bool::storage().committee().committee_assets_consensus(cid);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none committee asset consensus");
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query committee asset consensus failed for {:?}", e);
            return None;
        }
    }
}