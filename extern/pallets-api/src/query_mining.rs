use node_primitives::AccountId20;
use crate::bool::runtime_types::node_primitives::AccountId20 as RuntimeAccountId20;
use crate::bool::runtime_types::{
    primitive_types::U256,
    pallet_facility::pallet::DIdentity
};
use anyhow::{anyhow, Result};
use sp_core::{H256 as Hash};
use crate::BoolSubClient;
use crate::bool::runtime_types::pallet_mining::pallet::DeviceInfo;

pub async fn pids_for_account(
    sub_client: &BoolSubClient,
    account: AccountId20,
    at_block: Option<Hash>,
) -> Option<Vec<u32>> {
    let store = crate::bool::storage().mining().account_pids(
        crate::bool::runtime_types::node_primitives::AccountId20(account.0),
    );
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none pids for account: {:?}", account);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query pids failed: did: {:?} for {:?}", account, e);
            return None;
        }
    }
}

pub async fn challenges(
    sub_client: &BoolSubClient,
    session: u32,
    at_block: Option<Hash>,
) -> Option<U256> {
    let store = crate::bool::storage().mining().challenges(session);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none challenges for session: {:?}", session);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query challenges failed: session: {:?} for {:?}", session, e);
            return None;
        }
    }
}

pub async fn working_devices(
    sub_client: &BoolSubClient,
    session: Option<u32>,
    at_block: Option<Hash>,
) -> Option<(Vec<(DIdentity, bool)>, u32)> {
    let session = match session {
        Some(session) => session,
        None => {
            let client = sub_client.client.read().await.blocks();
            let current_block = match at_block {
                Some(hash) => {
                    client.at(hash).await
                },
                None => {
                    client.at_latest().await
                }
            };
            let current_number = match current_block {
                Ok(block) => block.number(),
                Err(e) => {
                    log::warn!(target: "pallets_api", "query block failed at for {:?}", e);
                    return None;
                }
            };
            let constant_query = crate::bool::constants().mining().era_block_number();
            if let Ok(era_block_number) = sub_client.query_constant(constant_query).await {
                current_number / era_block_number
            } else {
                return None
            }
        }
    };
    let store = crate::bool::storage().mining().working_devices(session);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none devices for session: {:?}", session);
            }
            res.and_then(|data| Some((data.0, session)))
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query working devices failed: session: {:?} for {:?}", session, e);
            return None;
        }
    }
}

pub async fn device_info_v2(
    sub_client: &BoolSubClient,
    id: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<DeviceInfo<RuntimeAccountId20, u32, u128>> {
    let storage_query = crate::bool::storage().mining().devices(id.clone());
    match sub_client.query_storage(storage_query, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none device info for id: {:?}", id);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query device failed: id: {:?} for {:?}", id, e);
            return None;
        }
    }
}

pub async fn device_votes_for_current_epoch(
    sub_client: &BoolSubClient,
    id: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<Vec<(RuntimeAccountId20, u128)>> {
    let storage_query = crate::bool::storage().mining().device_votes_for_current_epoch(id.clone());
    match sub_client.query_storage(storage_query, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none vote info for id: {:?}", id);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query vote info failed: id: {:?} for {:?}", id, e);
            return None;
        }
    }
}

pub async fn device_votes_for_next_epoch(
    sub_client: &BoolSubClient,
    id: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<Vec<(RuntimeAccountId20, u128)>> {
    let storage_query = crate::bool::storage().mining().device_votes_for_next_epoch(id.clone());
    match sub_client.query_storage(storage_query, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none vote info for id: {:?}", id);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query vote info failed: id: {:?} for {:?}", id, e);
            return None;
        }
    }
}

pub async fn device_data(
    sub_client: &BoolSubClient,
    did: DIdentity,
    at_block: Option<Hash>,
) -> Result<Option<Vec<u8>>> {
    let store = crate::bool::storage().mining().device_data(did.clone());
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none device_data for did: {did:?}");
            }
            Ok(res)
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query device_data failed: did: {did:?} for {e:?}");
            Err(anyhow!("{e:?}"))
        }
    }
}
