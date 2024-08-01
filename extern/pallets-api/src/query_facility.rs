use crate::bool::runtime_types::node_primitives::AccountId20;
use crate::bool::runtime_types::pallet_facility::pallet::{Device, DIdentity};
use sp_core::H256 as Hash;
use crate::BoolSubClient;

pub async fn device_info(
    sub_client: &BoolSubClient,
    did: &DIdentity,
    at_block: Option<Hash>,
) -> Option<Device<AccountId20>> {
    let storage_query = crate::bool::storage().facility().device_to_did(did);
    match sub_client.query_storage(storage_query, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none device info for did: {:?}", did);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query device failed: did: {:?} for {:?}", did, e);
            return None;
        }
    }
}

pub async fn report_to_didentity(
    sub_client: &BoolSubClient,
    did: DIdentity,
    at_block: Option<Hash>,
) -> Option<Vec<u8>> {
    let store = crate::bool::storage().facility().report_to_identity(&did);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none report info for did: {:?}", did);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query report failed: did: {:?} for {:?}", did, e);
            return None;
        }
    }
}

pub async fn version_to_pk(
    sub_client: &BoolSubClient,
    pk: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<u16> {
    let store = crate::bool::storage().facility().version_to_pk(pk.clone());
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query version info for pk: {:?}", pk);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query version failed: pk: {:?} for {:?}", pk, e);
            return None;
        }
    }
}

pub async fn hash_to_version(
    sub_client: &BoolSubClient,
    version: u16,
    at_block: Option<Hash>,
) -> Option<Vec<u8>> {
    let store = crate::bool::storage().facility().hash_to_version(&version);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query hash info for version: {}", version);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query hash failed: version: {} for {:?}", version, e);
            return None;
        }
    }
}

pub async fn version_list(sub_client: &BoolSubClient, at_block: Option<Hash>) -> Option<Vec<u16>> {
    let store = crate::bool::storage().facility().version_list();
    match sub_client.query_storage_or_default(store, at_block).await {
        Ok(res) => Some(res),
        Err(e) => {
            log::error!(target: "pallets_api", "query version_list failed for {:?}", e);
            return None;
        }
    }
}
