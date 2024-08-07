use crate::bool::runtime_types::node_primitives::AccountId20 as RuntimeAccountId20;
use crate::bool::runtime_types::pallet_rpc::pallet::DeviceInfo;
use crate::BoolSubClient;
use sp_core::H256 as Hash;

pub async fn device_info_rpc(
    sub_client: &BoolSubClient,
    id: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<DeviceInfo<RuntimeAccountId20, u32>> {
    let storage_query = crate::bool::storage().rpc().devices(id.clone());
    match sub_client.query_storage(storage_query, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none device info for id: {:?}", id);
            }
            res
        }
        Err(e) => {
            log::error!(target: "pallets_api", "query device failed: id: {:?} for {:?}", id, e);
            return None;
        }
    }
}

pub async fn relate_deviceid_rpc(
    sub_client: &BoolSubClient,
    id: Vec<u8>,
    at_block: Option<Hash>,) 
    -> Option<Vec<Vec<u8>>> {
    let storage_query = crate::bool::storage().rpc().watcher_deviceid_map_rpc_deviceid(id.clone());
    match sub_client.query_storage(storage_query, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none device info for id: {:?}", id);
            }
            res
            }
            Err(e) => {
                log::error!(target: "pallets_api", "query device failed: id: {:?} for {:?}", id, e);
                return None;
            }
    }
}