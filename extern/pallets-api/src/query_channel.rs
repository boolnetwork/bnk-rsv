use sp_core::H256 as Hash;
use crate::bool::runtime_types::pallet_channel::pallet::{
    TxMessage, Channel, SourceTXInfo, BtcTxTunnel, BtcCmtType, TaprootPair, RefreshRecord,
};
use crate::bool::runtime_types::node_primitives::AccountId20;
use crate::BoolSubClient;

pub async fn tx_messages(
    sub_client: &BoolSubClient,
    cid: u32,
    hash: Hash,
    at_block: Option<Hash>,
) -> Option<TxMessage<u32>> {
    let store = crate::bool::storage().channel().tx_messages(cid, hash);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none tx_message for cid: {}, hash: {:?}", cid, hash);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query tx_message failed for cid: {}, hash: {:?}: for: {:?}", cid, hash, e);
            return None;
        }
    }
}

pub async fn channel_info(
    sub_client: &BoolSubClient,
    channel_id: u32,
    at_block: Option<Hash>,
) -> Option<Channel<AccountId20>> {
    let store = crate::bool::storage().channel().channel_info(channel_id);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none channel_info for channel_id: {:?}", channel_id);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query channel_info failed: cid: {:?} for {:?}", channel_id, e);
            return None;
        }
    }
}

pub async fn hashes_for_cid(
    sub_client: &BoolSubClient,
    cid: u32,
    at_block: Option<Hash>,
) -> Option<(Vec<SourceTXInfo>, BtcTxTunnel)> {
    let store = crate::bool::storage().channel().hashes_for_cid(cid);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none hash_for_cid for cid: {:?}", cid);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query hash_for_cid failed: cid: {:?} for {:?}", cid, e);
            return None;
        }
    }
}

pub async fn source_tx_package(
    sub_client: &BoolSubClient,
    cid: u32,
    package_key: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<Vec<SourceTXInfo>> {
    let store = crate::bool::storage().channel().source_tx_package(cid, package_key.clone());
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none src_tx_package for cid: {:?}, package key: {:?}", cid, hex::encode(&package_key));
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query src_tx_package failed: cid: {:?} package_key: {:?}, for {:?}", cid, hex::encode(&package_key), e);
            return None;
        }
    }
}

pub async fn source_hash_to_package_key
(
    sub_client: &BoolSubClient,
    chain_id: u32,
    src_hash: Vec<u8>,
    at_block: Option<Hash>,
) -> Option<Vec<u8>> {
    let store = crate::bool::storage().channel().source_hash_to_package_key(chain_id, src_hash.clone());
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none src_hash_to_package_key for chain id: {:?}, src_hash: {:?}", chain_id, hex::encode(&src_hash));
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query src_tx_package failed: chain_id: {:?} src_hash: {:?} for {:?}", chain_id, hex::encode(&src_hash), e);
            return None;
        }
    }
}

pub async fn btc_committee_type(
    sub_client: &BoolSubClient,
    cid: u32,
    at_block: Option<Hash>,
) -> Option<BtcCmtType> {
    let store = crate::bool::storage().channel().btc_committee_type(cid);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none btc committee type for cid: {:?}", cid);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query btc committee type failed: cid: {:?} for {:?}", cid, e);
            return None;
        }
    }
}

pub async fn btc_committee_type_iter(
    sub_client: &BoolSubClient,
    page_size: u32,
    at_block: Option<Hash>,
) -> Result<Vec<BtcCmtType>, subxt::Error> {
    let store = crate::bool::storage().channel().btc_committee_type_root();
    sub_client.query_storage_value_iter(store, page_size, at_block).await
}

pub async fn escape_taproot(sub_client: &BoolSubClient, cid: u32, at_block: Option<Hash>) -> Option<TaprootPair> {
    let store = crate::bool::storage().channel().escape_taproots(cid);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none escape_taproot for cid: {}", cid);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query escape_taproot failed: cid: {}, for {:?}", cid, e);
            return None;
        }
    }
}

pub async fn escape_taproot_iter(
    sub_client: &BoolSubClient,
    page_size: u32,
    at_block: Option<Hash>,
) -> Result<Vec<TaprootPair>, subxt::Error> {
    let store = crate::bool::storage().channel().escape_taproots_root();
    sub_client.query_storage_value_iter(store, page_size, at_block).await
}

pub async fn refresh_record(
    sub_client: &BoolSubClient,
    inscription_hash: Vec<u8>,
    inscription_pos: u8,
    at_block: Option<Hash>,
) -> Option<RefreshRecord> {
    let store = crate::bool::storage().channel().refresh_data(inscription_hash.clone(), inscription_pos);
    match sub_client.query_storage(store, at_block).await {
        Ok(res) => {
            if res.is_none() {
                log::warn!(target: "pallets_api", "query none refresh data for inscription_hash: {:?}, inscription_pos: {:?}", inscription_hash, inscription_pos);
            }
            res
        },
        Err(e) => {
            log::error!(target: "pallets_api", "query refresh data failed for: {:?}", e);
            return None;
        }
    }
}
