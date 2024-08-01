use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct WatchedEventEx {
    pub inner: WatchedEvent,
    pub retry_times: u64,
    pub is_on_chain_checked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct WatchedEvent {
    pub src_chain_id: u32,
    pub dst_chain_id: u32,
    // the source hash of blockchain
    pub src_hash: String,
    // the event's name
    pub name: String,
    // the src anchor
    pub src_anchor: String,
    // the dst anchor
    pub dst_anchor: String,
    // the event unique identity
    pub uid: String,
    // the event's payload to sign
    pub payload: EventPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub enum EventPayload {
    Vrn(Vec<u8>),
    Message(Vec<u8>),
    Brc20Asset(u64, Vec<u8>),
}

/// This is raw cross chain message struct.
/// message from different chains could be change to/from this struct.
/// all param should be big end order bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[repr(C)]
pub struct RawMessage {
    pub uid: Vec<u8>,
    pub cross_type: Vec<u8>,
    pub src_anchor: Vec<u8>,
    pub dst_anchor: Vec<u8>,
    pub extra_feed: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct UniqueIdentification {
    pub src_chain_id: u32,
    pub dst_chain_id: u32,
    pub unique_id: u128,
}

impl UniqueIdentification {
    pub fn new(data: [u8; 32]) -> Self {
        let mut src_chain_id = [0u8; 4];
        let mut dst_chain_id = [0u8; 4];
        let mut unique_id = [0u8; 16];
        src_chain_id.copy_from_slice(&data[..4]);
        dst_chain_id.copy_from_slice(&data[4..8]);
        unique_id.copy_from_slice(&data[16..]);
        let src_chain_id = u32::from_be_bytes(src_chain_id);
        let dst_chain_id = u32::from_be_bytes(dst_chain_id);
        let unique_id = u128::from_be_bytes(unique_id);
        UniqueIdentification {
            src_chain_id,
            dst_chain_id,
            unique_id,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NeedSignedTransaction {
    pub chain_type: crate::ChainType,
    pub chain_id: u32,
    pub to: String, // the to address should strip the '0x' prefix
    pub value: String,
    pub data: String,
    pub sig: String,
    pub pubkey: String, // cmt pk
    pub uid: String,
    pub source_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UncheckParams {
    pub cid: u32,
    pub uid: Vec<u8>,
    pub msg: Vec<u8>,
    pub sig: Vec<u8>,
    pub hash: Vec<u8>,
    pub chain_type: crate::ChainType,
    pub source_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AnchorItem {
    pub chain_id: u32,
    pub address: String,
    pub messenger: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AnchorResponse {
    pub anchors: Vec<AnchorItem>,
}
