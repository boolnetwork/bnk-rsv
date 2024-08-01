use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PreparedCrossTransactionData {
    pub channel_id: u32,
    pub cid: u32,
    pub uid: Vec<u8>,
    pub msg: Vec<u8>,
    pub chain_type: crate::ChainType,
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub amount: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ExtrinsicData {
    PreparedCrossTransaction(PreparedCrossTransactionData),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NeedSignedExtrinsic {
    pub id: u32,
    pub data: ExtrinsicData,
}
