use crate::EngineType;
use serde::{Deserialize, Serialize};

//######## user to chain
// cross chain extra data. big-end

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockedExtra {
    V1(LockedExtraV1),
}

impl LockedExtra {
    pub fn version(&self) -> u8 {
        match self {
            Self::V1(inner) => inner.version,
        }
    }

    pub fn nonce(&self) -> u32 {
        match self {
            Self::V1(inner) => inner.nonce,
        }
    }

    pub fn transfer_fee(&self) -> u32 {
        match self {
            Self::V1(inner) => inner.transfer_fee,
        }
    }

    pub fn addr_len(&self) -> u32 {
        match self {
            Self::V1(inner) => inner.addr_len,
        }
    }

    pub fn addr(&self) -> Vec<u8> {
        match self {
            Self::V1(inner) => inner.addr.clone(),
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::V1(inner) => inner.to_bytes(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        match data[0] {
            1 => {
                let inner = LockedExtraV1::from_bytes(data)?;
                Ok(Self::V1(inner))
            }
            _ => Err(format!("unknown {} version", data[0])),
        }
    }
}

impl Default for LockedExtra {
    fn default() -> Self {
        LockedExtra::V1(LockedExtraV1::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedExtraV1 {
    // 1 bytes
    pub version: u8,
    // 4 bytes
    pub nonce: u32,
    // 4 bytes
    pub transfer_fee: u32,
    // 4 bytes
    pub addr_len: u32,
    // dynamic array
    pub addr: Vec<u8>,
}

impl LockedExtraV1 {
    const MIN_LEN: usize = 13;

    pub fn to_bytes(mut self) -> Vec<u8> {
        let mut out = [0u8; Self::MIN_LEN].to_vec();
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.nonce.to_be_bytes());
        out[5..9].copy_from_slice(&self.transfer_fee.to_be_bytes());
        out[9..13].copy_from_slice(&self.addr_len.to_be_bytes());
        out.append(&mut self.addr);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::MIN_LEN {
            return Err("Invalid length".to_string());
        }

        let mut extra = Self::default();

        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&data[1..5]);
        extra.nonce = u32::from_be_bytes(tmp);
        tmp.copy_from_slice(&data[5..9]);
        extra.transfer_fee = u32::from_be_bytes(tmp);
        tmp.copy_from_slice(&data[9..13]);
        extra.addr_len = u32::from_be_bytes(tmp);
        if data.len() != extra.addr_len as usize + Self::MIN_LEN {
            return Err("Invalid address".to_string());
        }
        extra.addr = data[13..].to_vec();

        Ok(extra)
    }
}

impl Default for LockedExtraV1 {
    fn default() -> Self {
        Self {
            version: 1,
            nonce: 0,
            transfer_fee: 0,
            addr_len: 0,
            addr: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeltedExtra {
    V1(MeltedExtraV1),
}

impl MeltedExtra {
    pub fn version(&self) -> u8 {
        match self {
            Self::V1(inner) => inner.version,
        }
    }

    pub fn nonce(&self) -> u32 {
        match self {
            Self::V1(inner) => inner.nonce,
        }
    }

    pub fn transfer_fee(&self) -> u32 {
        match self {
            Self::V1(inner) => inner.transfer_fee,
        }
    }

    pub fn addr_len(&self) -> u32 {
        match self {
            Self::V1(inner) => inner.addr_len,
        }
    }

    pub fn addr(&self) -> Vec<u8> {
        match self {
            Self::V1(inner) => inner.addr.clone(),
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::V1(inner) => inner.to_bytes(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        match data[0] {
            1 => {
                let inner = MeltedExtraV1::from_bytes(data)?;
                Ok(Self::V1(inner))
            }
            _ => Err(format!("unknown {} version", data[0])),
        }
    }
}

impl Default for MeltedExtra {
    fn default() -> Self {
        Self::V1(MeltedExtraV1::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeltedExtraV1 {
    // 1 bytes
    pub version: u8,
    // 4 bytes
    pub nonce: u32,
    // 4 bytes
    pub transfer_fee: u32,
    // 4 bytes
    pub addr_len: u32,
    // dynamic array
    pub addr: Vec<u8>,
}

impl MeltedExtraV1 {
    const MIN_LEN: usize = 13;

    pub fn to_bytes(mut self) -> Vec<u8> {
        let mut out = [0u8; Self::MIN_LEN].to_vec();
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.nonce.to_be_bytes());
        out[5..9].copy_from_slice(&self.transfer_fee.to_be_bytes());
        out[9..13].copy_from_slice(&self.addr_len.to_be_bytes());
        out.append(&mut self.addr);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::MIN_LEN {
            return Err("Invalid length".to_string());
        }

        let mut extra = Self::default();

        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&data[1..5]);
        extra.nonce = u32::from_be_bytes(tmp);
        tmp.copy_from_slice(&data[5..9]);
        extra.transfer_fee = u32::from_be_bytes(tmp);
        tmp.copy_from_slice(&data[9..13]);
        extra.addr_len = u32::from_be_bytes(tmp);
        if data.len() != extra.addr_len as usize + Self::MIN_LEN {
            return Err("Invalid address".to_string());
        }
        extra.addr = data[13..].to_vec();

        Ok(extra)
    }
}

impl Default for MeltedExtraV1 {
    fn default() -> Self {
        Self {
            version: 1,
            nonce: 0,
            transfer_fee: 0,
            addr_len: 0,
            addr: vec![],
        }
    }
}

pub fn disintegrate_btc_msg(raw_msg: &str) -> Result<(Vec<String>, Vec<Vec<String>>, Vec<Vec<u64>>, bool), String> {
    let mut raw_msg = hex::decode(raw_msg).map_err(|e| e.to_string())?;
    if raw_msg.len() <= 2 {
        return Err(
            format!("msg length too short: {} ", raw_msg.len())
        );
    }

    // read taproot data.
    let is_taproot = raw_msg.pop().unwrap() == 1;
    if is_taproot {
        raw_msg.truncate(raw_msg.len() - 32);
    }

    let is_brc20 = raw_msg.pop().unwrap() == 1;
    if is_brc20 {
        // three tx's msg_hash offset num(u8)
        if raw_msg.len() <= 3 {
            return Err(
                format!("invalid brc20 tx length: {}", raw_msg.len())
            )
        }
        let transfer_tx_to_sign_num = raw_msg.pop().unwrap() as usize;
        let reveal_to_sign_num = raw_msg.pop().unwrap() as usize;
        let commit_tx_to_sign_num = raw_msg.pop().unwrap() as usize;
        let total_hash_num_to_sign = transfer_tx_to_sign_num + reveal_to_sign_num + commit_tx_to_sign_num;
        if raw_msg.len() <= total_hash_num_to_sign * 32 {
            return Err(
                format!("invalid brc20 msg length: {}", raw_msg.len()),
            )
        }
        raw_msg.reverse();
        let all_to_sign = &mut raw_msg[..total_hash_num_to_sign * 32];
        all_to_sign.reverse();
        let mut commit_tx_to_sign = Vec::new();
        for i in 0..commit_tx_to_sign_num {
            let msg = &all_to_sign[i * 32..(i + 1) * 32];
            commit_tx_to_sign.push(hex::encode(msg));
        }
        let mut reveal_tx_to_sign = Vec::new();
        for i in commit_tx_to_sign_num..commit_tx_to_sign_num + reveal_to_sign_num {
            let msg = &all_to_sign[i * 32..(i + 1) * 32];
            reveal_tx_to_sign.push(hex::encode(msg));
        }

        let mut transfer_tx_to_sign = Vec::new();
        for i in commit_tx_to_sign_num + reveal_to_sign_num..total_hash_num_to_sign {
            let msg = &all_to_sign[i * 32..(i + 1) * 32];
            transfer_tx_to_sign.push(hex::encode(msg));
        }

        // raw.append(&mut commit_tx_raw);
        // raw.append(&mut reveal_tx_raw);
        // raw.append(&mut transfer_tx_raw);
        //
        // // append three txs' raw len
        // raw.append(&mut commit_tx_len);
        // raw.append(&mut reveal_tx_len);
        // raw.append(&mut transfer_tx_len);
        let tx_msgs_with_offset = &mut raw_msg[total_hash_num_to_sign * 32..].to_vec();

        if tx_msgs_with_offset.len() <= 3 * 4 {
            return Err(
                format!("brc20 raw msg off set error, raw msg len: {}", tx_msgs_with_offset.len())
            );
        }
        let (transfer_tx_len_bytes, reset1) = tx_msgs_with_offset.split_at_mut(4);
        let (reveal_tx_len_bytes, reset2) = reset1.split_at_mut(4);
        let (commit_tx_len_bytes, reset3) = reset2.split_at_mut(4);
        transfer_tx_len_bytes.reverse();
        reveal_tx_len_bytes.reverse();
        commit_tx_len_bytes.reverse();
        let mut transfer_tx_len_tmp = [0u8; 4];
        transfer_tx_len_tmp.copy_from_slice(&transfer_tx_len_bytes);
        let mut reveal_tx_len_tmp = [0u8; 4];
        reveal_tx_len_tmp.copy_from_slice(&reveal_tx_len_bytes);
        let mut commit_tx_len_tmp = [0u8; 4];
        commit_tx_len_tmp.copy_from_slice(&commit_tx_len_bytes);

        let transfer_tx_len = u32::from_le_bytes(transfer_tx_len_tmp) as usize;
        let reveal_tx_len = u32::from_le_bytes(reveal_tx_len_tmp) as usize;
        let commit_tx_len = u32::from_le_bytes(commit_tx_len_tmp) as usize;

        if reset3.len() != (transfer_tx_len + reveal_tx_len + commit_tx_len) {
            return Err(
                format!("invalid brc20 raw msg length: {}, expect: {}", reset3.len(), (transfer_tx_len + reveal_tx_len + commit_tx_len))
            );
        }

        let mut transfer_tx = reset3[..transfer_tx_len].as_ref().to_vec();
        let mut reveal_tx = reset3[transfer_tx_len..transfer_tx_len + reveal_tx_len].as_ref().to_vec();
        let mut commit_tx = reset3[transfer_tx_len + reveal_tx_len..].as_ref().to_vec();
        transfer_tx.reverse();
        reveal_tx.reverse();
        commit_tx.reverse();

        Ok(
            (
                vec![hex::encode(commit_tx), hex::encode(reveal_tx), hex::encode(transfer_tx)],
                vec![commit_tx_to_sign, reveal_tx_to_sign, transfer_tx_to_sign],
                vec![],
                is_brc20
            )
        )
    } else {
        let to_sign_num = raw_msg.pop().unwrap() as usize;
        if raw_msg.len() <= to_sign_num * 8 + to_sign_num * 32 {
            return Err("invalid message length".to_string());
        }
        raw_msg.reverse();
        let all_values = &mut raw_msg[0..to_sign_num * 8].to_vec(); // [0..16]
        let all_to_sign = &mut raw_msg[to_sign_num * 8..(to_sign_num * 8 + to_sign_num * 32)].to_vec(); // [16..80]
        let msg_vec = &mut raw_msg[(to_sign_num * 8 + to_sign_num * 32)..].to_vec();
        all_values.reverse();
        all_to_sign.reverse();
        msg_vec.reverse();
        let raw_tx = hex::encode(&msg_vec); // [80..]
        let mut messages_should_sign = Vec::new();
        for i in 0..to_sign_num {
            let msg = &all_to_sign[i * 32..(i + 1) * 32];
            messages_should_sign.push(hex::encode(msg));
        }
        let mut values = Vec::new();
        let value_num = all_values.len() / 8usize;
        for i in 0..value_num {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&all_values[i * 8..(i + 1) * 8]);
            values.push(u64::from_le_bytes(tmp))
        }
        Ok((vec![raw_tx], vec![messages_should_sign], vec![values], is_brc20))
    }
}

pub fn disintegrate_fil_msg(
    raw_msg: &str,
    engine: &EngineType,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut raw_msg = hex::decode(raw_msg).map_err(|e| e.to_string())?;
    let hash_length = match engine {
        EngineType::ECDSA => 32,
        EngineType::BLS => 38,
        _ => unimplemented!(),
    };
    if raw_msg.len() <= hash_length {
        return Err("invalid message length".to_string());
    }
    raw_msg.reverse();
    let msg_need_to_sign = &mut raw_msg[..hash_length].to_vec();
    let raw_tx = &mut raw_msg[hash_length..].to_vec();
    msg_need_to_sign.reverse();
    raw_tx.reverse();
    Ok((raw_tx.to_vec(), msg_need_to_sign.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn lock_extra_serde_test() {
        let addr = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let extra = LockedExtra::V1(LockedExtraV1 {
            version: 1,
            nonce: 1,
            transfer_fee: 0,
            addr_len: 20,
            addr: addr.to_vec(),
        });

        let extra_bytes = extra.clone().to_bytes();
        println!("{:?}", hex::encode(&extra_bytes));
        let real_bytes = <Vec<u8>>::from_hex(
            "010000000100000000000000140102030405060708090a0b0c0d0e0f1011121314",
        )
        .unwrap();
        assert_eq!(extra_bytes, real_bytes);

        let ds_extra = LockedExtra::from_bytes(&real_bytes).unwrap();
        assert_eq!(extra, ds_extra);
    }
}
