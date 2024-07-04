use sha3::{Digest, Sha3_256};

pub fn sha3_hash256(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.input(msg);
    hasher.result()[..].to_vec()
}
