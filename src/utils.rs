use pallets_api::hash_to_version;
use pallets_api::BoolSubClient;
use sha3::{Digest, Sha3_256};

pub fn sha3_hash256(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.input(msg);
    hasher.result()[..].to_vec()
}

pub fn no_prefix<T: AsRef<str>>(data: T) -> String {
    data.as_ref()
        .strip_prefix("0x")
        .unwrap_or(data.as_ref())
        .to_string()
}

pub async fn verify_enclave_hash(
    sub_client: &BoolSubClient,
    version: u16,
    enclave_hash: Vec<u8>,
) -> Result<bool, String> {
    if version == 0 {
        return Ok(true);
    }
    let online_enclave_list = hash_to_version(sub_client, version, None)
        .await
        .ok_or("hash_to_version failed".to_string())?;

    let online_enclave_hashs: Vec<Vec<u8>> = online_enclave_list
        .as_slice()
        .chunks(32)
        .map(|c| c.to_vec())
        .collect();
    Ok(online_enclave_hashs.contains(&enclave_hash))
}

pub async fn call_register_rpc(
    sub_client: &BoolSubClient,
    config_owner: &str,
    did: (u16, Vec<u8>),
    report: Vec<u8>,
    signature: Vec<u8>,
) -> Result<String, String> {
    let (version, _pk) = did;
    let owner = hex::decode(no_prefix(config_owner)).map_err(|e| e.to_string())?;
    let mut owner_bytes = [0u8; 20];
    owner_bytes.copy_from_slice(&owner);
    match pallets_api::register_device_rpc(
        sub_client,
        pallets_api::bool::runtime_types::node_primitives::AccountId20(owner_bytes),
        report,
        version,
        signature,
    )
    .await
    {
        Ok(hash) => Ok("0x".to_string() + &hex::encode(hash.0)),
        Err(e) => Err(e),
    }
}
