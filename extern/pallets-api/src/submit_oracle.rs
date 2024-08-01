use node_primitives::Hash;
use crate::{BoolSubClient, handle_custom_error};

pub async fn request_random_number(
    client: &BoolSubClient,
    bls_cid: u32,
    ecdsa_cid: u32,
    chain_id: u32,
    request_id: Vec<u8>,
    consumer_addr: Vec<u8>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().oracle().request_random_number(bls_cid, ecdsa_cid, chain_id, request_id, consumer_addr);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn report_sig_about_random_num(
    client: &BoolSubClient,
    cid: u32,
    chain_id: u32,
    nonce: Vec<u8>,
    sender_pk: Vec<u8>,
    sender_sig: Vec<u8>,
    cmt_sig: Vec<u8>,
    fork_id: u8,
) -> Result<Hash, String> {
    let call = crate::bool::tx().oracle().report_sig_about_random_num(cid, chain_id, nonce, sender_pk, sender_sig, cmt_sig, fork_id);
    client.submit_extrinsic_without_signer(call).await.map_err(|e| {
        handle_custom_error(e)
    })
}

pub async fn import_new_btc_block(
    client: &BoolSubClient,
    block_height: u64,
    total_instructions: u32,
    start_index: u32,
    instructions_num: u32,
    transactions: Vec<u8>,
    need_watche_res: bool,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().oracle().import_new_btc_block(block_height, total_instructions, start_index, instructions_num, transactions);
    if need_watche_res {
        client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
    } else {
        client.submit_extrinsic_with_signer_without_watch(call, nonce).await.map_err(|e| e.to_string())
    }
}

pub async fn report_sig_about_brc20(
    client: &BoolSubClient,
    height: u64,
    chunk_index: u32,
    sender_pk: Vec<u8>,
    sender_sig: Vec<u8>,
    cmt_sig: Vec<u8>,
    fork_id: u8,
) -> Result<Hash, String> {
    let call = crate::bool::tx().oracle().report_sig_about_brc20(height, chunk_index, sender_pk, sender_sig, cmt_sig, fork_id);
    client.submit_extrinsic_without_signer(call).await.map_err(|e| {
        handle_custom_error(e)
    })
}

pub async fn new_brc20_oracle_request(
    client: &BoolSubClient,
    chain_id: u32,
    oracle: Vec<u8>,
    uid: u64,
    data: Vec<u8>,
    nonce: Option<u32>,
) -> Result<Hash, String> {
    let call = crate::bool::tx().oracle().new_brc20_oracle_request(chain_id, oracle, uid, data);
    client.submit_extrinsic_with_signer_and_watch(call, nonce).await.map_err(|e| e.to_string())
}

pub async fn report_brc20_oracle_sig(
    client: &BoolSubClient,
    chain_id: u32,
    oracle: Vec<u8>,
    uid: u64,
    sender_pk: Vec<u8>,
    sender_sig: Vec<u8>,
    cmt_sig: Vec<u8>,
    fork_id: u8,
) -> Result<Hash, String> {
    let call = crate::bool::tx().oracle().report_brc20_oracle_sig(chain_id, oracle, uid, sender_pk, sender_sig, cmt_sig, fork_id);
    client.submit_extrinsic_without_signer(call).await.map_err(|e| {
        handle_custom_error(e)
    })
}
