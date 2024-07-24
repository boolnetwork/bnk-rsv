use std::str::FromStr;

use crate::{
    sign_with_device_sgx_key, sign_with_device_sgx_key_test, verify_sig_from_string_public, KeyType,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub fn create_sgx_response<T: Serialize>(origin_resp: T, keytype: KeyType) -> String {
    let origin_resp_str = serde_json::to_string(&origin_resp).unwrap();

    let sign_fn = Box::new(|msg: String, keytype: KeyType| {
        let sig = match keytype {
            KeyType::SGX => sign_with_device_sgx_key(msg.as_bytes().to_vec()).unwrap(),
            KeyType::TEST => sign_with_device_sgx_key_test(msg.as_bytes().to_vec()).unwrap(),
        };
        hex::encode(&sig)
    });

    result_parse(origin_resp_str, sign_fn, keytype)
}

pub fn result_parse(
    input: String,
    sign_fn: Box<dyn Fn(String, KeyType) -> String>,
    keytype: KeyType,
) -> String {
    let mut json_data: Value = serde_json::from_str(&input).unwrap();

    if let Some(result) = json_data.get_mut("result") {
        let msg = serde_json::to_string(&result.clone()).unwrap();

        let sig: String = sign_fn(msg, keytype);

        let sgx_result = json!({"result": result, "sig": sig});

        *result = sgx_result;
    }

    serde_json::to_string(&json_data).unwrap()
}

pub fn verify_sgx_response(sgx_response: String, public_key: String) -> Result<bool, String> {
    let (msg, sig) =
        sgx_result_parse(sgx_response).map_err(|e| format!("verify_sgx_response error {e:?}"))?;

    let sig =
        hex::decode(&sig).map_err(|e| format!("verify_sgx_response error decode sig {e:?}"))?;

    verify_sig_from_string_public(msg.as_bytes().to_vec(), sig, public_key)
}

fn sgx_result_parse(input: String) -> Result<(String, String), String> {
    let json_data: Value =
        serde_json::from_str(&input).map_err(|e| format!("sgx_result_parse error {e:?}"))?;

    if let Some(result) = json_data.get("result") {
        let msg = result.get("result").ok_or("no [result]".to_string())?;
        let msg = serde_json::to_string(&msg.clone()).unwrap();

        let sig = result.get("sig").ok_or("no [sig]".to_string())?;

        return Ok((msg, sig.as_str().unwrap().to_string()));
    };

    Err("sgx_result_parse error: no [result] element".to_string())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SGXResponseV2 {
    pub resp: Value,
    pub sig: String,
}

pub fn create_sgx_response_v2_string(origin_resp: String, keytype: KeyType) -> String {
    let sign_fn = Box::new(|msg: String, keytype: KeyType| {
        let sig = match keytype {
            KeyType::SGX => sign_with_device_sgx_key(msg.as_bytes().to_vec()).unwrap(),
            KeyType::TEST => sign_with_device_sgx_key_test(msg.as_bytes().to_vec()).unwrap(),
        };
        hex::encode(&sig)
    });
    let sig = sign_fn(origin_resp.clone(), keytype);

    let resp = Value::from_str(&origin_resp).unwrap();
    let sgx_resp = SGXResponseV2 { resp, sig };

    serde_json::to_string(&sgx_resp).unwrap()
}

pub fn create_sgx_response_v2<T: Serialize>(origin_resp: T, keytype: KeyType) -> String {
    let origin_resp_str = serde_json::to_string(&origin_resp).unwrap();

    let sign_fn = Box::new(|msg: String, keytype: KeyType| {
        let sig = match keytype {
            KeyType::SGX => sign_with_device_sgx_key(msg.as_bytes().to_vec()).unwrap(),
            KeyType::TEST => sign_with_device_sgx_key_test(msg.as_bytes().to_vec()).unwrap(),
        };
        hex::encode(&sig)
    });
    let sig = sign_fn(origin_resp_str.clone(), keytype);

    let resp = Value::from_str(&origin_resp_str).unwrap();
    let sgx_resp = SGXResponseV2 { resp, sig };

    serde_json::to_string(&sgx_resp).unwrap()
}

pub fn verify_sgx_response_and_restore_origin_response_v2(
    sgx_response: String,
    public_key: String,
) -> Result<String, String> {
    let sgx_resp: SGXResponseV2 = serde_json::from_str(&sgx_response)
        .map_err(|e| format!("[verify resp v2] deserilize SGXResponseV2 error {e:?}"))?;

    let origin_resp = sgx_resp.resp;

    let msg = origin_resp.to_string();
    let sig = hex::decode(&sgx_resp.sig)
        .map_err(|e| format!("[verify resp v2] hex::decode sig error {e:?}"))?;

    if verify_sig_from_string_public(msg.as_bytes().to_vec(), sig, public_key)
        .map_err(|e| format!("[verify resp v2] error {e:?}"))?
    {
        if origin_resp.is_string() {
            return Ok(origin_resp.as_str().ok_or("err")?.to_owned());
        } else {
            let origin_resp_str = serde_json::to_string(&origin_resp)
                .map_err(|e| format!("[verify resp v2] deserilize origin_resp fail {e:?}"))?;
            return Ok(origin_resp_str);
        }
    }

    Err("sig verify false".to_string())
}

#[cfg(test)]
mod test {
    use crate::ONLINESK;
    use crate::*;
    use resp_verify::{
        create_sgx_response, create_sgx_response_v2, verify_sgx_response,
        verify_sgx_response_and_restore_origin_response_v2,
    };
    use serde_json::json;

    fn reg_mock() {
        let secret_key = Secret::from_bytes(&[8u8; 32]).unwrap();
        *ONLINESK.write().unwrap() = Some(secret_key);
    }

    fn public_key() -> String {
        get_public(KeyType::SGX)
    }

    ///  eth or btc type json response
    #[test]
    fn test_v2_eth() {
        let block = json!({"blocknum":"888", "hash":"0x1234", "root":"0x5678"});
        let origin_response = json!({"jsonrpc":"1.0", "result":block, "id":"curltest"});

        reg_mock();

        let sgx_result = create_sgx_response_v2(origin_response.clone(), KeyType::SGX);

        let verification_result =
            verify_sgx_response_and_restore_origin_response_v2(sgx_result, public_key()).unwrap();

        assert_eq!(verification_result, origin_response.to_string());
    }

    #[test]
    fn test_parse_v2_string() {
        reg_mock();

        {
            let origin_response =
                "b72a9a7cfbb0685e393f86fa1fa1c43c2888b9ad01c9ac48a28b98e2c8721a89".to_string();
            let origin_resp_str = serde_json::to_string(&origin_response).unwrap();
            let sgx_result = create_sgx_response_v2_string(origin_resp_str.clone(), KeyType::SGX);
            let verification_result =
                verify_sgx_response_and_restore_origin_response_v2(sgx_result, public_key())
                    .unwrap();
            assert_eq!(verification_result, origin_response);
        }

        // After one to_string is applied, the response will be converted to a String in the
        // enum serde_json::Value. Subsequently, using serde_json::to_string will directly
        // take out the internal String. If no to_string is applied, the response will be a enum Object 
        // in enum serde_json::Value.
        // and then using serde_json::to_string will convert the Object into a string.
        // Therefore, the result after one more to_string() is the same.
        {
            let origin_response = json!([
              {
                "txid": "c56a054302df8f8f80c5ac6b86b24ed52bf41d64de640659837c56bc33d10c9e",
                "vout": 0,
                "status": {
                  "confirmed": true,
                  "block_height": 174923,
                  "block_hash": "000000750e335ff355be2e3754fdada30d107d7d916aef07e2f5d014bec845e5",
                  "block_time": 1703321003
                },
                "value": 546
              },
            ]);

            let origin_response_one_more_to_string = serde_json::to_string(&origin_response.clone()).unwrap();
            
            let sgx_result = create_sgx_response_v2(origin_response_one_more_to_string.clone(), KeyType::SGX);

            let verification_result =
                verify_sgx_response_and_restore_origin_response_v2(sgx_result, public_key())
                    .unwrap();

            let sgx_result_2 = create_sgx_response_v2(origin_response.clone(), KeyType::SGX);

            let verification_result_2 =
                 verify_sgx_response_and_restore_origin_response_v2(sgx_result_2, public_key())
                    .unwrap();

            assert_eq!(verification_result, verification_result_2);
        }
    }

    /// GET /signet/api/block/:hash/txid/:index
    /// b72a9a7cfbb0685e393f86fa1fa1c43c2888b9ad01c9ac48a28b98e2c8721a89
    ///
    /// GET /signet/api/address/:address/utxo
    /// curl -sSL "https://mempool.space/signet/api/address/tb1pu8ysre22dcl6qy5m5w7mjwutw73w4u24slcdh4myq06uhr6q29dqwc3ckt/utxo"
    /// https://mempool.space/signet/docs/api/rest#get-address-utxo
    ///
    /// GET /signet/api/blocks/tip/height
    /// 53763
    /// 
    /// GET /signet/api/block/:hash
    #[test]
    fn test_v2_electrs() {
        reg_mock();

        {
            let origin_response =
                "b72a9a7cfbb0685e393f86fa1fa1c43c2888b9ad01c9ac48a28b98e2c8721a89".to_string();
            let sgx_result = create_sgx_response_v2(origin_response.clone(), KeyType::SGX);
            let verification_result =
                verify_sgx_response_and_restore_origin_response_v2(sgx_result, public_key())
                    .unwrap();
            assert_eq!(verification_result, origin_response.to_string());
        }

        {
            let origin_response = json!([
              {
                "txid": "c56a054302df8f8f80c5ac6b86b24ed52bf41d64de640659837c56bc33d10c9e",
                "vout": 0,
                "status": {
                  "confirmed": true,
                  "block_height": 174923,
                  "block_hash": "000000750e335ff355be2e3754fdada30d107d7d916aef07e2f5d014bec845e5",
                  "block_time": 1703321003
                },
                "value": 546
              },
            ]);
            let sgx_result = create_sgx_response_v2(origin_response.clone(), KeyType::SGX);
            let verification_result =
                verify_sgx_response_and_restore_origin_response_v2(sgx_result, public_key())
                    .unwrap();
            assert_eq!(verification_result, origin_response.to_string());
        }

        {
            let origin_response = 53763;
            let sgx_result = create_sgx_response_v2(origin_response.clone(), KeyType::SGX);
            let verification_result =
                verify_sgx_response_and_restore_origin_response_v2(sgx_result, public_key())
                    .unwrap();
            assert_eq!(verification_result, origin_response.to_string());
        }

        {
            let origin_response = json!({
                "id": "000000ca66fab8083d4f0370d499c3d602e78af5fa69b2427cda15a3f0d96152",
                "height": 53745,
                "version": 536870912,
                "timestamp": 1630624390,
                "tx_count": 1,
                "size": 343,
                "weight": 1264,
                "merkle_root": "2c1984132841b9f98270274012b22beb7d4ade778cf058e9a44d38de5a111362",
                "previousblockhash": "000001497bffdc2347656847647f343afc0eee441a849259335b8a1d79b6aa4a",
                "mediantime": 1630621400,
                "nonce": 19642021,
                "bits": 503404179,
                "difficulty": 0
              });
            let sgx_result = create_sgx_response_v2(origin_response.clone(), KeyType::SGX);
            let verification_result =
                verify_sgx_response_and_restore_origin_response_v2(sgx_result, public_key())
                    .unwrap();
            assert_eq!(verification_result, origin_response.to_string());
        }

    }

    #[test]
    fn test_parse_eth_response() {
        let block = json!({"blocknum":"888", "hash":"0x1234", "root":"0x5678"});
        let origin_response = json!({"jsonrpc":"1.0", "result":block, "id":"curltest"});

        reg_mock();

        let sgx_result = create_sgx_response(origin_response, KeyType::SGX);
        println!("sgx_result {:?}", sgx_result);

        let expect_result = json!({
            "id": "curltest",
            "jsonrpc": "1.0",
            "result": json!({
                "result": block,
                "sig": "313990e3c046fb2773e77db569566ea9f89c85ae09de3406c17b81e8fc3c90e2ea7c7d9acec026ebae7c1fd3ba8b4e483fcb43a7eab4faf046e5619b7c050201"
            })
        });

        let expect_result_str = serde_json::to_string(&expect_result).unwrap();
        assert_eq!(expect_result_str, sgx_result);

        let verification_result = verify_sgx_response(sgx_result, public_key()).unwrap();
        assert_eq!(verification_result, true);
    }

    #[test]
    fn test_parse_btc_response() {
        let block = json!({"blocknum":"888", "hash":"0x1234", "root":"0x5678"});
        let origin_response =
            json!({"jsonrpc":"1.0", "result":block, "error": "null" ,"id":"curltest"});

        reg_mock();

        let sgx_result = create_sgx_response(origin_response, KeyType::SGX);
        println!("sgx_result {:?}", sgx_result);

        let expect_result = json!({
            "id": "curltest",
            "error": "null",
            "jsonrpc": "1.0",
            "result": json!({
                "result": block,
                "sig": "313990e3c046fb2773e77db569566ea9f89c85ae09de3406c17b81e8fc3c90e2ea7c7d9acec026ebae7c1fd3ba8b4e483fcb43a7eab4faf046e5619b7c050201"
            })
        });

        let expect_result_str = serde_json::to_string(&expect_result).unwrap();
        assert_eq!(expect_result_str, sgx_result);

        let verification_result = verify_sgx_response(sgx_result, public_key()).unwrap();
        assert_eq!(verification_result, true);
    }

    #[test]
    pub fn helios_test() {
        fn sign_hash_with_sgx_sk_test(input: String) -> String {
            let sig = sign_with_device_sgx_key(input.as_bytes().to_vec()).unwrap();
            hex::encode(sig)
        }

        let block = json!({"blocknum":"888", "hash":"0x1234", "root":"0x5678"});
        let origin_response_1 = json!({"jsonrpc":"1.0", "result":block, "id":"curltest"});

        let str = "ldjflajdfljal";
        let origin_response_2 = json!({"jsonrpc":"1.0", "result":str, "id":"curltest"});

        reg_mock();

        let block_str = serde_json::to_string(&block).unwrap();
        let sig = sign_hash_with_sgx_sk_test(block_str.clone());
        let new_resp = json!({
            "id": "curltest",
            "jsonrpc": "1.0",
            "result": json!({
                "result": block,
                "sig": sig
            })
        });
        let new_resp = serde_json::to_string(&new_resp).unwrap();
        let sgx_result = create_sgx_response(origin_response_1, KeyType::SGX);
        assert_eq!(new_resp, sgx_result);

        assert!(verify_sgx_response(new_resp, public_key()).unwrap());

        let str_str = serde_json::to_string(&str).unwrap();
        //let str_str = str.to_string();
        let sig = sign_hash_with_sgx_sk_test(str_str.clone());
        let new_resp = json!({
            "id": "curltest",
            "jsonrpc": "1.0",
            "result": json!({
                "result": str,
                "sig": sig
            })
        });
        let new_resp = serde_json::to_string(&new_resp).unwrap();
        let sgx_result = create_sgx_response(origin_response_2, KeyType::SGX);
        assert_eq!(new_resp, sgx_result);
        assert!(verify_sgx_response(new_resp, public_key()).unwrap());
    }

    /// curl -k  --user prz:prz --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "generate", "params": [10]}'  https://127.0.0.1:18334/
    #[test]
    pub fn asd(){
        let resp = r#"{"jsonrpc":"1.0","result":{"result":
        ["221f546c2b26e396d0dbc91abce905bab72f67d5fbb6ac6bc888d81cb9de4735",
        "5d766b8e2210b498cf146f8b9e278a1ab2813eccb04122d421a41f2f1ebea066",
        "3cff7e4209cf7a1e80f4d77281b1479a97d06bbe8a6c817ee2d2e874284eab87",
        "3a4bbf0d8f4cc935ae198baa4975aefa9cd6e9d9a27d0f2f7ca770247460d328",
        "7f408823c815fb54a93e06222600781f5a3177177d7328e266cc27b26c9eb94c",
        "48501e534dedda247bb1028dfa8c7439ed5c3098ea511f7f4efa57db31ea979d",
        "7b2393fc75f1fd26425fd991fe4bd971dfc9db22d5e91872eca8958252c3ee5d",
        "5560a2422cde2131cbf8f5df6dc34a2152dac90d7da7b9e2f42e65c1241c89ec",
        "1bef267d5ed1ff813cceef853dc88c2c3e722de7e796f7a45c845a0f8a2f0c75",
        "497c1eadc5debff21dccc63f79c0c595bc927cfda5b8c4d67ab1e47c821b7ed5"]
        ,"sig":"f0af8d2adba58fbfc0560f5fe4089754a8ecd683ac8bb4b320f8da86e79c146ba993b4ab61ee2a36f803c6b59dd0f69099c7e112e2bb0c8b48ba4d00cce93105"},
        "error":null,
        "id":"curltest"}"#;

        let pubkey = "d3bf5eaec58db3d802e4868a7821af531bc603662248358c5c346aa6fb304090";

        let verification_result = verify_sgx_response(resp.to_string(), pubkey.to_string()).unwrap();
        assert_eq!(verification_result, true);
    }

    #[tokio::test]
    pub async fn test_btcd_parse() {
        use reqwest::{Client, Url};
        use reqwest::header::AUTHORIZATION;

        let url = Url::parse("https://127.0.0.1:18334/").unwrap();
        let client = Client::new();

        let req = json!({
            "jsonrpc": "2.0",
            "method": "getblockchaininfo",
            "params": [],
            "id": 0,
        });
        let request = req.to_string();
        let response = client
        .get(url)
        .header("Content-Type", "application/json")
        .basic_auth("prz", Some("prz"))
        .header(AUTHORIZATION, " Basic cHJ6OnByeg==")
        .body(request)
        .timeout(std::time::Duration::from_secs(5)).send().await.unwrap();
       
        println!("response {:?}",response);

        // response.send()
        // .await.unwrap();

    }
}
