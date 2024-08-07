use std::str::FromStr;

use crate::{
    get_public, sign_with_device_sgx_key, sign_with_device_sgx_key_test,
    verify_sig_from_string_public, KeyType,
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

pub fn sgx_result_parse(input: String) -> Result<(String, String), String> {
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
    pub pubkey: String,
}

pub fn create_sgx_response_v2_string(origin_resp: String, keytype: KeyType) -> String {
    let sign_fn = Box::new(|msg: String, keytype: &KeyType| {
        let sig = match keytype {
            KeyType::SGX => sign_with_device_sgx_key(msg.as_bytes().to_vec()).unwrap(),
            KeyType::TEST => sign_with_device_sgx_key_test(msg.as_bytes().to_vec()).unwrap(),
        };
        hex::encode(&sig)
    });
    let sig = sign_fn(origin_resp.clone(), &keytype);

    let pubkey = get_public(keytype);

    let resp = Value::from_str(&origin_resp).unwrap();
    let sgx_resp = SGXResponseV2 { resp, sig, pubkey };

    serde_json::to_string(&sgx_resp).unwrap()
}

pub fn create_sgx_response_v2<T: Serialize>(origin_resp: T, keytype: KeyType) -> String {
    let origin_resp_str = serde_json::to_string(&origin_resp).unwrap();

    let sign_fn = Box::new(|msg: String, keytype: &KeyType| {
        let sig = match keytype {
            KeyType::SGX => sign_with_device_sgx_key(msg.as_bytes().to_vec()).unwrap(),
            KeyType::TEST => sign_with_device_sgx_key_test(msg.as_bytes().to_vec()).unwrap(),
        };
        hex::encode(&sig)
    });
    let sig = sign_fn(origin_resp_str.clone(), &keytype);
    let resp = Value::from_str(&origin_resp_str).unwrap();
    let pubkey = get_public(keytype);

    let sgx_resp = SGXResponseV2 { resp, sig, pubkey };

    serde_json::to_string(&sgx_resp).unwrap()
}

pub fn verify_sgx_response_and_restore_origin_response_v2(
    sgx_response: String,
    _public_key: String,
) -> Result<String, String> {
    let sgx_resp: SGXResponseV2 = serde_json::from_str(&sgx_response)
        .map_err(|e| format!("[verify resp v2] deserilize SGXResponseV2 error {e:?}"))?;

    let origin_resp = sgx_resp.resp;
    let public_key = sgx_resp.pubkey;
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

#[derive(Serialize, Deserialize, Debug)]
pub struct PubkeyResponse {
    pub pubkey: String,
}

#[cfg(test)]
mod test {
    use crate::ONLINESK;
    use crate::*;
    use resp_verify::{
        create_sgx_response, create_sgx_response_v2, verify_sgx_response,
        verify_sgx_response_and_restore_origin_response_v2, PubkeyResponse,
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

            let origin_response_one_more_to_string =
                serde_json::to_string(&origin_response.clone()).unwrap();

            let sgx_result =
                create_sgx_response_v2(origin_response_one_more_to_string.clone(), KeyType::SGX);

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
            let verification_result = verify_sgx_response_and_restore_origin_response_v2(
                sgx_result,
                "public_key()".to_string(),
            )
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
    async fn send_req(req: String) -> String {
        use reqwest::{Client, Url};
        let url = Url::parse("https://127.0.0.1:18334/").unwrap();
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let response = client
            .post(url)
            .header("Content-Type", "application/json")
            .basic_auth("prz", Some("prz"))
            .body(req)
            .send()
            .await
            .expect("failed to get response")
            .text()
            .await
            .expect("failed to get payload");
        response
    }

    #[tokio::test]
    pub async fn test_btcd_parse() {
        let req = r#"{"jsonrpc": "2.0", "id": "curltest", "method": "getsgxpubkey", "params": []}"#;
        let pubkey_resp = send_req(req.to_string()).await;
        let (pk, _) = sgx_result_parse(pubkey_resp).unwrap();
        let pk_s: PubkeyResponse = serde_json::from_str(&pk).unwrap();

        let req = r#"{"jsonrpc": "2.0", "id": "curltest", "method": "generate", "params": [10]}"#;
        let resp = send_req(req.to_string()).await;
        let verification_result = verify_sgx_response(resp.to_string(), pk_s.pubkey).unwrap();
        assert_eq!(verification_result, true);
        let (_data, _) = sgx_result_parse(resp).unwrap();
    }

    #[tokio::test]
    pub async fn test_btcd_batch_parse_1() {
        let req = r#"{"jsonrpc": "2.0", "id": "curltest", "method": "getsgxpubkey", "params": []}"#;
        let pubkey_resp = send_req(req.to_string()).await;
        let _pk = verify_sgx_response_and_restore_origin_response_v2(
            pubkey_resp.clone(),
            "no".to_string(),
        )
        .unwrap();

        let req = r#"[{"jsonrpc": "2.0", "id": "curltest", "method": "generate", "params": [1]}
        ,{"jsonrpc": "2.0", "id": "curltest", "method": "generate", "params": [2]},
        {"jsonrpc": "2.0", "id": "curltest", "method": "generate", "params": [3]}]"#;
        let resp = send_req(req.to_string()).await;
        println!("batch {}", resp);
        let _verification_result =
            verify_sgx_response_and_restore_origin_response_v2(resp.to_string(), "no".to_string())
                .unwrap();
    }

    #[tokio::test]
    pub async fn test_btcd_batch_parse_2() {
        let resp = r#"{"resp":
        [{"jsonrpc":"2.0","result":["4055eeb616218a362240a23d2c905365f033455bfe3ee4d4b4ce80dd914bd3bc"],"error":null,"id":"curltest"},
        {"jsonrpc":"2.0","result":["619232c87a41f35d0eaec638350d3cb7806b99107752b24ce496f9ca866c01bf","6a3b1eb4e570e1d3186bb59075ff5ba65fa30be9cafd386296a2e8a2977b8148"],"error":null,"id":"curltest"},
        {"jsonrpc":"2.0","result":["03f733a7ccdca34794f1f8988c0f236656e7c20572562604522b764b772b521b","4b4c1c5d82b002c13235a06a3f35b6141dd44c00ecd9b6e6d9d16de52d49770f","608d28361e9ba960bad5060258c5221b4cf558ffaf76174afe0cd8c6d277246a"],"error":null,"id":"curltest"}],
        "sig":"55abcbd3e6583765065d351cde133d0f0a27de0384639888e1aaa130920fcd70b77b6531d32bf9813ecc6a90144b0c8edc553acdbfe2552c8f42ed3915a34605",
        "pubkey":"ce31e7216fbcf2ddb2e443d5fe2494d3bcd07abb19763b10906a9f1598492f93"}"#;

        let response =
            verify_sgx_response_and_restore_origin_response_v2(resp.to_string(), "".to_string())
                .unwrap();
        let expect_response = json!([{"error":null,"id":"curltest","jsonrpc":"2.0",
        "result":["4055eeb616218a362240a23d2c905365f033455bfe3ee4d4b4ce80dd914bd3bc"]},
        {"error":null,"id":"curltest","jsonrpc":"2.0",
        "result":["619232c87a41f35d0eaec638350d3cb7806b99107752b24ce496f9ca866c01bf",
        "6a3b1eb4e570e1d3186bb59075ff5ba65fa30be9cafd386296a2e8a2977b8148"]},
        {"error":null,"id":"curltest","jsonrpc":"2.0",
        "result":["03f733a7ccdca34794f1f8988c0f236656e7c20572562604522b764b772b521b",
        "4b4c1c5d82b002c13235a06a3f35b6141dd44c00ecd9b6e6d9d16de52d49770f",
        "608d28361e9ba960bad5060258c5221b4cf558ffaf76174afe0cd8c6d277246a"]}]);
        let expect_result_str = serde_json::to_string(&expect_response).unwrap();

        assert_eq!(response, expect_result_str);
    }
}
