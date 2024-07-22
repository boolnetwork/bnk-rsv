use crate::{
    sign_with_device_sgx_key, sign_with_device_sgx_key_test, verify_sig_from_string_public, KeyType,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseSgx<T: Serialize> {
    pub result: T,
    pub sig: String,
}

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

#[cfg(test)]
mod test {
    use crate::ONLINESK;
    use crate::*;
    use resp_verify::{create_sgx_response, verify_sgx_response};
    use serde_json::json;

    fn reg_mock() {
        let secret_key = Secret::from_bytes(&[8u8; 32]).unwrap();
        *ONLINESK.write().unwrap() = Some(secret_key);
    }

    fn public_key() -> String {
        get_public(KeyType::SGX)
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

        let verify_result = verify_sgx_response(sgx_result, public_key()).unwrap();
        assert_eq!(verify_result, true);
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

        let verify_result = verify_sgx_response(sgx_result, public_key()).unwrap();
        assert_eq!(verify_result, true);
    }
}
