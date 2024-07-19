use serde::{Serialize, Deserialize};
use crate::{sign_with_device_sgx_key_test, sign_with_device_sgx_key, KeyType};
use serde_json::{Value, json};

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
        serde_json::to_string(&sig).unwrap()
    });

    result_parse(origin_resp_str, sign_fn, keytype)
}

pub fn result_parse(input: String, sign_fn: Box<dyn Fn(String, KeyType) -> String>, keytype: KeyType) -> String {
    let mut json_data: Value = serde_json::from_str(&input).unwrap();
    if let Some(result) = json_data.get_mut("result") {
        let msg = serde_json::to_string(&result.clone()).unwrap();

        let sig: String = sign_fn(msg, keytype);
        
        let sgx_result = json!({"result": result, "sig": sig});

        *result =  sgx_result;

    }

    serde_json::to_string(&json_data).unwrap()
}

#[cfg(test)]
mod test {
    use crate::*;
    use resp_verify::create_sgx_response;
    use serde::{Serialize, Deserialize};
    use serde_json::json;
    use crate::ONLINESK;

    #[derive(Serialize, Deserialize)]
    struct Example<T: Serialize>{
        jsonrpc: String,
        result: T,
        id: String,
    }

    fn reg_mock() {
        let secret_key = Secret::from_bytes(&[8u8; 32]).unwrap();
        *ONLINESK.write().unwrap() = Some(secret_key);
    }

    #[test]
    fn test_parse() {
        let block = json!({"blocknum":"888", "hash":"0x1234", "root":"0x5678"});
        let test_data = json!({"jsonrpc":"1.0", "result":block, "id":"curltest"});
        
        reg_mock();
        
        let res =  create_sgx_response(test_data, KeyType::SGX);
        
        let expect_result = json!({
            "id": "curltest",
            "jsonrpc": "1.0",
            "result": json!({
                "result": block,
                "sig": "[49,57,144,227,192,70,251,39,115,231,125,181,105,86,110,169,248,156,133,174,9,222,52,6,193,123,129,232,252,60,144,226,234,124,125,154,206,192,38,235,174,124,31,211,186,139,78,72,63,203,67,167,234,180,250,240,70,229,97,155,124,5,2,1]"
            })
        });
        
        let expect_result_str = serde_json::to_string(&expect_result).unwrap();
        assert_eq!(expect_result_str,res);
    }
}