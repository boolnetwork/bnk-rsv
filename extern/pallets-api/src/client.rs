use anyhow::Result;
use node_primitives::AccountId20;
use sp_core::H256 as Hash;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use subxt::config::{
    polkadot::PolkadotExtrinsicParams,
    substrate::{BlakeTwo256, SubstrateHeader},
};
use subxt::{
    OnlineClient, Config, tx::{TxPayload, SecretKey, BoolSigner}, JsonRpseeError,
    Error, error::RpcError, storage::{address::Yes, StorageAddress},
};
use subxt::tx::Signer;

#[derive(Clone, Debug)]
pub enum BoolConfig {}

impl Config for BoolConfig {
    type Index = u32;
    type Hash = Hash;
    type AccountId = node_primitives::AccountId20;
    type Address = sp_runtime::MultiAddress<node_primitives::AccountId20, ()>;
    type Signature = node_primitives::BnkSignature;
    type Hasher = BlakeTwo256;
    type Header = SubstrateHeader<u32, BlakeTwo256>;
    type ExtrinsicParams = PolkadotExtrinsicParams<Self>;
}

#[derive(Clone)]
pub struct SubClient<C: Config, P: Signer<C> + Clone> {
    pub ws_url: String,
    pub signer: Option<P>,
    pub client: Arc<RwLock<OnlineClient<C>>>,
    pub inner_nonce: Arc<RwLock<u32>>,
    // milliseconds, default 10000 milllis(10 seconds)
    pub warn_time: u128,
}

impl SubClient<BoolConfig, BoolSigner<BoolConfig>> {
    pub async fn new(url: &str, id: &str, password_override: Option<String>, warn_time: Option<u128>) -> SubClient<BoolConfig, BoolSigner<BoolConfig>> {
        let password_override = password_override.unwrap_or("".to_string());
        let phase = id.to_owned() + &password_override;
        let seed = sp_core::keccak_256(phase.as_bytes());
        let signer = BoolSigner::new(SecretKey::parse(&seed).expect("phase sk from seed should successfully"));
        let subxt_client = OnlineClient::<BoolConfig>::from_url(url).await.unwrap();
        let chain_nonce = subxt_client.tx().account_nonce(signer.account_id()).await.unwrap();
        SubClient {
            ws_url: url.to_string(),
            signer: Some(signer),
            client: Arc::new(RwLock::new(subxt_client)),
            inner_nonce: Arc::new(RwLock::new(chain_nonce)),
            warn_time: warn_time.unwrap_or(10000),
        }
    }

    pub async fn new_from_ecdsa_sk(url: String, sk: Option<String>, warn_time: Option<u128>) -> Result<SubClient<BoolConfig, BoolSigner<BoolConfig>>, String> {
        let mut chain_nonce = 0;
        let subxt_client = OnlineClient::<BoolConfig>::from_url(&url).await.map_err(|e| e.to_string())?;
        let signer = if let Some(sk) = sk {
            let sk = hex::decode(sk.strip_prefix("0x").unwrap_or(&sk)).map_err(|e| e.to_string())?;
            let signer = BoolSigner::new(SecretKey::parse_slice(&sk).map_err(|e| e.to_string())?);
            chain_nonce = subxt_client.tx().account_nonce(signer.account_id()).await.unwrap();
            Some(signer)
        } else {
            None
        };
        Ok(SubClient {
            ws_url: url,
            signer,
            client: Arc::new(RwLock::new(subxt_client)),
            inner_nonce: Arc::new(RwLock::new(chain_nonce)),
            warn_time: warn_time.unwrap_or(10000),
        })
    }

    pub async fn submit_extrinsic_with_signer_and_watch<
        Call: TxPayload,
    >(
        &self,
        call: Call,
        nonce: Option<u32>,
    ) -> Result<Hash, Error> {
        let timer =   Instant::now();
        self.check_client_runtime_version_and_update().await?;

        let mut inner_nonce = self.inner_nonce.write().await;
        let client = self.client.read().await;
        let signer = self.signer.as_ref().ok_or_else(|| Error::Other("empty sk to sign and submit tx".to_string()))?;
        let account_id = signer.account_id();

        let target_nonce = if let Some(nonce) = nonce {
            nonce
        } else {
            let chain_nonce = client.tx().account_nonce(account_id).await?;
            if chain_nonce >= *inner_nonce {
                chain_nonce
            } else {
                // Some errors occurred
                if *inner_nonce - chain_nonce > 10 {
                    log::warn!(target: "subxt", "Some errors occurred to nonce inner {}, chain {}", *inner_nonce, chain_nonce);
                    chain_nonce
                } else {
                    *inner_nonce
                }
            }
        };
        let tx: subxt::tx::SubmittableExtrinsic<BoolConfig, OnlineClient<BoolConfig>> = client.tx().create_signed_with_nonce(&call, signer, target_nonce, Default::default())?;
        let tx_hash = match tx
            .submit_and_watch()
            .await?
            .wait_for_in_block()
            .await
        {
            Ok(tx) => {
                log::debug!(target: "subxt::nonce", "inner_nonce {}", target_nonce + 1);
                *inner_nonce = target_nonce + 1;
                tx.wait_for_success().await?.extrinsic_hash()
            },
            Err(e) => return Err(e)
        };
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "submit_extrinsic_with_signer_and_watch exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        Ok(tx_hash)
    }

    pub async fn submit_extrinsic_with_signer_without_watch<
        Call: TxPayload,
    >(
        &self,
        call: Call,
        nonce: Option<u32>,
    ) -> Result<Hash, Error> {
        let timer =   Instant::now();
        self.check_client_runtime_version_and_update().await?;

        let mut inner_nonce = self.inner_nonce.write().await;
        let client = self.client.read().await;
        let signer = self.signer.as_ref().ok_or_else(|| Error::Other("empty sk to sign and submit tx".to_string()))?;
        let account_id = signer.account_id();

        let target_nonce = if let Some(nonce) = nonce {
            nonce
        } else {
            let chain_nonce = client.tx().account_nonce(account_id).await?;
            if chain_nonce >= *inner_nonce {
                chain_nonce
            } else {
                // Some errors occurred
                if *inner_nonce - chain_nonce > 10 {
                    log::warn!(target: "subxt", "Some errors occurred to nonce inner {}, chain {}", *inner_nonce, chain_nonce);
                    chain_nonce
                } else {
                    *inner_nonce
                }
            }
        };
        let tx = client.tx().create_signed_with_nonce(&call, signer, target_nonce, Default::default())?;
        let tx_hash = match tx
            .submit()
            .await
        {
            Ok(tx) => {
                log::debug!(target: "subxt::nonce", "inner_nonce {}", target_nonce + 1);
                *inner_nonce = target_nonce + 1;
                tx
            },
            Err(e) => return Err(e)
        };
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "submit_extrinsic_with_signer_and_watch exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        Ok(tx_hash)
    }

    pub async fn submit_extrinsic_without_signer<Call: TxPayload>(
        &self,
        call: Call,
    ) -> Result<Hash, Error> {
        let timer =   Instant::now();
        let client = self.client.read().await;
        let tx = client.tx().create_unsigned(&call)?;
        let tx_hash = tx.submit().await?;
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "submit_extrinsic_without_signer exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        Ok(tx_hash)
    }

    pub async fn query_storage<F: StorageAddress<IsFetchable = Yes>>(
        &self,
        store_query: F,
        at_block: Option<Hash>,
    ) -> Result<Option<F::Target>, Error> {
        let timer =   Instant::now();
        self.check_client_runtime_version_and_update().await?;
        let storage_client = self.client.read().await.storage();
        let res = match at_block {
            Some(block) => {
                storage_client.at(block).fetch(&store_query).await
            },
            None => {
                storage_client.at_latest().await?.fetch(&store_query).await
            }
        };
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "query_storage exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        res
    }

    pub async fn query_storage_value_iter<F: StorageAddress<IsIterable = Yes> + 'static>(
        &self,
        store_query: F,
        page_sise: u32,
        at_block: Option<Hash>,
    ) -> Result<Vec<F::Target>, Error> {
        let timer = Instant::now();
        self.check_client_runtime_version_and_update().await?;
        let storage_client = self.client.read().await.storage();
        let mut iter = match at_block {
            Some(block) => {
                storage_client.at(block).iter(store_query, page_sise).await?
            },
            None => {
                storage_client.at_latest().await?.iter(store_query, page_sise).await?
            }
        };
        let mut values = Vec::new();
        while let Some((_key, value)) = iter.next().await? {
            values.push(value)
        }
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "query_storage exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        Ok(values)
    }

    pub async fn query_storage_or_default<F: StorageAddress<IsFetchable = Yes, IsDefaultable = Yes>>(
        &self,
        store_query: F,
        at_block: Option<Hash>,
    ) -> Result<F::Target, Error> {
        let timer =   Instant::now();
        self.check_client_runtime_version_and_update().await?;
        let storage_client = self.client.read().await.storage();
        let res = match at_block {
            Some(block) => {
                storage_client.at(block).fetch_or_default(&store_query).await
            },
            None => {
                storage_client.at_latest().await?.fetch_or_default(&store_query).await
            }
        };
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "query_storage_or_default exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        res
    }

    pub async fn query_constant<Address: subxt::constants::ConstantAddress>(
        &self,
        address: Address,
    ) -> Result<Address::Target, Error> {
        let timer =   Instant::now();
        self.check_client_runtime_version_and_update().await?;
        let client = self.client.read().await.constants();
        let res = client.at(&address);
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "query_constant exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        res
    }

    pub async fn query_account_nonce(&self) -> Option<u32> {
        let timer =   Instant::now();
        self.check_client_runtime_version_and_update().await.ok()?;
        let res = match self.client.read().await.tx().account_nonce(&self.account_id().await).await {
            Ok(nonce) => Some(nonce),
            Err(_) => None,
        };
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "query_account_nonce exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        res
    }

    pub async fn account_id(&self) -> AccountId20 {
        let timer =   Instant::now();
        let res = self.signer.as_ref()
            .expect("Bool subclient should has account")
            .account_id()
            .clone();
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "account_id exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        res
    }
}

impl<C: Config, P: Signer<C> + Clone> SubClient<C, P> {
    pub async fn new_from_signer(url: &str, signer: Option<P>, warn_time: Option<u128>) -> Result<SubClient<C, P>, Error> {
        let ws_url: url::Url = url.parse().map_err(|_| Error::Other("parse url from string failed".to_string()))?;
        let mut fixed_ws_url = ws_url.as_str().to_string();
        if ws_url.port().is_none() {
            let mut tmp = vec![fixed_ws_url.strip_suffix(ws_url.path()).unwrap_or(&fixed_ws_url)];
            let default_port = format!(":{}", default_port(ws_url.scheme()).unwrap());
            tmp.push(&default_port);
            tmp.push(ws_url.path());
            fixed_ws_url = tmp.concat();
        }
        let subxt_client = OnlineClient::<C>::from_url(fixed_ws_url.clone()).await?;
        Ok(
            SubClient {
                ws_url: fixed_ws_url,
                signer,
                client: Arc::new(RwLock::new(subxt_client)),
                inner_nonce: Arc::new(RwLock::new(0)),
                warn_time: warn_time.unwrap_or(10000),
            }
        )
    }

    pub async fn check_client_runtime_version_and_update(&self) -> Result<(), Error> {
        let timer =   Instant::now();
        let client = self.client.read().await;
        let res = match client.rpc().runtime_version(None).await {
            Ok(runtime_version) => if runtime_version != client.runtime_version() {
                log::warn!(target: "subxt", "invalid runtime version, try to rebuild client...");
                drop(client);
                self.rebuild_client().await
            } else {
                Ok(())
            },
            Err(e) => {
                log::warn!(target: "subxt", "rebuild client for: {:?}", e);
                drop(client);
                self.handle_error(e).await
            },
        };
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "check_client_runtime_version_and_update exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        res
    }

    pub async fn rebuild_client(&self) -> Result<(), Error> {
        let timer =   Instant::now();
        let res = match OnlineClient::<C>::from_url(&self.ws_url).await {
            Ok(client) => {
                *self.client.write().await = client;
                log::info!(target: "subxt", "rebuild client successful");
                Ok(())
            }
            Err(e) => Err(e)
        };
        if timer.elapsed().as_millis() > self.warn_time {
            log::warn!(target: "subxt", "rebuild_client exceed warn_time: {} millis", timer.elapsed().as_millis());
        }
        res
    }

    pub async fn handle_error(&self, err: Error) -> Result<(), Error> {
        return match err {
            Error::Rpc(RpcError::SubscriptionDropped) => {
                log::warn!(target: "subxt", "rebuild client for SubscriptionDropped");
                self.rebuild_client().await
            },
            Error::Rpc(RpcError::ClientError(client_err)) => {
                match client_err.downcast_ref::<JsonRpseeError>() {
                    Some(e) => {
                        match *e {
                            JsonRpseeError::RestartNeeded(_) => {
                                log::warn!(target: "subxt", "rebuild client for {:?}", e);
                                self.rebuild_client().await
                            },
                            _ => Err(Error::Rpc(RpcError::ClientError(client_err))),
                        }
                    },
                    // Not handle other error type now
                    None => Err(Error::Rpc(RpcError::ClientError(client_err))),
                }
            },
            _ => Err(err),
        }
    }
}

pub fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        _ => None,
    }
}

#[tokio::test]
async fn test_rebuild_client() {
    let url = "ws://127.0.0.1:9944".to_string();
    let sk = "5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133".to_string();
    let client = SubClient::new_from_ecdsa_sk(url, Some(sk), None).await.unwrap();
    loop {
        println!("try to query challenges");
        let res = crate::query_mining::challenges(&client, 1, None).await;
        println!("query challenges result: {:?}", res);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}


#[tokio::test]
async fn test_query_iter() {
    let url = "wss://test-rpc-node-ws.bool.network".to_string();
    let client = crate::client::SubClient::new_from_signer(&url, None, None).await.unwrap();
    let res = crate::query_committee::committees_iter(&client, 300, None).await.unwrap();
    println!("res: {res:?}");
}

#[tokio::test]
async fn test_query_cmt() {
    let url = "wss://test-rpc-node-ws.bool.network".to_string();
    let client = crate::client::SubClient::new_from_signer(&url, None, None).await.unwrap();

    for i in 1u32..426 {
        let res = crate::query_committee::committees(&client, i, None).await.unwrap();
        println!("res: {res:?}");
    }
}

#[tokio::test]
async fn test_query_btc_committee_type_iter() {
    let url = "ws://127.0.0.1:9944".to_string();
    let client = crate::client::SubClient::new_from_signer(&url, None, None).await.unwrap();
    let res = crate::query_channel::btc_committee_type_iter(&client, 300, None).await.unwrap();
    println!("res: {res:?}");
}

