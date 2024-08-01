use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ExecutorMode {
    BothLD,
    Listener,
    Deliverer,
    Aider,
}

impl Default for ExecutorMode {
    fn default() -> Self {
        ExecutorMode::BothLD
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[repr(C)]
pub struct Config {
    /// The port of server
    pub port: u16,
    /// Custom database links
    pub database_url: Option<String>,
    /// Used to notify URL of third party.eg. http://localhost:8080/event
    pub notified_url: Option<String>,
    pub bool_config: Option<BoolConfig>,
    /// Known backend of the chain for use by source.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub endpoints: Vec<ChainEndpoint>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub btc_endpoints: Vec<BtcChainEndpoint>,
    /// The factory contract source to watch
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub sources: Vec<Source>,
    /// Default Watcher configuration
    pub default_watcher: WatcherConfig,
    /// This field determines how to obtain the data source, defaults to config,
    /// if true, from the database and config, config is preferred.
    pub merge: Option<bool>,
    pub mode: Option<ExecutorMode>,
    /// Delay time submitted to bool, default is 1000 millisecond.
    pub event_delay_time: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BoolConfig {
    /// Used to call bool node.
    pub bool_node_url: String,
    /// Hex encoded secret key for Bool account.
    pub bool_identity: Option<String>,
    /// Bool client warn time limit(milliseconds)
    pub warn_time: Option<u128>,
    /// If this is Some, previous identity is encrypted by this password.
    pub password: Option<String>,
    /// EventWatcher config for max delay from Finalized block to Latest block
    pub finalize_delay: Option<u32>,
    /// Mode to submit new transaction to bool
    pub submit_by_evm: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[repr(C)]
pub struct ChainEndpoint {
    pub chain_id: u32,
    pub name: String,
    pub http_url: Option<String>,
    pub ws_url: Option<String>,
    pub private_key: Option<String>,
    pub token: Option<String>,
    pub password: Option<String>,
    pub capacity: Option<u32>,
    /// Base gas, used to solve chains with inaccurate estimate_gas(). The default value is 0.
    /// The final gas is estimate_gas() + base_gas
    pub base_gas: Option<u64>,
    /// Used to limit the sudden increase in transaction fees. If the gas fee exceeds the preset value, 
    /// the transaction will not be sent and will enter the retry state.
    pub max_fee: Option<u64>,
    /// the timeout of deliver. default is 10 minutes
    pub deliver_timeout: Option<u64>,
}

impl fmt::Display for ChainEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChainEndpoint {{ chain_id: {}, name: {}, http_url: {:?}, ws_url: {:?}, private_key: {:?}, token: {:?}, password: {:?}, capacity: {:?}, base_gas: {:?} }}",
            self.chain_id,
            self.name,
            self.http_url,
            self.ws_url,
            hide_sensitive(&self.private_key),
            self.token,
            hide_sensitive(&self.password),
            self.capacity,
            self.base_gas
        )
    }
}

// Helper function to hide sensitive information
fn hide_sensitive(sensitive: &Option<String>) -> String {
    sensitive
        .as_ref()
        .map(|s| {
            if s.len() < 4 {
                "*".repeat(s.len())
            } else {
                format!("{}***{}", &s[..2], &s[s.len() - 2..])
            }
        })
        .unwrap_or_else(|| String::new())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[repr(C)]
pub struct BtcChainEndpoint {
    pub chain_id: u32,
    pub name: String,
    pub mode: NodeType,
    /// the timeout of deliver. default is 5 minutes
    pub deliver_timeout: Option<u64>,
    pub electrs_type: Option<ElectrsType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum NodeType {
    Spv {
        spv_http_url: String,
        spv_rpc_port: u32,
        spv_wallet_port: u32,
    },
    Other {
        electrs_url: String,
        inscription_url: Option<String>,
        api_key: Option<String>,
        rune_url: Option<String>,
        fee_mode: Option<FeeMode>,
        fee_multiplier: Option<f64>,
        fee_rate_limit: Option<f64>,
        raw_btc_filter_unconfirmed: Option<bool>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[repr(C)]
pub enum ElectrsType {
    Normal,
    Mempool,
}

impl Default for ElectrsType {
    fn default() -> Self {
        Self::Mempool
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[repr(C)]
pub enum FeeMode {
    #[default]
    Fast,
    Avg,
    Slow,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[repr(C)]
pub struct Source {
    // used as name
    pub named: String,
    // the tag of source
    pub tag: String,
    // The kind of the source.
    pub kind: Kind,
    // The backend name
    pub backend: String,
    // The address that we should watch
    pub address: String,
    // the watcher config
    pub watcher: WatcherConfig,
}

impl Source {
    pub fn key(&self) -> String {
        match self.kind {
            Kind::Full => format!("{}", self.backend),
            _ => format!("{}{}", self.backend, self.address),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[repr(C)]
pub enum Kind {
    // a normal address of chain, eg. btc address, eth address
    #[default]
    Native,
    // a contract address of chain, eg. the eth contract
    Contract,
    // only run a single instance
    Full,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[repr(C)]
pub struct WatcherConfig {
    /// if it is enabled for this chain or not.
    pub enabled: bool,
    /// Polling interval in milliseconds
    pub polling_interval: u64,
    /// The maximum number of events to fetch in one request.
    pub max_step: u64,
    /// The begin height to fetch logs
    pub begin_height: u64,
    /// the delayed blocks to query
    pub delayed_blocks: Option<u64>,
    /// The height end to watch
    pub to_height: Option<u64>,
    /// control to send dst tx
    pub enable_send_tx: Option<bool>,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            polling_interval: 30000,
            max_step: 2000,
            begin_height: 0,
            delayed_blocks: None,
            to_height: None,
            enable_send_tx: None,
        }
    }
}

pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config = toml::from_str::<Config>(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_serde_test() {
        let ep1 = ChainEndpoint {
            chain_id: 1,
            name: "Ethereum".to_string(),
            http_url: Some("http://localhost:8545".to_string()),
            ws_url: None,
            private_key: None,
            token: None,
            password: None,
            capacity: None,
            ..Default::default()
        };
        let ep2 = ChainEndpoint {
            chain_id: 2,
            name: "Kovan".to_string(),
            http_url: Some("http://localhost:8545".to_string()),
            ws_url: Some("ws://localhost:9944".to_string()),
            private_key: None,
            token: None,
            password: None,
            capacity: None,
            ..Default::default()
        };
        let eps = vec![ep1, ep2];

        let sr1 = Source {
            named: "factory".to_string(),
            tag: "".to_string(),
            kind: Kind::Native,
            backend: "Ethereum".to_string(),
            address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
            watcher: Default::default(),
        };

        let sr2 = Source {
            named: "factory".to_string(),
            tag: "".to_string(),
            kind: Kind::Contract,
            backend: "Kovan".to_string(),
            address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
            watcher: Default::default(),
        };

        let srs = vec![];
        let mut config = Config {
            port: 8080,
            bool_config: None,
            database_url: None,
            endpoints: eps,
            btc_endpoints: Default::default(),
            sources: srs,
            notified_url: None,
            default_watcher: Default::default(),
            merge: Default::default(),
            mode: Default::default(),
            event_delay_time: Default::default(),
        };

        let toml = toml::to_string(&config).unwrap();
        println!("toml: {}", toml);

        config.sources = vec![sr1, sr2];
        let _toml = toml::to_string(&config).unwrap();
    }

    #[test]
    fn config_deserialize_test() {
        let str = r#"
        port = 8740
        database_url = "/bnk/data/sqlite.db"
        
        [[endpoints]]
        chain_id = 80001
        name = "mumbai"
        http_url = "http://localhost:8545"
        
        [[endpoints]]
        chain_id = 420
        name = "optimism"
        http_url = "http://localhost:8545"
        
        [[endpoints]]
        chain_id = 5
        name = "goerli"
        http_url = "http://localhost:8545"

        [default_watcher]
        enabled = true
        polling_interval = 30000
        max_step = 2000
        begin_height = 0
        "#;

        let config: Config = toml::from_str(str).unwrap();
        println!("toml: {:?}", config);
    }
}
