pub mod memory;
#[cfg(feature = "sqlite")]
pub mod sql;
pub mod store;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
    pub transaction_hash: String,
    pub event_name: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub input: Vec<u8>,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub chain_id: i64,
    // lowercase address
    pub addr: String,
    pub backend: String,
    pub named: String,
    pub tag: String,
    pub latest: i64,
    pub disused: bool,
}

impl Status {
    pub fn key(&self) -> String {
        match self.chain_id {
            // Bitcoin-Testnet || Solana-Testnet
            0x10340fc0 | 0x43997816 => format!("{}", self.backend),
            _ => format!("{}{}", self.backend, self.addr),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheWatched {
    pub tstamp: i64,
    pub src_chain_id: i64,
    pub dst_chain_id: i64,
    pub src_hash: String,
    pub event_name: String,
    pub event_address: String,
    pub event_uid: String,
    pub payload: String,
}

#[async_trait::async_trait]
pub trait EventRepository: Send + Sync {
    async fn query_event(&self, hash: String, index: i64) -> anyhow::Result<Option<Event>>;
    async fn insert_event(&self, tx: Event) -> anyhow::Result<()>;
    async fn delete_event(&self, hash: String, index: i64) -> anyhow::Result<bool>;
}

#[async_trait::async_trait]
pub trait StatusRepository: Send + Sync {
    async fn query_status(&self, name: &str, chain_id: i64) -> anyhow::Result<Option<Status>>;
    async fn insert_status(&self, st: Status) -> anyhow::Result<()>;
    async fn delete_status(&self, name: &str) -> anyhow::Result<bool>;
    async fn update_status(&self, st: Status) -> anyhow::Result<bool>;
    async fn all_status(&self) -> anyhow::Result<Vec<Status>>;
}

#[async_trait::async_trait]
pub trait CacheRepository: Send + Sync {
    async fn query_all(&self) -> anyhow::Result<Vec<CacheWatched>>;
    async fn batch_insert(&self, data: Vec<CacheWatched>) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
pub trait Repository: StatusRepository + EventRepository + CacheRepository {}

#[cfg(feature = "sqlite")]
pub async fn setup_sql_storage(config: crate::monitor_config::Config) -> anyhow::Result<()> {
    const DEFAULT_DATABASE_FILE: &str = "monitor.db";

    let database_url = config
        .database_url
        .unwrap_or_else(|| DEFAULT_DATABASE_FILE.to_string());

    // ensure env existed.
    let key = "DATABASE_URL";
    if std::env::var(key).is_err() {
        std::env::set_var(key, database_url.as_str());
    }

    // if no file, then create it.
    if std::fs::File::open(database_url.as_str()).is_err() {
        let path_vec = database_url.rsplit('/').collect::<Vec<&str>>();
        let mut file_name = "".to_string();
        if let Some(&name) = path_vec.first() {
            if name.ends_with(".db") {
                file_name = name.to_string();
            }
        };
        let path_prefix = database_url
            .strip_suffix(&file_name)
            .unwrap_or(&database_url);
        std::fs::create_dir_all(path_prefix)?;
        if !file_name.is_empty() {
            std::fs::File::create(database_url.as_str())?;
        }
        log::info!("create \"{}\" file. ", database_url.as_str());
    }

    let db = sql::PoolOptions::new()
        .max_connections(50)
        .connect(database_url.as_str())
        .await?;
    sqlx::migrate!().run(&db).await?;
    Ok(())
}
