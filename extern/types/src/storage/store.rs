use crate::storage::*;

#[derive(Clone)]
pub enum Store {
    LruMemory(memory::LruMemory),
    #[cfg(feature = "sqlite")]
    Sqlite(sql::SqlRepository),
}

#[async_trait::async_trait]
impl EventRepository for Store {
    async fn query_event(&self, hash: String, index: i64) -> anyhow::Result<Option<Event>> {
        match self {
            Store::LruMemory(store) => store.query_event(hash, index).await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.query_event(hash, index).await,
        }
    }

    async fn insert_event(&self, tx: Event) -> anyhow::Result<()> {
        match self {
            Store::LruMemory(store) => store.insert_event(tx).await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.insert_event(tx).await,
        }
    }

    async fn delete_event(&self, hash: String, index: i64) -> anyhow::Result<bool> {
        match self {
            Store::LruMemory(store) => store.delete_event(hash, index).await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.delete_event(hash, index).await,
        }
    }
}

#[async_trait::async_trait]
impl StatusRepository for Store {
    async fn query_status(&self, name: &str, chain_id: i64) -> anyhow::Result<Option<Status>> {
        match self {
            Store::LruMemory(store) => store.query_status(name, chain_id).await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.query_status(name, chain_id).await,
        }
    }

    async fn insert_status(&self, st: Status) -> anyhow::Result<()> {
        match self {
            Store::LruMemory(store) => store.insert_status(st).await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.insert_status(st).await,
        }
    }

    async fn delete_status(&self, name: &str) -> anyhow::Result<bool> {
        match self {
            Store::LruMemory(store) => store.delete_status(name).await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.delete_status(name).await,
        }
    }

    async fn update_status(&self, st: Status) -> anyhow::Result<bool> {
        match self {
            Store::LruMemory(store) => store.update_status(st).await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.update_status(st).await,
        }
    }

    async fn all_status(&self) -> anyhow::Result<Vec<Status>> {
        match self {
            Store::LruMemory(store) => store.all_status().await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.all_status().await,
        }
    }
}

#[async_trait::async_trait]
impl CacheRepository for Store {
    async fn query_all(&self) -> anyhow::Result<Vec<CacheWatched>> {
        match self {
            Store::LruMemory(store) => store.query_all().await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.query_all().await,
        }
    }

    async fn batch_insert(&self, data: Vec<CacheWatched>) -> anyhow::Result<()> {
        match self {
            Store::LruMemory(store) => store.batch_insert(data).await,
            #[cfg(feature = "sqlite")]
            Store::Sqlite(store) => store.batch_insert(data).await,
        }
    }
}

#[async_trait::async_trait]
impl Repository for Store {}

impl From<memory::LruMemory> for Store {
    fn from(value: memory::LruMemory) -> Self {
        Store::LruMemory(value)
    }
}

#[cfg(feature = "sqlite")]
impl From<sql::SqlRepository> for Store {
    fn from(value: sql::SqlRepository) -> Self {
        Store::Sqlite(value)
    }
}
