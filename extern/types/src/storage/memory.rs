use crate::storage::*;
use lru::{DefaultHasher, LruCache};
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone)]
pub struct LruMemory {
    pub txs: Arc<RwLock<LruCache<(String, i64), Event>>>,
    pub sts: Arc<RwLock<LruCache<String, Status>>>,
    pub cws: Arc<RwLock<LruCache<String, CacheWatched>>>,
}

#[async_trait::async_trait]
impl EventRepository for LruMemory {
    async fn query_event(&self, hash: String, index: i64) -> anyhow::Result<Option<Event>> {
        let mut rep = self.txs.write();
        Ok(rep.get(&(hash, index)).map(|v| v.to_owned()))
    }
    async fn insert_event(&self, tx: Event) -> anyhow::Result<()> {
        self.txs
            .write()
            .put((tx.transaction_hash.clone(), tx.log_index as i64), tx);
        Ok(())
    }
    async fn delete_event(&self, hash: String, index: i64) -> anyhow::Result<bool> {
        Ok(self.txs.write().pop(&(hash, index)).is_some())
    }
}

#[async_trait::async_trait]
impl StatusRepository for LruMemory {
    async fn query_status(&self, name: &str, _chain_id: i64) -> anyhow::Result<Option<Status>> {
        Ok(self.sts.write().get(name).map(|v| v.to_owned()))
    }
    async fn insert_status(&self, st: Status) -> anyhow::Result<()> {
        self.sts.write().put(st.addr.clone(), st);
        Ok(())
    }
    async fn delete_status(&self, name: &str) -> anyhow::Result<bool> {
        Ok(self.sts.write().pop(name).is_some())
    }
    async fn update_status(&self, st: Status) -> anyhow::Result<bool> {
        Ok(self.sts.write().put(st.addr.clone(), st).is_some())
    }
    async fn all_status(&self) -> anyhow::Result<Vec<Status>> {
        Ok(self.sts.write().iter().map(|(_k, v)| v.clone()).collect())
    }
}

#[async_trait::async_trait]
impl CacheRepository for LruMemory {
    async fn query_all(&self) -> anyhow::Result<Vec<CacheWatched>> {
        Ok(self.cws.write().iter().map(|(_k, v)| v.clone()).collect())
    }
    async fn batch_insert(&self, data: Vec<CacheWatched>) -> anyhow::Result<()> {
        let mut db = self.cws.write();
        for d in data {
            db.put(d.event_uid.clone(), d.clone());
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Repository for LruMemory {}

impl LruMemory {
    #[allow(dead_code)]
    pub fn new(size: usize) -> Self {
        LruMemory {
            txs: Arc::new(RwLock::new(LruCache::with_hasher(
                size,
                DefaultHasher::default(),
            ))),
            sts: Arc::new(RwLock::new(LruCache::with_hasher(
                size,
                DefaultHasher::default(),
            ))),
            cws: Arc::new(RwLock::new(LruCache::with_hasher(
                size,
                DefaultHasher::default(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_db_test() {
        let memdb = LruMemory::new(100);
        let mut tx = Event::default();
        tx.transaction_hash = "1234".to_string();
        tx.log_index = 1;

        memdb.insert_event(tx).await.unwrap();
    }
}
