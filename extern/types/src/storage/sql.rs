use crate::storage::*;
use std::env;

pub type SqlPool = sqlx::SqlitePool;
pub type PoolOptions = sqlx::sqlite::SqlitePoolOptions;

#[derive(Clone)]
pub struct SqlRepository {
    pool: SqlPool,
}

impl SqlRepository {
    pub async fn new(uri: Option<String>) -> anyhow::Result<Self> {
        let uri = uri.unwrap_or_else(|| {
            return env::var("DATABASE_URL").unwrap();
        });
        let pool = SqlPool::connect(uri.as_str()).await?;
        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl EventRepository for SqlRepository {
    async fn query_event(&self, hash: String, index: i64) -> anyhow::Result<Option<Event>> {
        let row = sqlx::query!(
            r"SELECT blockNumber, transactionIndex, logIndex, transactionHash, eventName, txFrom, txTo, txValue, txInput, rawData
                FROM events WHERE transactionHash = $1 and logIndex= $2
            ",
            hash,
            index
        )
            .fetch_optional(&self.pool)
            .await?
            .map(|v| Event {
                block_number: v.blockNumber as u64,
                transaction_index: v.transactionIndex as u64,
                log_index: v.logIndex as u64,
                transaction_hash: v.transactionHash,
                event_name: v.eventName,
                from: v.txFrom,
                to: v.txTo,
                value: v.txValue,
                input: v.txInput,
                raw_data: v.rawData,
            });

        Ok(row)
    }
    async fn insert_event(&self, tx: Event) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO events (blockNumber, transactionIndex, logIndex, transactionHash, eventName, txFrom, txTo, txValue, txInput, rawData)
                VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 )
                RETURNING transactionHash
            "#,
        )
            .bind(tx.block_number as i64)
            .bind(tx.transaction_index as i64)
            .bind(tx.log_index as i64)
            .bind(tx.transaction_hash)
            .bind(tx.event_name)
            .bind(tx.from)
            .bind(tx.to)
            .bind(tx.value)
            .bind(tx.input)
            .bind(tx.raw_data)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn delete_event(&self, hash: String, index: i64) -> anyhow::Result<bool> {
        sqlx::query!(
            r#" DELETE FROM events WHERE transactionHash = $1 and logIndex = $2"#,
            hash,
            index
        )
        .execute(&self.pool)
        .await?;
        Ok(true)
    }
}

#[async_trait::async_trait]
impl StatusRepository for SqlRepository {
    async fn query_status(&self, name: &str, chain_id: i64) -> anyhow::Result<Option<Status>> {
        let row = sqlx::query_as!(
            Status,
            r#" SELECT addr, backend, named, tag, chain_id, latest, disused FROM stats WHERE addr = $1 and chain_id = $2"#,
            name,
            chain_id
        )
            .fetch_optional(&self.pool)
            .await?;

        Ok(row)
    }
    async fn insert_status(&self, st: Status) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO stats (addr, backend, named, tag, chain_id, latest, disused)
                VALUES ( $1, $2, $3, $4, $5, $6, $7)
                RETURNING addr
            "#,
        )
        .bind(st.addr)
        .bind(st.backend)
        .bind(st.named)
        .bind(st.tag)
        .bind(st.chain_id)
        .bind(st.latest)
        .bind(st.disused)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    async fn delete_status(&self, addr: &str) -> anyhow::Result<bool> {
        sqlx::query!(r#"DELETE FROM stats WHERE addr = $1"#, addr)
            .execute(&self.pool)
            .await?;
        Ok(true)
    }
    async fn update_status(&self, st: Status) -> anyhow::Result<bool> {
        sqlx::query!(
            r#"UPDATE stats SET latest=$1, tag=$2 WHERE addr = $3 and chain_id = $4"#,
            st.latest,
            st.tag,
            st.addr,
            st.chain_id
        )
        .execute(&self.pool)
        .await?;
        Ok(true)
    }
    async fn all_status(&self) -> anyhow::Result<Vec<Status>> {
        let row = sqlx::query_as!(Status, r#"SELECT * FROM stats"#,)
            .fetch_all(&self.pool)
            .await?;
        Ok(row)
    }
}

#[async_trait::async_trait]
impl CacheRepository for SqlRepository {
    async fn query_all(&self) -> anyhow::Result<Vec<CacheWatched>> {
        let row = sqlx::query_as!(CacheWatched, r#"SELECT * FROM cache"#)
            .fetch_all(&self.pool)
            .await?;
        Ok(row)
    }
    async fn batch_insert(&self, data: Vec<CacheWatched>) -> anyhow::Result<()> {
        for d in data {
            sqlx::query(
                r#"INSERT INTO cache (tstamp, src_chain_id, dst_chain_id, src_hash, event_name, event_address, event_uid, payload)
                    VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )
                    RETURNING event_uid
                "#,
            )
                .bind(d.tstamp)
                .bind(d.src_chain_id)
                .bind(d.dst_chain_id)
                .bind(d.src_hash)
                .bind(d.event_name)
                .bind(d.event_address)
                .bind(d.event_uid)
                .bind(d.payload)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Repository for SqlRepository {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokio;

    #[tokio::test]
    async fn sql_db_confirm_schema() {
        dotenv::dotenv().ok();
        let repository = SqlRepository::new(None).await.unwrap();
        sqlx::migrate!("./migrations")
            .run(&repository.pool)
            .await
            .unwrap();

        // transaction
        let tx = Event {
            block_number: 3,
            transaction_index: 1,
            log_index: 2,
            transaction_hash: "0xe06034dafb8cc139d927bde7565d93c4ad36de84e12c2154d8de9c034d3cf3d5"
                .to_string(),
            from: "0x32b56fc48684fa085df8c4cd2feaafc25c304db9".to_string(),
            to: "0xffa397285ce46fb78c588a9e993286aac68c37cd".to_string(),
            value: "0x00000000000000000000000004250450ee0f8f776859ac4602d3a4630557acb4".to_string(),
            input: vec![2u8],
            event_name: "Transfer".to_string(),
            raw_data: vec![1u8, 2u8, 3, 4],
        };
        repository.insert_event(tx.clone()).await.unwrap();
        let db_tx = repository
            .query_event(tx.transaction_hash.clone(), tx.log_index as i64)
            .await
            .unwrap();
        assert_eq!(db_tx.unwrap(), tx);
        repository
            .delete_event(tx.transaction_hash.clone(), tx.log_index as i64)
            .await
            .unwrap();
        let no_tx = repository
            .query_event(tx.transaction_hash.clone(), tx.log_index as i64)
            .await
            .unwrap();
        assert!(no_tx.is_none());

        // status
        let mut st = Status::default();
        st.chain_id = 1;
        st.addr = "0xffa397285ce46fb78c588a9e993286aac68c37cd".to_string();
        repository.insert_status(st.clone()).await.unwrap();
        let db_st = repository.query_status(&st.addr, 1).await.unwrap();
        assert_eq!(db_st.unwrap(), st);

        st.latest = 100;
        repository.update_status(st.clone()).await.unwrap();
        let db_st = repository.query_status(&st.addr, 1).await.unwrap();
        assert_eq!(db_st.unwrap(), st);

        repository.delete_status(&st.addr).await.unwrap();
        let no_st = repository.query_status(&st.addr, 1).await.unwrap();
        assert!(no_st.is_none());
    }
}
