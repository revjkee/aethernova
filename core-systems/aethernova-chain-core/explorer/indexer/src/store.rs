// aethernova-chain-core/explorer/indexer/src/store.rs
//! Хранилище индекса блокчейна: интерфейс, InMemory-реализация и Postgres backend.
//! Особенности промышленного уровня:
//! - Идемпотентные upsert-операции по уникальным ключам.
//! - Транзакции с повтором при deadlock/serialization failure (экспоненциальный бэкофф).
//! - Чекпоинты индексации и безопасный откат при реоргах.
//! - Минимальные модели данных, достаточные для индексатора (блоки/транзакции/логи).
//! - Конкурентная безопасность (внутренние Mutex только в InMemory).
//!
//! Включите фичу `postgres` для бэкенда на SQLx/Postgres.
//!
//! Таблицы, на которые опирается реализация Postgres (DDL ориентировочный):
//! ```sql
//! CREATE TABLE IF NOT EXISTS blocks (
//!   number        BIGINT PRIMARY KEY,
//!   hash          TEXT    NOT NULL UNIQUE,
//!   parent_hash   TEXT    NOT NULL,
//!   timestamp_ms  BIGINT  NOT NULL,
//!   tx_count      INTEGER NOT NULL,
//!   canonical     BOOLEAN NOT NULL DEFAULT TRUE
//! );
//!
//! CREATE TABLE IF NOT EXISTS transactions (
//!   hash          TEXT PRIMARY KEY,
//!   block_number  BIGINT  NOT NULL REFERENCES blocks(number) ON DELETE CASCADE,
//!   tx_index      INTEGER NOT NULL,
//!   "from"        TEXT    NOT NULL,
//!   "to"          TEXT,
//!   value_wei     NUMERIC(78,0) NOT NULL,   -- до 2^256-1
//!   fee_wei       NUMERIC(78,0) NOT NULL,
//!   success       BOOLEAN NOT NULL,
//!   nonce         BIGINT  NOT NULL
//! );
//! CREATE INDEX IF NOT EXISTS txs_block_idx ON transactions(block_number, tx_index);
//!
//! CREATE TABLE IF NOT EXISTS logs (
//!   tx_hash    TEXT    NOT NULL REFERENCES transactions(hash) ON DELETE CASCADE,
//!   log_index  INTEGER NOT NULL,
//!   address    TEXT    NOT NULL,
//!   topics     JSONB   NOT NULL,
//!   data       BYTEA   NOT NULL,
//!   PRIMARY KEY (tx_hash, log_index)
//! );
//!
//! CREATE TABLE IF NOT EXISTS checkpoints (
//!   source_chain TEXT PRIMARY KEY,
//!   block_number BIGINT NOT NULL
//! );
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::sleep;

/* ==========================
   Типы доменной модели
   ========================== */

pub type BlockNumber = u64;

/// Минимальная модель блока.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub number: BlockNumber,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp_ms: i64,
    pub tx_count: u32,
}

/// Минимальная модель транзакции.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub hash: String,
    pub block_number: BlockNumber,
    pub tx_index: u32,
    pub from: String,
    pub to: Option<String>,
    /// Значение в минимальных единицах (например, wei) как десятичная строка.
    pub value_wei: String,
    /// Комиссия/стоимость газа как десятичная строка.
    pub fee_wei: String,
    pub success: bool,
    pub nonce: u64,
}

/// Лог события.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Log {
    pub tx_hash: String,
    pub log_index: u32,
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

/// Композит для атомарной фиксации канонического блока.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockBundle {
    pub block: Block,
    pub txs: Vec<Transaction>,
    pub logs: Vec<Log>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ChainRef(pub String);

/* ==========================
   Ошибки хранилища
   ========================== */

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("db: {0}")]
    Db(String),
    #[error("conflict")]
    Conflict,
    #[error("not found")]
    NotFound,
}

/* ==========================
   Абстрактный интерфейс Store
   ========================== */

#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Возвращает чекпоинт (последний канонический номер блока) для указанной цепи.
    async fn get_checkpoint(&self, chain: &ChainRef) -> Result<Option<BlockNumber>, StoreError>;

    /// Устанавливает чекпоинт (идемпотентно).
    async fn set_checkpoint(&self, chain: &ChainRef, number: BlockNumber) -> Result<(), StoreError>;

    /// Атомарно записывает канонический блок и связанные сущности.
    /// Обновляет существующие записи (upsert), чтобы операция была идемпотентной.
    async fn upsert_canonical_bundle(&self, bundle: &BlockBundle) -> Result<(), StoreError>;

    /// Возвращает максимальный номер канонического блока (если есть данные).
    async fn get_last_canonical_block(&self) -> Result<Option<BlockNumber>, StoreError>;

    /// Помечает все блоки и данные начиная с `from_number` как неканонические.
    /// В реализациях с БД допустимо удаление несовместимых частей (CASCADE).
    async fn revert_canonical_from(&self, from_number: BlockNumber) -> Result<(), StoreError>;

    /// Поиск транзакции по хэшу.
    async fn get_tx_by_hash(&self, hash: &str) -> Result<Option<Transaction>, StoreError>;
}

/* ==========================
   In-memory реализация
   ========================== */

#[derive(Default)]
pub struct MemoryStore {
    // Ключи: block_number -> Block
    blocks: Mutex<BTreeMap<BlockNumber, Block>>,
    // hash -> Transaction
    txs: Mutex<HashMap<String, Transaction>>,
    // (tx_hash, idx) -> Log
    logs: Mutex<HashMap<(String, u32), Log>>,
    // chain -> checkpoint
    checkpoints: Mutex<HashMap<ChainRef, BlockNumber>>,
}

#[async_trait]
impl Store for MemoryStore {
    async fn get_checkpoint(&self, chain: &ChainRef) -> Result<Option<BlockNumber>, StoreError> {
        Ok(self.checkpoints.lock().await.get(chain).copied())
    }

    async fn set_checkpoint(&self, chain: &ChainRef, number: BlockNumber) -> Result<(), StoreError> {
        self.checkpoints.lock().await.insert(chain.clone(), number);
        Ok(())
    }

    async fn upsert_canonical_bundle(&self, bundle: &BlockBundle) -> Result<(), StoreError> {
        // Запись блока
        self.blocks
            .lock()
            .await
            .insert(bundle.block.number, bundle.block.clone());
        // Транзакции
        {
            let mut txs = self.txs.lock().await;
            for t in &bundle.txs {
                txs.insert(t.hash.clone(), t.clone());
            }
        }
        // Логи
        {
            let mut logs = self.logs.lock().await;
            for l in &bundle.logs {
                logs.insert((l.tx_hash.clone(), l.log_index), l.clone());
            }
        }
        Ok(())
    }

    async fn get_last_canonical_block(&self) -> Result<Option<BlockNumber>, StoreError> {
        Ok(self.blocks.lock().await.keys().next_back().copied())
    }

    async fn revert_canonical_from(&self, from_number: BlockNumber) -> Result<(), StoreError> {
        // Удаляем блоки >= from_number, вместе с их tx и logs.
        let mut blocks = self.blocks.lock().await;
        let to_remove: Vec<_> = blocks
            .range(from_number..)
            .map(|(n, _)| *n)
            .collect();
        for n in to_remove {
            // собрать tx-хэши этого блока
            let tx_hashes: Vec<String> = {
                let txs = self.txs.lock().await;
                txs.values()
                    .filter(|t| t.block_number == n)
                    .map(|t| t.hash.clone())
                    .collect()
            };
            // удалить логи
            {
                let mut logs = self.logs.lock().await;
                logs.retain(|(h, _), _| !tx_hashes.contains(h));
            }
            // удалить tx
            {
                let mut txs = self.txs.lock().await;
                txs.retain(|_, t| t.block_number < n);
            }
            // удалить блок
            blocks.remove(&n);
        }
        Ok(())
    }

    async fn get_tx_by_hash(&self, hash: &str) -> Result<Option<Transaction>, StoreError> {
        Ok(self.txs.lock().await.get(hash).cloned())
    }
}

/* ==========================================
   Postgres реализация (feature = "postgres")
   ========================================== */

#[cfg(feature = "postgres")]
pub mod postgres {
    use super::*;
    use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};

    /// Обёртка Postgres-пула.
    #[derive(Clone)]
    pub struct PgStore {
        pool: PgPool,
        retry: TxRetry,
    }

    #[derive(Clone, Copy, Debug)]
    struct TxRetry {
        attempts: usize,
        base_delay: Duration,
        max_delay: Duration,
    }

    impl Default for TxRetry {
        fn default() -> Self {
            Self {
                attempts: 8,
                base_delay: Duration::from_millis(100),
                max_delay: Duration::from_millis(5_000),
            }
        }
    }

    impl PgStore {
        /// Подключение к БД с пулом соединений.
        pub async fn connect(dsn: &str, max_connections: u32) -> Result<Self> {
            let pool = PgPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(Duration::from_secs(10))
                .connect(dsn)
                .await
                .with_context(|| "connect postgres")?;
            Ok(Self { pool, retry: TxRetry::default() })
        }

        async fn with_tx<F, T>(&self, mut f: F) -> Result<T, StoreError>
        where
            F: FnMut(Transaction<'_, Postgres>) -> futures::future::BoxFuture<'_, Result<T, StoreError>>,
        {
            let mut attempt = 0usize;
            let mut delay = self.retry.base_delay;

            loop {
                let tx = self.pool.begin().await.map_err(|e| StoreError::Db(e.to_string()))?;

                match f(tx).await {
                    Ok(v) => return Ok(v),
                    Err(StoreError::Db(msg)) if is_retryable(&msg) && attempt + 1 < self.retry.attempts => {
                        attempt += 1;
                        let d = std::cmp::min(delay, self.retry.max_delay);
                        sleep(d).await;
                        delay = delay.saturating_mul(2);
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    fn is_retryable(msg: &str) -> bool {
        // SQLSTATE: 40001 serialization_failure; 40P01 deadlock_detected
        msg.contains("40001") || msg.contains("40P01")
    }

    #[async_trait]
    impl Store for PgStore {
        async fn get_checkpoint(&self, chain: &ChainRef) -> Result<Option<BlockNumber>, StoreError> {
            let rec = sqlx::query_scalar!(
                r#"SELECT block_number as "block_number!: i64" FROM checkpoints WHERE source_chain = $1"#,
                &chain.0
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Db(e.to_string()))?;
            Ok(rec.map(|v| v as u64))
        }

        async fn set_checkpoint(&self, chain: &ChainRef, number: BlockNumber) -> Result<(), StoreError> {
            sqlx::query!(
                r#"
                INSERT INTO checkpoints (source_chain, block_number)
                VALUES ($1, $2)
                ON CONFLICT (source_chain) DO UPDATE SET block_number = EXCLUDED.block_number
                "#,
                &chain.0,
                number as i64
            )
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Db(e.to_string()))?;
            Ok(())
        }

        async fn upsert_canonical_bundle(&self, bundle: &BlockBundle) -> Result<(), StoreError> {
            self.with_tx(|mut tx| {
                Box::pin(async move {
                    // Блок
                    sqlx::query!(
                        r#"
                        INSERT INTO blocks (number, hash, parent_hash, timestamp_ms, tx_count, canonical)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        ON CONFLICT (number)
                        DO UPDATE SET
                          hash = EXCLUDED.hash,
                          parent_hash = EXCLUDED.parent_hash,
                          timestamp_ms = EXCLUDED.timestamp_ms,
                          tx_count = EXCLUDED.tx_count,
                          canonical = TRUE
                        "#,
                        bundle.block.number as i64,
                        bundle.block.hash,
                        bundle.block.parent_hash,
                        bundle.block.timestamp_ms,
                        bundle.block.tx_count as i32
                    )
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| StoreError::Db(e.to_string()))?;

                    // Транзакции
                    for t in &bundle.txs {
                        sqlx::query!(
                            r#"
                            INSERT INTO transactions
                              (hash, block_number, tx_index, "from", "to", value_wei, fee_wei, success, nonce)
                            VALUES
                              ($1,   $2,           $3,       $4,    $5,  $6,        $7,      $8,      $9)
                            ON CONFLICT (hash) DO UPDATE SET
                              block_number = EXCLUDED.block_number,
                              tx_index     = EXCLUDED.tx_index,
                              "from"       = EXCLUDED."from",
                              "to"         = EXCLUDED."to",
                              value_wei    = EXCLUDED.value_wei,
                              fee_wei      = EXCLUDED.fee_wei,
                              success      = EXCLUDED.success,
                              nonce        = EXCLUDED.nonce
                            "#,
                            t.hash,
                            t.block_number as i64,
                            t.tx_index as i32,
                            t.from,
                            t.to,
                            &t.value_wei,
                            &t.fee_wei,
                            t.success,
                            t.nonce as i64
                        )
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| StoreError::Db(e.to_string()))?;
                    }

                    // Логи: удалим прежние логи транзакций бандла и вставим заново (простая идемпотентность).
                    if !bundle.logs.is_empty() {
                        let tx_hashes: Vec<&str> = bundle.logs.iter().map(|l| l.tx_hash.as_str()).collect();
                        sqlx::query(
                            r#"DELETE FROM logs WHERE tx_hash = ANY($1)"#
                        )
                        .bind(&tx_hashes)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| StoreError::Db(e.to_string()))?;
                    }
                    for l in &bundle.logs {
                        sqlx::query!(
                            r#"
                            INSERT INTO logs (tx_hash, log_index, address, topics, data)
                            VALUES ($1, $2, $3, $4::jsonb, $5)
                            ON CONFLICT (tx_hash, log_index) DO UPDATE SET
                              address = EXCLUDED.address,
                              topics  = EXCLUDED.topics,
                              data    = EXCLUDED.data
                            "#,
                            l.tx_hash,
                            l.log_index as i32,
                            l.address,
                            serde_json::to_value(&l.topics).unwrap(),
                            &l.data
                        )
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| StoreError::Db(e.to_string()))?;
                    }

                    tx.commit().await.map_err(|e| StoreError::Db(e.to_string()))?;
                    Ok(())
                })
            })
            .await
        }

        async fn get_last_canonical_block(&self) -> Result<Option<BlockNumber>, StoreError> {
            let rec = sqlx::query_scalar!(
                r#"SELECT MAX(number) as "max!: i64" FROM blocks WHERE canonical = TRUE"#
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Db(e.to_string()))?;
            Ok(rec.map(|v| v as u64))
        }

        async fn revert_canonical_from(&self, from_number: BlockNumber) -> Result<(), StoreError> {
            self.with_tx(|mut tx| {
                Box::pin(async move {
                    // Удалить/пометить неканоничными все блоки >= from_number.
                    // Транзакции/логи ссылаются каскадом (ON DELETE CASCADE) — допустимо удалить блоки.
                    sqlx::query!(
                        r#"DELETE FROM blocks WHERE number >= $1"#,
                        from_number as i64
                    )
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| StoreError::Db(e.to_string()))?;
                    tx.commit().await.map_err(|e| StoreError::Db(e.to_string()))?;
                    Ok(())
                })
            })
            .await
        }

        async fn get_tx_by_hash(&self, hash: &str) -> Result<Option<Transaction>, StoreError> {
            let rec = sqlx::query!(
                r#"
                SELECT hash, block_number, tx_index, "from", "to", value_wei, fee_wei, success, nonce
                FROM transactions WHERE hash = $1
                "#,
                hash
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Db(e.to_string()))?;

            Ok(rec.map(|r| Transaction {
                hash: r.hash,
                block_number: r.block_number as u64,
                tx_index: r.tx_index as u32,
                from: r.from,
                to: r.to,
                value_wei: r.value_wei,
                fee_wei: r.fee_wei,
                success: r.success,
                nonce: r.nonce as u64,
            }))
        }
    }
}

/* ==========================
   Утилиты и тесты
   ========================== */

/// Простая экспоненциальная задержка с ограничением.
fn next_backoff(prev: Duration, max: Duration) -> Duration {
    let next = prev.saturating_mul(2);
    if next > max { max } else { next }
}

/// Предварительный модуль экспорта.
pub mod prelude {
    pub use super::{
        Block, BlockBundle, BlockNumber, ChainRef, Log, MemoryStore, Store, StoreError, Transaction,
    };
    #[cfg(feature = "postgres")]
    pub use super::postgres::PgStore;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_roundtrip() {
        let store = MemoryStore::default();

        let chain = ChainRef("chain-A".into());
        assert!(store.get_checkpoint(&chain).await.unwrap().is_none());

        store.set_checkpoint(&chain, 10).await.unwrap();
        assert_eq!(store.get_checkpoint(&chain).await.unwrap(), Some(10));

        // Сформируем бандл блока 11
        let b = Block {
            number: 11,
            hash: "0xB".into(),
            parent_hash: "0xA".into(),
            timestamp_ms: 1_700_000_000_000,
            tx_count: 2,
        };
        let t1 = Transaction {
            hash: "0xT1".into(),
            block_number: 11,
            tx_index: 0,
            from: "0xF1".into(),
            to: Some("0xR1".into()),
            value_wei: "1000".into(),
            fee_wei: "10".into(),
            success: true,
            nonce: 1,
        };
        let t2 = Transaction {
            hash: "0xT2".into(),
            block_number: 11,
            tx_index: 1,
            from: "0xF2".into(),
            to: None,
            value_wei: "2000".into(),
            fee_wei: "20".into(),
            success: false,
            nonce: 2,
        };
        let l1 = Log {
            tx_hash: "0xT1".into(),
            log_index: 0,
            address: "0xC1".into(),
            topics: vec!["0xAAA".into()],
            data: vec![1, 2, 3],
        };
        let bundle = BlockBundle { block: b, txs: vec![t1.clone(), t2.clone()], logs: vec![l1.clone()] };

        store.upsert_canonical_bundle(&bundle).await.unwrap();
        assert_eq!(store.get_last_canonical_block().await.unwrap(), Some(11));

        // Найти транзакцию
        let got = store.get_tx_by_hash("0xT1").await.unwrap().unwrap();
        assert_eq!(got, t1);

        // Реорг с блока 11 — всё должно исчезнуть
        store.revert_canonical_from(11).await.unwrap();
        assert_eq!(store.get_last_canonical_block().await.unwrap(), None);
        assert!(store.get_tx_by_hash("0xT1").await.unwrap().is_none());
    }

    #[test]
    fn backoff_increases_but_caps() {
        let mut d = Duration::from_millis(50);
        let max = Duration::from_millis(300);
        d = next_backoff(d, max);
        assert_eq!(d, Duration::from_millis(100));
        d = next_backoff(d, max);
        assert_eq!(d, Duration::from_millis(200));
        d = next_backoff(d, max);
        assert_eq!(d, Duration::from_millis(300));
        d = next_backoff(d, max);
        assert_eq!(d, Duration::from_millis(300));
    }
}
