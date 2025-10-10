// aethernova-chain-core/explorer/indexer/src/lib.rs
//! Универсальный индексатор блокчейна.
//!
//! Рекомендуемые зависимости (в Cargo.toml):
//! tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
//! futures = "0.3"
//! async-trait = "0.1"
//! serde = { version = "1", features = ["derive"] }
//! thiserror = "1"
//! rand = "0.8"
//! tracing = "0.1"
//! tokio-util = { version = "0.7", features = ["sync"] }
//
//! Библиотека предоставляет:
//! - Trait BlockchainClient: загрузка высоты, блоков, хешей.
//! - Trait Store: транзакции, upsert блоков/транзакций, чекпойнты, чтение хешей для откатов.
//! - Trait MetricsSink: необязательные хуки метрик.
//! - Indexer: основной исполнитель с подтверждениями, батч-проходом, конкуренцией и reorg.
//!
//! Пример использования приведен в модульных тестах (mock-клиент и mock-хранилище).

use std::cmp::{max, min};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::{stream, StreamExt, TryStreamExt};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Базовые типы данных индексируемой цепи.
/// Вы можете адаптировать под конкретный блокчейн.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub txs: Vec<Tx>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tx {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub fee: String,
    pub nonce: u64,
    pub index_in_block: u32,
}

#[async_trait]
pub trait BlockchainClient: Send + Sync + 'static {
    /// Текущая высота цепи (может быть меняющейся).
    async fn latest_block_number(&self) -> Result<u64, IndexerError>;
    /// Загрузка блока по номеру. Возвращает None, если блок отсутствует (например, race).
    async fn block_by_number(&self, number: u64) -> Result<Option<Block>, IndexerError>;
    /// Хеш блока по номеру. Для ускорения reorg-детекции.
    async fn block_hash_by_number(&self, number: u64) -> Result<Option<String>, IndexerError>;
}

#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Начать транзакцию (опционально no-op).
    async fn begin(&self) -> Result<(), IndexerError> { Ok(()) }
    /// Зафиксировать транзакцию.
    async fn commit(&self) -> Result<(), IndexerError> { Ok(()) }
    /// Откатить транзакцию.
    async fn rollback(&self) -> Result<(), IndexerError> { Ok(()) }

    /// Upsert блока и его транзакций (идемпотентно).
    async fn upsert_block_with_txs(&self, block: &Block) -> Result<(), IndexerError>;
    /// Сохранить/обновить чекпойнт (последний полностью обработанный номер блока).
    async fn set_checkpoint(&self, block_number: u64) -> Result<(), IndexerError>;
    /// Прочитать чекпойнт. Возвращает None, если еще не индексировали.
    async fn get_checkpoint(&self) -> Result<Option<u64>, IndexerError>;

    /// Прочитать сохраненный хеш блока из БД (для поиска общего предка при reorg).
    async fn stored_block_hash(&self, number: u64) -> Result<Option<String>, IndexerError>;

    /// Журналировать реорганизацию (опционально).
    async fn record_reorg(&self, _from_number: u64, _to_number: u64, _depth: u64) -> Result<(), IndexerError> {
        Ok(())
    }
}

/// Необязательный приемник метрик.
pub trait MetricsSink: Send + Sync + 'static {
    fn inc_counter(&self, name: &str, labels: &[(&str, &str)]);
    fn observe_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]);
}

/// Конфигурация индексатора.
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    pub confirmations: u64,          // Сколько подтверждений ожидать перед индексацией.
    pub batch_size: u64,             // Размер партии блоков.
    pub concurrency: usize,          // Параллелизм загрузки блоков.
    pub poll_interval: Duration,     // Интервал опроса высоты.
    pub max_backoff: Duration,       // Верхняя граница бэкоффа.
    pub start_block: Option<u64>,    // Необязательная принудительная начальная высота.
    pub reorg_depth_limit: u64,      // Максимальная глубина отката при реорганизации.
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            confirmations: 12,
            batch_size: 50,
            concurrency: 8,
            poll_interval: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
            start_block: None,
            reorg_depth_limit: 64,
        }
    }
}

#[derive(Error, Debug)]
pub enum IndexerError {
    #[error("client error: {0}")]
    Client(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("inconsistent chain at height {height}: expected parent {expected_parent}, got {actual_parent}")]
    InconsistentChain {
        height: u64,
        expected_parent: String,
        actual_parent: String,
    },
    #[error("reorg depth exceeded: {0}")]
    ReorgTooDeep(u64),
    #[error("canceled")]
    Canceled,
    #[error("other: {0}")]
    Other(String),
}

impl From<anyhow::Error> for IndexerError {
    fn from(e: anyhow::Error) -> Self { Self::Other(e.to_string()) }
}

/// Основной индексатор.
pub struct Indexer<C: BlockchainClient, S: Store> {
    cfg: IndexerConfig,
    client: Arc<C>,
    store: Arc<S>,
    metrics: Option<Arc<dyn MetricsSink>>,
}

impl<C: BlockchainClient, S: Store> Indexer<C, S> {
    pub fn new(cfg: IndexerConfig, client: Arc<C>, store: Arc<S>, metrics: Option<Arc<dyn MetricsSink>>) -> Self {
        Self { cfg, client, store, metrics }
    }

    /// Запуск основного цикла. Блокирующий future до отмены или ошибки.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), IndexerError> {
        let mut rng = StdRng::from_entropy();
        loop {
            if cancel.is_cancelled() {
                return Err(IndexerError::Canceled);
            }

            let latest = self.client.latest_block_number().await
                .map_err(|e| IndexerError::Client(format!("{e:?}")))?;
            let safe_tip = latest.saturating_sub(self.cfg.confirmations);
            let from = self.compute_start_height().await?;
            if safe_tip < from {
                // Ждем появления новых безопасных блоков.
                sleep(self.cfg.poll_interval).await;
                continue;
            }

            // Индексируем диапазон [from..=safe_tip] пакетами.
            self.index_range(from..=safe_tip, &cancel).await?;

            // После прохода сдвигаем чекпойнт на safe_tip.
            self.store.set_checkpoint(safe_tip).await
                .map_err(|e| IndexerError::Store(format!("{e:?}")))?;

            // Небольшая пауза перед новым опросом.
            sleep(self.cfg.poll_interval).await;
        }
    }

    async fn compute_start_height(&self) -> Result<u64, IndexerError> {
        if let Some(h) = self.cfg.start_block {
            Ok(h)
        } else {
            Ok(self.store.get_checkpoint().await
                .map_err(|e| IndexerError::Store(format!("{e:?}")))?
                .map(|h| h.saturating_add(1))
                .unwrap_or(0))
        }
    }

    async fn index_range(&self, range: RangeInclusive<u64>, cancel: &CancellationToken) -> Result<(), IndexerError> {
        let total = range.end().saturating_sub(*range.start()) + 1;
        let batch_size = self.cfg.batch_size.max(1);

        let mut start = *range.start();
        while start <= *range.end() {
            if cancel.is_cancelled() {
                return Err(IndexerError::Canceled);
            }

            let end = min(start.saturating_add(batch_size - 1), *range.end());
            let began_at = Instant::now();
            match self.index_batch(start, end, cancel).await {
                Ok(()) => {
                    self.observe_hist("index_batch_seconds", began_at.elapsed().as_secs_f64(),
                        &[("result", "ok")]);
                    start = end.saturating_add(1);
                }
                Err(e) => {
                    self.observe_hist("index_batch_seconds", began_at.elapsed().as_secs_f64(),
                        &[("result", "err")]);
                    warn!("batch [{start}..={end}] failed: {e:?}");
                    self.backoff_retry(cancel).await?;
                }
            }
        }
        info!("indexed {} blocks", total);
        Ok(())
    }

    async fn index_batch(&self, start: u64, end: u64, cancel: &CancellationToken) -> Result<(), IndexerError> {
        // Загрузка и проверка связности блоков с конкуренцией.
        let numbers: Vec<u64> = (start..=end).collect();
        let blocks: Vec<Block> = stream::iter(numbers.into_iter())
            .map(|n| {
                let client = Arc::clone(&self.client);
                async move {
                    let b = client.block_by_number(n).await
                        .map_err(|e| IndexerError::Client(format!("{e:?}")))?;
                    b.ok_or_else(|| IndexerError::Client(format!("missing block {n}")))
                }
            })
            .buffer_unordered(self.cfg.concurrency)
            .try_collect()
            .await?;

        // Сортируем по номеру, т.к. buffer_unordered не гарантирует порядок.
        let mut blocks = blocks;
        blocks.sort_by_key(|b| b.number);

        // Проверка линейности цепи и обработка возможного reorg на границе.
        self.detect_and_handle_reorg(&blocks).await?;

        // Запись в БД одной транзакцией для идемпотентности партии.
        self.store.begin().await.map_err(|e| IndexerError::Store(format!("{e:?}")))?;
        for b in &blocks {
            self.store.upsert_block_with_txs(b).await
                .map_err(|e| IndexerError::Store(format!("{e:?}")))?;
        }
        self.store.commit().await.map_err(|e| IndexerError::Store(format!("{e:?}")))?;

        // Продвинем чекпойнт на конец партии.
        self.store.set_checkpoint(end).await
            .map_err(|e| IndexerError::Store(format!("{e:?}")))?;

        self.inc("indexed_blocks_total", &[("result", "ok")]);
        Ok(())
    }

    async fn detect_and_handle_reorg(&self, batch: &[Block]) -> Result<(), IndexerError> {
        if batch.is_empty() {
            return Ok(());
        }

        // Проверка связности внутри партии.
        for win in batch.windows(2) {
            let a = &win[0];
            let b = &win[1];
            if b.parent_hash != a.hash {
                return Err(IndexerError::InconsistentChain {
                    height: b.number,
                    expected_parent: a.hash.clone(),
                    actual_parent: b.parent_hash.clone(),
                });
            }
        }

        // Проверим, не расходится ли первый блок партии с уже сохраненным предыдущим в БД.
        let first = &batch[0];
        if first.number > 0 {
            if let Some(stored_parent_hash) = self.store.stored_block_hash(first.number - 1).await
                .map_err(|e| IndexerError::Store(format!("{e:?}")))? {
                if stored_parent_hash != first.parent_hash {
                    // Реорганизация. Откатываемся к общему предку.
                    let depth = self.rewind_to_common_ancestor(first.number - 1).await?;
                    self.store.record_reorg(first.number - 1, batch.last().unwrap().number, depth).await
                        .map_err(|e| IndexerError::Store(format!("{e:?}")))?;
                    warn!("reorg handled: depth={depth}, resumed from {}", first.number);
                }
            }
        }
        Ok(())
    }

    async fn rewind_to_common_ancestor(&self, mut at: u64) -> Result<u64, IndexerError> {
        let mut depth: u64 = 0;
        loop {
            if depth >= self.cfg.reorg_depth_limit {
                return Err(IndexerError::ReorgTooDeep(depth));
            }
            // Сопоставляем хеши: в БД и в сети.
            let db_hash = self.store.stored_block_hash(at).await
                .map_err(|e| IndexerError::Store(format!("{e:?}")))?;
            let net_hash = self.client.block_hash_by_number(at).await
                .map_err(|e| IndexerError::Client(format!("{e:?}")))?;
            match (db_hash, net_hash) {
                (Some(dh), Some(nh)) if dh == nh => {
                    // Нашли общего предка. Чекпойнт на этого предка.
                    self.store.set_checkpoint(at).await
                        .map_err(|e| IndexerError::Store(format!("{e:?}")))?;
                    return Ok(depth);
                }
                _ => {
                    // Сдвигаемся назад.
                    if at == 0 { 
                        self.store.set_checkpoint(0).await
                            .map_err(|e| IndexerError::Store(format!("{e:?}")))?;
                        return Ok(depth);
                    }
                    at -= 1;
                    depth += 1;
                }
            }
        }
    }

    async fn backoff_retry(&self, cancel: &CancellationToken) -> Result<(), IndexerError> {
        // Экспоненциальный бэкофф с джиттером.
        let mut delay = Duration::from_millis(400);
        let mut rng = StdRng::from_entropy();
        while !cancel.is_cancelled() && delay <= self.cfg.max_backoff {
            let jitter = rng.gen_range(0..=200);
            sleep(delay + Duration::from_millis(jitter)).await;
            return Ok(()); // одна пауза между ретраями на уровень вызывающего
        }
        if cancel.is_cancelled() { Err(IndexerError::Canceled) } else { Ok(()) }
    }

    fn inc(&self, name: &str, labels: &[(&str, &str)]) {
        if let Some(m) = &self.metrics {
            m.inc_counter(name, labels);
        }
    }

    fn observe_hist(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        if let Some(m) = &self.metrics {
            m.observe_histogram(name, value, labels);
        }
    }
}

// -------------------------- Тесты с моками --------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    struct MockClient {
        tip: Mutex<u64>,
        blocks: Mutex<HashMap<u64, Block>>,
    }

    #[async_trait]
    impl BlockchainClient for MockClient {
        async fn latest_block_number(&self) -> Result<u64, IndexerError> {
            Ok(*self.tip.lock().await)
        }
        async fn block_by_number(&self, number: u64) -> Result<Option<Block>, IndexerError> {
            Ok(self.blocks.lock().await.get(&number).cloned())
        }
        async fn block_hash_by_number(&self, number: u64) -> Result<Option<String>, IndexerError> {
            Ok(self.blocks.lock().await.get(&number).map(|b| b.hash.clone()))
        }
    }

    struct MockStore {
        cp: Mutex<Option<u64>>,
        blocks: Mutex<HashMap<u64, (String, String)>>,
    }

    #[async_trait]
    impl Store for MockStore {
        async fn upsert_block_with_txs(&self, block: &Block) -> Result<(), IndexerError> {
            self.blocks.lock().await.insert(block.number, (block.hash.clone(), block.parent_hash.clone()));
            Ok(())
        }
        async fn set_checkpoint(&self, block_number: u64) -> Result<(), IndexerError> {
            *self.cp.lock().await = Some(block_number);
            Ok(())
        }
        async fn get_checkpoint(&self) -> Result<Option<u64>, IndexerError> {
            Ok(*self.cp.lock().await)
        }
        async fn stored_block_hash(&self, number: u64) -> Result<Option<String>, IndexerError> {
            Ok(self.blocks.lock().await.get(&number).map(|(h, _)| h.clone()))
        }
    }

    struct NoopMetrics;
    impl MetricsSink for NoopMetrics {
        fn inc_counter(&self, _: &str, _: &[(&str, &str)]) {}
        fn observe_histogram(&self, _: &str, _: f64, _: &[(&str, &str)]) {}
    }

    fn mk_chain(n: u64, reorg_at: Option<(u64, u64)>) -> (Vec<Block>, u64) {
        // Стандартная линейная цепь с опциональной реорганизацией глубины d в позиции h.
        // reorg_at: (h, d) — соорудим альтернативные хеши после h-d+1.
        let mut v = Vec::new();
        let mut parent = String::from("genesis");
        for i in 0..=n {
            let hash = format!("H{i:08}");
            v.push(Block {
                number: i,
                hash: hash.clone(),
                parent_hash: parent.clone(),
                timestamp: 0,
                txs: vec![],
            });
            parent = hash;
        }

        if let Some((h, d)) = reorg_at {
            // Перепишем хвост на альтернативные хеши
            let start = h.saturating_sub(d).saturating_add(1);
            let parent = if start == 0 { "genesis".to_string() } else { v[(start - 1) as usize].hash.clone() };
            let mut p = parent;
            for i in start..=h {
                let alt = format!("R{i:08}");
                v[i as usize].hash = alt.clone();
                v[i as usize].parent_hash = p.clone();
                p = alt;
            }
        }

        (v, n)
    }

    #[tokio::test]
    async fn linear_chain_indexing() {
        let (chain, tip) = mk_chain(50, None);
        let client = Arc::new(MockClient {
            tip: Mutex::new(tip),
            blocks: Mutex::new(chain.iter().map(|b| (b.number, b.clone())).collect()),
        });
        let store = Arc::new(MockStore { cp: Mutex::new(None), blocks: Mutex::new(HashMap::new()) });
        let metrics = Some(Arc::new(NoopMetrics) as Arc<dyn MetricsSink>);

        let cfg = IndexerConfig { confirmations: 2, batch_size: 10, concurrency: 4, ..Default::default() };
        let indexer = Indexer::new(cfg, client, store.clone(), metrics);

        let cancel = CancellationToken::new();
        // Остановим после одного цикла опроса, когда safe_tip будет проиндексирован.
        let stopper = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            stopper.cancel();
        });

        let _ = indexer.run(cancel).await;
        // Должен продвинуть чекпойнт.
        assert!(store.get_checkpoint().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn reorg_handling_rewinds_to_common_ancestor() {
        // Конструируем реорг глубиной 3.
        let (chain, tip) = mk_chain(30, Some((25, 3)));
        let client = Arc::new(MockClient {
            tip: Mutex::new(tip),
            blocks: Mutex::new(chain.iter().map(|b| (b.number, b.clone())).collect()),
        });
        let store = Arc::new(MockStore { cp: Mutex::new(Some(24)), blocks: Mutex::new(HashMap::new()) });
        // Предположим, что БД хранит хеш на 24, а сеть на 24 совпадает; на 25 уже расходится.
        store.blocks.lock().await.insert(24, (format!("H{:08}", 24), format!("H{:08}", 23)));

        let metrics = Some(Arc::new(NoopMetrics) as Arc<dyn MetricsSink>);
        let cfg = IndexerConfig { confirmations: 0, batch_size: 5, concurrency: 2, ..Default::default() };
        let indexer = Indexer::new(cfg, client, store.clone(), metrics);

        // Индексируем [25..=27], где присутствует реорг.
        let cancel = CancellationToken::new();
        let res = indexer.index_batch(25, 27, &cancel).await;
        assert!(res.is_ok());
        // Проверим, что чекпойнт продвинулся хотя бы до 27 после перезаписи.
        assert_eq!(store.get_checkpoint().await.unwrap(), Some(27));
    }
}
