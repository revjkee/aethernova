// aethernova-chain-core/bridge/relayer/src/lib.rs
//! Aethernova Bridge Relayer core library.
//!
//! Архитектура:
//! - `SourceClient` вытягивает подтверждённые сообщения из исходной цепи по блокам.
//! - `TargetClient` публикует сообщения в целевую цепь (или шину).
//! - `Store` даёт идемпотентность и чекпоинты (перезапуски/реорги).
//! - `Relayer` оркестрирует polling, подтверждения, батчинг, ретраи, ограничения конкуренции.
//!
//! Требуемые зависимости (пример Cargo.toml):
//!   anyhow = "1"
//!   async-trait = "0.1"
//!   futures = "0.3"
//!   serde = { version = "1", features = ["derive"] }
//!   thiserror = "1"
//!   tokio = { version = "1", features = ["rt-multi-thread","macros","time","sync"] }
//!   tracing = "0.1"
//!
//! Опционально: метрики/экспорт Prometheus — реализуйте свой `Metrics` поверх этого интерфейса.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, Instant};
use tracing::{debug, error, info, instrument, warn};

/// Уникальный идентификатор цепи (произвольная строка: "l1", "l2", "ton", "evm:1", ...).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub String);

/// Тип блока (монотонно растущий номер).
pub type BlockNumber = u64;

/// Идентификатор сообщения (должен обеспечивать идемпотентность в приёмнике).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

/// Сообщение для релея между цепями.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub source: ChainId,
    pub target: ChainId,
    pub block_number: BlockNumber,
    pub nonce: u64,
    pub payload: Vec<u8>,
    pub timestamp_ms: u64,
}

/// Результат публикации сообщения в целевую систему.
#[derive(Clone, Debug)]
pub struct SubmitReceipt {
    pub message_id: MessageId,
    pub target_tx: Option<String>,
}

#[derive(Debug, Error)]
pub enum RelayerError {
    #[error("source client error: {0}")]
    Source(String),
    #[error("target client error: {0}")]
    Target(String),
    #[error("store error: {0}")]
    Store(String),
}

/// Клиент исходной цепи: отдает подтверждённые сообщения и заголовки.
#[async_trait]
pub trait SourceClient: Send + Sync + 'static {
    /// Возвращает последний известный номер блока.
    async fn latest_block(&self) -> Result<BlockNumber, RelayerError>;

    /// Возвращает массив сообщений из полуинтервала [from, to], включительно.
    async fn fetch_messages(
        &self,
        from: BlockNumber,
        to: BlockNumber,
        limit: usize,
    ) -> Result<Vec<Message>, RelayerError>;
}

/// Клиент целевой цепи/шины: публикует сообщения.
#[async_trait]
pub trait TargetClient: Send + Sync + 'static {
    /// Публикация одного сообщения. Должна быть идемпотентной на стороне приёмника.
    async fn submit(&self, msg: &Message) -> Result<SubmitReceipt, RelayerError>;
}

/// Хранилище для идемпотентности и чекпоинтов.
/// Продакшн-вариант: Redis/Postgres/Etcd. Здесь — интерфейс и in-memory реализация.
#[async_trait]
pub trait Store: Send + Sync + 'static {
    async fn has_processed(&self, target: &ChainId, id: &MessageId) -> Result<bool, RelayerError>;
    async fn mark_processed(&self, target: &ChainId, id: &MessageId) -> Result<(), RelayerError>;

    async fn get_checkpoint(&self, source: &ChainId) -> Result<Option<BlockNumber>, RelayerError>;
    async fn set_checkpoint(&self, source: &ChainId, block: BlockNumber) -> Result<(), RelayerError>;
}

/// Метрики. Реализуйте экспорт в Prometheus/OpenTelemetry вне этого крейта.
#[async_trait]
pub trait Metrics: Send + Sync + 'static {
    async fn inc_seen(&self, _chain: &ChainId, _n: u64) {}
    async fn inc_submitted(&self, _chain: &ChainId) {}
    async fn inc_failed(&self, _chain: &ChainId) {}
    async fn record_latency_ms(&self, _op: &'static str, _ms: u128) {}
    async fn set_checkpoint(&self, _chain: &ChainId, _block: BlockNumber) {}
}

/// Пустые метрики по умолчанию.
#[derive(Default)]
pub struct NoopMetrics;
#[async_trait]
impl Metrics for NoopMetrics {}

/// Конфигурация релейера.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayerConfig {
    /// Сколько подтверждений требуется до финализации блока.
    pub confirmations: u64,
    /// Интервал опроса исходной цепи.
    pub poll_interval_ms: u64,
    /// Максимальный размер batch при fetch_messages.
    pub source_batch: usize,
    /// Максимум одновременно публикуемых сообщений.
    pub max_inflight: usize,
    /// Параметры экспоненциального бэкоффа.
    pub retry: RetryConfig,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            confirmations: 12,
            poll_interval_ms: 1500,
            source_batch: 100,
            max_inflight: 256,
            retry: RetryConfig::default(),
        }
    }
}

/// Конфигурация ретраев.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_attempts: usize,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            base_delay_ms: 200,
            max_delay_ms: 8_000,
            jitter: true,
        }
    }
}

/// Класс релейера.
pub struct Relayer<S, T, St, M>
where
    S: SourceClient,
    T: TargetClient,
    St: Store,
    M: Metrics,
{
    source_chain: ChainId,
    target_chain: ChainId,
    source: Arc<S>,
    target: Arc<T>,
    store: Arc<St>,
    metrics: Arc<M>,
    cfg: RelayerConfig,
    limiter: Arc<Semaphore>,
}

impl<S, T, St, M> Relayer<S, T, St, M>
where
    S: SourceClient,
    T: TargetClient,
    St: Store,
    M: Metrics,
{
    pub fn new(
        source_chain: ChainId,
        target_chain: ChainId,
        source: Arc<S>,
        target: Arc<T>,
        store: Arc<St>,
        metrics: Arc<M>,
        cfg: RelayerConfig,
    ) -> Self {
        Self {
            source_chain,
            target_chain,
            source,
            target,
            store,
            metrics,
            limiter: Arc::new(Semaphore::new(cfg.max_inflight)),
            cfg,
        }
    }

    /// Главный цикл релейера: polling → выбор финализированного диапазона → fetch → publish.
    #[instrument(skip_all, fields(source = %self.source_chain.0, target = %self.target_chain.0))]
    pub async fn run(&self) -> Result<()> {
        info!("relayer started");
        loop {
            let started = Instant::now();
            match self.step().await {
                Ok(progress) => {
                    self.metrics
                        .record_latency_ms("step", started.elapsed().as_millis())
                        .await;
                    if !progress {
                        // Нет прогресса — подождём poll_interval.
                        sleep(Duration::from_millis(self.cfg.poll_interval_ms)).await;
                    }
                }
                Err(e) => {
                    error!("relayer step error: {e:?}");
                    sleep(Duration::from_millis(self.cfg.poll_interval_ms)).await;
                }
            }
        }
    }

    /// Один шаг: обработка нового финализированного диапазона.
    async fn step(&self) -> Result<bool> {
        let latest = self.source.latest_block().await.map_err(|e| anyhow!(e))?;
        if latest < self.cfg.confirmations {
            debug!("latest < confirmations, skip");
            return Ok(false);
        }
        let finalized = latest - self.cfg.confirmations;

        // Чекпоинт: откуда продолжать.
        let from = match self.store.get_checkpoint(&self.source_chain).await? {
            Some(cp) if cp < finalized => cp + 1,
            Some(_) => {
                debug!("already up to date: finalized={finalized}");
                return Ok(false);
            }
            None => 0,
        };

        if from > finalized {
            debug!("from > finalized, nothing to do");
            return Ok(false);
        }

        // Загружаем сообщения частями и публикуем.
        let mut cursor = from;
        let mut made_progress = false;

        while cursor <= finalized {
            let upper = (cursor + self.cfg.source_batch as u64 - 1).min(finalized);
            let msgs = self
                .source
                .fetch_messages(cursor, upper, self.cfg.source_batch)
                .await
                .map_err(|e| anyhow!(e))?;

            self.metrics
                .inc_seen(&self.source_chain, msgs.len() as u64)
                .await;

            if msgs.is_empty() {
                cursor = upper.saturating_add(1);
                continue;
            }

            // Параллельная публикация с ограничением concurrency.
            let limiter = self.limiter.clone();
            let target = self.target.clone();
            let store = self.store.clone();
            let target_chain = self.target_chain.clone();
            let metrics = self.metrics.clone();
            let rcfg = self.cfg.retry.clone();

            stream::iter(msgs)
                .for_each_concurrent(self.cfg.max_inflight, move |msg| {
                    let limiter = limiter.clone();
                    let target = target.clone();
                    let store = store.clone();
                    let target_chain = target_chain.clone();
                    let metrics = metrics.clone();
                    let rcfg = rcfg.clone();

                    async move {
                        // Идемпотентность.
                        match store.has_processed(&target_chain, &msg.id).await {
                            Ok(true) => {
                                debug!("skip already processed {}", (msg.id.0));
                                return;
                            }
                            Ok(false) => {}
                            Err(e) => {
                                warn!("store error has_processed: {e:?}");
                                return;
                            }
                        }

                        // Лимитер на единичный таск.
                        let _permit = limiter.acquire().await;

                        let res = retry_with_backoff(rcfg.clone(), || async {
                            let start = Instant::now();
                            let r = target.submit(&msg).await;
                            if r.is_ok() {
                                metrics
                                    .record_latency_ms("submit", start.elapsed().as_millis())
                                    .await;
                            }
                            r
                        })
                        .await;

                        match res {
                            Ok(rcpt) => {
                                let _ = store.mark_processed(&target_chain, &rcpt.message_id).await;
                                metrics.inc_submitted(&target_chain).await;
                            }
                            Err(e) => {
                                metrics.inc_failed(&target_chain).await;
                                error!("submit failed for {}: {e:?}", msg.id.0);
                            }
                        }
                    }
                })
                .await;

            // Сдвигаем чекпоинт на upper (всегда безопасно: верх как минимум просмотрен).
            self.store
                .set_checkpoint(&self.source_chain, upper)
                .await?;
            self.metrics.set_checkpoint(&self.source_chain, upper).await;

            made_progress = true;
            cursor = upper.saturating_add(1);
        }

        Ok(made_progress)
    }
}

/// Экспоненциальный бэкофф с опциональным джиттером.
async fn retry_with_backoff<F, Fut, T>(
    cfg: RetryConfig,
    mut op: F,
) -> Result<T, RelayerError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, RelayerError>>,
{
    let mut attempt = 0usize;
    let mut delay = Duration::from_millis(cfg.base_delay_ms.max(1));

    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                attempt += 1;
                if attempt >= cfg.max_attempts {
                    return Err(e);
                }
                let max = Duration::from_millis(cfg.max_delay_ms.max(cfg.base_delay_ms));
                let mut d = delay.min(max);
                if cfg.jitter {
                    // простейший равномерный джиттер [d/2; d]
                    let half = d / 2;
                    let jitter = rand_u64_range(half.as_millis() as u64, d.as_millis() as u64);
                    d = Duration::from_millis(jitter);
                }
                sleep(d).await;
                delay = delay.saturating_mul(2);
            }
        }
    }
}

fn rand_u64_range(min: u64, max: u64) -> u64 {
    // Очень лёгкий PRNG на базе xorshift64* (без зависимости от rand)
    let mut x = (min ^ 0x9E3779B97F4A7C15).wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 30;
    x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    let span = max.saturating_sub(min).max(1);
    min + (x % span)
}

/// Простое in-memory хранилище для тестов/локальной разработки.
#[derive(Default)]
pub struct MemoryStore {
    processed: Mutex<HashMap<ChainId, HashSet<MessageId>>>,
    checkpoints: Mutex<HashMap<ChainId, BlockNumber>>,
}

#[async_trait]
impl Store for MemoryStore {
    async fn has_processed(&self, target: &ChainId, id: &MessageId) -> Result<bool, RelayerError> {
        let m = self.processed.lock().await;
        Ok(m.get(target).map(|s| s.contains(id)).unwrap_or(false))
    }

    async fn mark_processed(&self, target: &ChainId, id: &MessageId) -> Result<(), RelayerError> {
        let mut m = self.processed.lock().await;
        m.entry(target.clone()).or_default().insert(id.clone());
        Ok(())
    }

    async fn get_checkpoint(&self, source: &ChainId) -> Result<Option<BlockNumber>, RelayerError> {
        let m = self.checkpoints.lock().await;
        Ok(m.get(source).copied())
    }

    async fn set_checkpoint(&self, source: &ChainId, block: BlockNumber) -> Result<(), RelayerError> {
        let mut m = self.checkpoints.lock().await;
        m.insert(source.clone(), block);
        Ok(())
    }
}

/// Prelude для удобного импорта извне.
pub mod prelude {
    pub use super::{
        ChainId, Message, MessageId, Relayer, RelayerConfig, RetryConfig, SubmitReceipt, MemoryStore,
        Metrics, NoopMetrics, SourceClient, TargetClient, Store,
    };
}

/* ------------------------------ ТЕСТЫ ------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct MockSource {
        latest: AtomicU64,
        // карта: номер блока -> очередь сообщений
        blocks: Arc<Mutex<HashMap<BlockNumber, VecDeque<Message>>>>,
    }

    #[async_trait]
    impl SourceClient for MockSource {
        async fn latest_block(&self) -> Result<BlockNumber, RelayerError> {
            Ok(self.latest.load(Ordering::Relaxed))
        }

        async fn fetch_messages(
            &self,
            from: BlockNumber,
            to: BlockNumber,
            limit: usize,
        ) -> Result<Vec<Message>, RelayerError> {
            let mut out = Vec::new();
            let mut blocks = self.blocks.lock().await;
            for b in from..=to {
                if let Some(q) = blocks.get_mut(&b) {
                    while let Some(m) = q.pop_front() {
                        out.push(m);
                        if out.len() >= limit {
                            break;
                        }
                    }
                }
                if out.len() >= limit {
                    break;
                }
            }
            Ok(out)
        }
    }

    struct MockTarget {
        pub delivered: Arc<Mutex<Vec<MessageId>>>,
        pub fail_first: bool,
    }

    #[async_trait]
    impl TargetClient for MockTarget {
        async fn submit(&self, msg: &Message) -> Result<SubmitReceipt, RelayerError> {
            // Смоделируем одну временную ошибку для первой публикации.
            if self.fail_first {
                // после первой попытки считаем, что последующие успешны
                self.delivered.lock().await.push(MessageId(format!("TEMP_FAIL_{}", msg.id.0)));
                return Err(RelayerError::Target("temporary".into()));
            }
            self.delivered.lock().await.push(msg.id.clone());
            Ok(SubmitReceipt {
                message_id: msg.id.clone(),
                target_tx: Some(format!("tx-{}", msg.nonce)),
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relayer_end_to_end() {
        let source_chain = ChainId("L1".into());
        let target_chain = ChainId("L2".into());

        // Подготовим 5 блоков по 2 сообщения.
        let mut blocks: HashMap<BlockNumber, VecDeque<Message>> = HashMap::new();
        let mut nonce = 0u64;
        for b in 0..5 {
            let mut q = VecDeque::new();
            for _ in 0..2 {
                let id = MessageId(format!("m-{b}-{nonce}"));
                q.push_back(Message {
                    id,
                    source: source_chain.clone(),
                    target: target_chain.clone(),
                    block_number: b,
                    nonce,
                    payload: vec![1, 2, 3],
                    timestamp_ms: 0,
                });
                nonce += 1;
            }
            blocks.insert(b, q);
        }

        let mock_source = MockSource {
            latest: AtomicU64::new(20),
            blocks: Arc::new(Mutex::new(blocks)),
        };

        let delivered = Arc::new(Mutex::new(Vec::new()));
        let target = MockTarget {
            delivered: delivered.clone(),
            fail_first: false,
        };

        let relayer = Relayer::new(
            source_chain.clone(),
            target_chain.clone(),
            Arc::new(mock_source),
            Arc::new(target),
            Arc::new(MemoryStore::default()),
            Arc::new(NoopMetrics::default()),
            RelayerConfig {
                confirmations: 10, // finalized = 20 - 10 = 10 ≥ наши блоки [0..4]
                poll_interval_ms: 50,
                source_batch: 10,
                max_inflight: 8,
                retry: RetryConfig {
                    max_attempts: 3,
                    base_delay_ms: 10,
                    max_delay_ms: 50,
                    jitter: false,
                },
            },
        );

        // Выполним один шаг (без бесконечного цикла).
        let progress = relayer.step().await.unwrap();
        assert!(progress);

        let ids = delivered.lock().await.clone();
        // 5 блоков * 2 сообщения = 10 публикаций
        assert_eq!(ids.len(), 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_works() {
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay_ms: 1,
            max_delay_ms: 3,
            jitter: false,
        };
        let mut attempts = 0usize;
        let res: Result<u32, RelayerError> =
            retry_with_backoff(cfg, || async {
                attempts += 1;
                if attempts < 3 {
                    Err(RelayerError::Target("temp".into()))
                } else {
                    Ok(42u32)
                }
            }).await;
        assert_eq!(res.unwrap(), 42);
        assert_eq!(attempts, 3);
    }
}
