//! Ethereum adapter for Aethernova relayer.
//!
//! Features:
//! - HTTP Provider (polling) + optional WS Provider (subscribe_logs).
//! - ChainId verification.
//! - Safe head calculation via JSON-RPC block tag "finalized" if available,
//!   otherwise `latest - confirmations`.
//! - Paged `eth_getLogs` with reorg handling and backoff retries.
//! - Dynamic ABI-based event decoding (no codegen), topic filtering,
//!   multi-contract filters.
//! - Pluggable checkpoint storage (trait `CheckpointStore`).
//! - Structured logging via `tracing`.
//!
//! Dependencies (Cargo.toml excerpt):
//! ethers = { version = "2", features = ["abigen", "ws", "rustls"] }
//! tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
//! thiserror = "1"
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! backoff = { version = "0.4", features = ["tokio"] }
//! tracing = "0.1"
//!
//! Notes:
//! - `Provider` exposes JSON-RPC incl. `get_logs`, `get_block`, `get_chainid` etc. (ethers-providers). 
//! - WS subscriptions are available only with WS transport (pubsub). 
//! - JSON-RPC supports tags "latest", "safe", "finalized" (if node supports them).

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use backoff::{future::retry, ExponentialBackoff};
use ethers::{
    abi::{Abi, RawLog},
    core::types::{
        Address, BlockId, BlockNumber, Filter, FilterBlockOption, Log, H160, H256, U64,
    },
    middleware::Middleware,
    providers::{Http, Provider, ProviderError, StreamExt, SubscriptionStream, Ws},
    types::FilterBuilder,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

/// Configuration for the Ethereum adapter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthConfig {
    /// Required HTTP RPC URL.
    pub http_url: String,
    /// Optional WebSocket RPC URL for subscriptions.
    pub ws_url: Option<String>,
    /// Expected chain id; if None, skip verification.
    pub expected_chain_id: Option<u64>,
    /// Number of confirmations if `finalized` not supported.
    pub confirmations: u64,
    /// Initial from-block (inclusive) for backfill; if None, use safe head - window.
    pub from_block: Option<u64>,
    /// Addresses to filter logs for (empty -> any).
    pub addresses: Vec<Address>,
    /// Optional topics[0]..topics[3] exact match filters.
    pub topics: [Option<H256>; 4],
    /// Max block span in a single getLogs request (respect provider limits).
    pub max_range: u64,
    /// Polling interval (HTTP mode) in seconds.
    pub poll_interval_secs: u64,
    /// Reorg rollback depth (blocks) when mismatch detected.
    pub reorg_rollback: u64,
}

impl Default for EthConfig {
    fn default() -> Self {
        Self {
            http_url: String::new(),
            ws_url: None,
            expected_chain_id: None,
            confirmations: 64,
            from_block: None,
            addresses: vec![],
            topics: [None, None, None, None],
            max_range: 5_000, // conservative vs. common 10k RPC limits
            poll_interval_secs: 12,
            reorg_rollback: 6,
        }
    }
}

/// Checkpoint info persisted by relayer (last processed block and its hash).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct Checkpoint {
    pub block_number: u64,
    pub block_hash: H256,
}

/// Abstract store for checkpoints (plug your DB here).
#[async_trait::async_trait]
pub trait CheckpointStore: Send + Sync + 'static {
    async fn load(&self) -> anyhow::Result<Option<Checkpoint>>;
    async fn save(&self, cp: Checkpoint) -> anyhow::Result<()>;
}

/// In-memory fallback (not durable).
pub struct MemoryCheckpoint(std::sync::Mutex<Option<Checkpoint>>);
impl MemoryCheckpoint {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(None))
    }
}
#[async_trait::async_trait]
impl CheckpointStore for MemoryCheckpoint {
    async fn load(&self) -> anyhow::Result<Option<Checkpoint>> {
        Ok(*self.0.lock().unwrap())
    }
    async fn save(&self, cp: Checkpoint) -> anyhow::Result<()> {
        *self.0.lock().unwrap() = Some(cp);
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum EthAdapterError {
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
    #[error("rpc unsupported: {0}")]
    RpcUnsupported(&'static str),
    #[error("abi: {0}")]
    Abi(String),
    #[error("other: {0}")]
    Other(String),
}
type Result<T> = std::result::Result<T, EthAdapterError>;

/// Decoded event (name -> tokens).
#[derive(Debug, Clone)]
pub struct DecodedEvent {
    pub name: String,
    pub fields: BTreeMap<String, serde_json::Value>,
    pub raw: Log,
}

/// Ethereum adapter.
pub struct EthAdapter<S: CheckpointStore> {
    cfg: EthConfig,
    http: Arc<Provider<Http>>,
    ws: Option<Arc<Provider<Ws>>>,
    cp: Arc<S>,
    abi: Arc<Abi>,
}

impl<S: CheckpointStore> EthAdapter<S> {
    /// Initialize adapter, establish HTTP (and optional WS) connections, verify chain id.
    pub async fn new(cfg: EthConfig, abi: Abi, cp: Arc<S>) -> Result<Self> {
        let http = Provider::<Http>::try_from(cfg.http_url.as_str())
            .map_err(EthAdapterError::Provider)?;
        // Optional: reduce noisy timeouts via `interval` or `with_sender` middlewares outside.
        let http = Arc::new(http);

        // Verify chain id if requested
        if let Some(exp) = cfg.expected_chain_id {
            let got = http.get_chainid().await?.as_u64();
            if got != exp {
                return Err(EthAdapterError::Other(format!(
                    "chain id mismatch: expected {}, got {}",
                    exp, got
                )));
            }
        }

        // Optional WS
        let ws = if let Some(ws_url) = &cfg.ws_url {
            let ws = Provider::<Ws>::connect(ws_url).await?;
            Some(Arc::new(ws))
        } else {
            None
        };

        Ok(Self {
            cfg,
            http,
            ws,
            cp,
            abi: Arc::new(abi),
        })
    }

    /// Compute safe head: try `finalized` block; if not, use `latest - confirmations`.
    pub async fn safe_head(&self) -> Result<u64> {
        // Try finalized tag (supported by modern clients post-Merge)
        // If provider rejects tag, fallback below.
        let finalized = self
            .http
            .get_block(BlockId::Number(BlockNumber::Finalized))
            .await;
        if let Ok(Some(b)) = finalized {
            if let Some(num) = b.number {
                return Ok(num.as_u64());
            }
        }
        // Fallback: latest - confirmations
        let latest = self.http.get_block_number().await?.as_u64();
        let c = self.cfg.confirmations.min(latest);
        Ok(latest - c)
    }

    /// Backfill logs from last checkpoint up to `safe_head`, page by page, with reorg handling.
    pub async fn backfill<F>(&self, mut on_event: F) -> Result<()>
    where
        F: FnMut(DecodedEvent) -> futures::future::BoxFuture<'static, anyhow::Result<()>> + Send,
    {
        let mut from = match self.cp.load().await.map_err(|e| {
            EthAdapterError::Other(format!("checkpoint load error: {e}"))
        })? {
            Some(cp) => cp.block_number.saturating_sub(self.cfg.reorg_rollback),
            None => self.cfg.from_block.unwrap_or(0),
        };

        loop {
            let head = self.safe_head().await?;
            if from > head {
                // nothing to do; let caller decide to sleep or exit
                break;
            }

            let to = (from + self.cfg.max_range).min(head);
            let logs = self.fetch_logs_range(from, to).await?;

            // Verify reorg safety: if we have a previous checkpoint, ensure parent hash matches.
            if let Some(prev) = self.cp.load().await.map_err(|e| {
                EthAdapterError::Other(format!("checkpoint reload error: {e}"))
            })? {
                if prev.block_number >= from {
                    // We rolled back to detect reorg — compare saved block hash with chain.
                    let blk = self
                        .http
                        .get_block(prev.block_number)
                        .await?
                        .ok_or_else(|| EthAdapterError::Other("missing block during reorg check".into()))?;
                    if blk.hash.unwrap_or_default() != prev.block_hash {
                        warn!("reorg detected at block {}", prev.block_number);
                        // Move window further back and retry
                        from = prev.block_number.saturating_sub(self.cfg.reorg_rollback);
                        continue;
                    }
                }
            }

            for log in logs {
                if let Some(decoded) = self.decode_log(&log)? {
                    if let Err(e) = on_event(decoded).await {
                        error!("event handler error: {e}");
                    }
                }
            }

            // Save checkpoint at `to`
            if let Some(blk) = self.http.get_block(to).await? {
                let cp = Checkpoint {
                    block_number: to,
                    block_hash: blk.hash.unwrap_or_default(),
                };
                self.cp.save(cp).await.map_err(|e| {
                    EthAdapterError::Other(format!("checkpoint save error: {e}"))
                })?;
            }

            from = to.saturating_add(1);
        }

        Ok(())
    }

    /// Subscribe to logs via WS (if available). If WS not configured, returns Err.
    pub async fn subscribe_ws(
        &self,
    ) -> Result<SubscriptionStream<'_, Provider<Ws>, Log>> {
        let ws = self
            .ws
            .as_ref()
            .ok_or(EthAdapterError::RpcUnsupported("ws provider not configured"))?;
        let filter = self.build_filter(None, None);
        let sub = ws.subscribe_logs(&filter).await?;
        Ok(sub)
    }

    /// Fetch logs in [from, to] with retry/backoff.
    async fn fetch_logs_range(&self, from: u64, to: u64) -> Result<Vec<Log>> {
        let filter = self.build_filter(Some(from), Some(to));
        let http = self.http.clone();

        let mut backoff = ExponentialBackoff {
            initial_interval: Duration::from_millis(500),
            max_interval: Duration::from_secs(8),
            max_elapsed_time: Some(Duration::from_secs(60)),
            ..ExponentialBackoff::default()
        };

        let res = retry(backoff, || async {
            match http.get_logs(&filter).await {
                Ok(v) => Ok(v),
                Err(e) => {
                    warn!("get_logs failed: {e}; retrying");
                    Err(e)
                }
            }
        })
        .await
        .map_err(EthAdapterError::Provider)?;
        Ok(res)
    }

    /// Build Filter object respecting addresses/topics and block range.
    fn build_filter(&self, from: Option<u64>, to: Option<u64>) -> Filter {
        let mut f = Filter::new();
        if !self.cfg.addresses.is_empty() {
            f = f.address(self.cfg.addresses.clone());
        }
        let t = self.cfg.topics.clone();
        f = f.topic0(t[0]).topic1(t[1]).topic2(t[2]).topic3(t[3]);

        if let (Some(fm), Some(tt)) = (from, to) {
            f = f.select(
                FilterBlockOption::Range {
                    from_block: Some(BlockNumber::Number(fm.into())),
                    to_block: Some(BlockNumber::Number(tt.into())),
                }
            );
        }
        f
    }

    /// Attempt to decode a log using loaded ABI; returns None if event unknown.
    fn decode_log(&self, log: &Log) -> Result<Option<DecodedEvent>> {
        // Match by first topic (event signature) against ABI.
        let topics = log.topics.clone();
        if topics.is_empty() {
            return Ok(None);
        }
        let sig = topics[0];
        let maybe = self
            .abi
            .events()
            .find(|(_, e)| e.signature() == sig)
            .map(|(name, e)| (name.to_string(), e.clone()));
        if let Some((name, ev)) = maybe {
            let raw = RawLog {
                topics,
                data: log.data.0.clone(),
            };
            let parsed = ev
                .parse_log(raw)
                .map_err(|e| EthAdapterError::Abi(e.to_string()))?;
            let mut fields = BTreeMap::new();
            for p in parsed.params {
                // Convert token to JSON for generic handling upstream
                fields.insert(
                    p.name.clone(),
                    serde_json::to_value(ethers::abi::token::LenientTokenizer::token_to_string(&p.value))
                        .unwrap_or_else(|_| serde_json::Value::String(format!("{:?}", p.value))),
                );
            }
            return Ok(Some(DecodedEvent {
                name,
                fields,
                raw: log.clone(),
            }));
        }
        Ok(None)
    }
}

/// Example runner (polling mode):
/// - periodically advances safe head and backfills.
/// - if WS configured, can be used in another task to get near-real-time events.
pub async fn run_polling<S, F>(
    adapter: Arc<EthAdapter<S>>,
    mut on_event: F,
) -> Result<()>
where
    S: CheckpointStore,
    F: FnMut(DecodedEvent) -> futures::future::BoxFuture<'static, anyhow::Result<()>> + Send + 'static,
{
    let mut tick = interval(Duration::from_secs(adapter.cfg.poll_interval_secs));
    loop {
        tick.tick().await;
        if let Err(e) = adapter.backfill(|evt| on_event(evt)).await {
            error!("backfill error: {e}");
            sleep(Duration::from_secs(5)).await;
        }
    }
}
