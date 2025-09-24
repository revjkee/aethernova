//! Aethernova Explorer Indexer (industrial-grade single-binary).
//!
//! Features:
//! - Config via CLI and environment (clap).
//! - Structured logging (tracing) with JSON output by default.
//! - Prometheus metrics exporter on optional HTTP socket (/metrics).
//! - PostgreSQL (sqlx) with schema bootstrap and idempotent UPSERTs.
//! - JSON-RPC polling with confirmations, batching, bounded concurrency.
//! - Exponential backoff with jitter for RPC/DB failures.
//! - Checkpointing in DB (indexer_state) to resume safely.
//! - Graceful shutdown on SIGINT/SIGTERM.

use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use clap::Parser;
use futures::{stream, StreamExt, TryStreamExt};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{error, info, warn, Level};
use tracing_subscriber::{fmt, EnvFilter};

use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};

/// ---- CLI / Config ----

#[derive(Clone, Debug, Parser)]
#[command(name = "aethernova-explorer-indexer", author, version, about)]
struct Config {
    /// Ethereum JSON-RPC HTTP endpoint, e.g. http://127.0.0.1:8545
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// Postgres DSN, e.g. postgres://user:pass@host:5432/db
    #[arg(long, env = "DATABASE_URL")]
    db_url: String,

    /// Start block if no checkpoint present.
    #[arg(long, env = "START_BLOCK", default_value = "0")]
    start_block: u64,

    /// Number of confirmations to wait before indexing a block.
    #[arg(long, env = "CONFIRMATIONS", default_value = "12")]
    confirmations: u64,

    /// Max blocks to index per loop iteration.
    #[arg(long, env = "BATCH_SIZE", default_value = "25")]
    batch_size: u64,

    /// Max concurrent RPC requests per batch.
    #[arg(long, env = "CONCURRENCY", default_value = "4")]
    concurrency: usize,

    /// Poll interval when head is not far enough.
    #[arg(long, env = "POLL_INTERVAL_MS", default_value = "1500")]
    poll_interval_ms: u64,

    /// Optional Prometheus exporter bind address, e.g. 0.0.0.0:9100
    #[arg(long, env = "METRICS_BIND")]
    metrics_bind: Option<SocketAddr>,

    /// Indexer name for checkpointing.
    #[arg(long, env = "INDEXER_NAME", default_value = "explorer-indexer")]
    indexer_name: String,

    /// Log level (RUST_LOG overrides), e.g. info,debug,trace
    #[arg(long, env = "LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Pretty (human) logs instead of JSON
    #[arg(long, env = "LOG_PRETTY", default_value = "false")]
    log_pretty: bool,
}

/// ---- Telemetry (metrics) ----
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

async fn init_metrics(bind: Option<SocketAddr>) {
    let builder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full("indexer_latency_seconds".into()),
            &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        )
        .unwrap_or_else(|b| b);

    let handle = builder
        .add_global_label("service", "aethernova-explorer-indexer")
        .install_recorder()
        .expect("failed to install metrics recorder");

    if let Some(addr) = bind {
        tokio::spawn(async move {
            use hyper::service::{make_service_fn, service_fn};
            use hyper::{Body, Method, Request, Response, Server, StatusCode};

            let make_svc = make_service_fn(move |_conn| {
                let handle = handle.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                        let handle = handle.clone();
                        async move {
                            match (req.method(), req.uri().path()) {
                                (&Method::GET, "/metrics") => {
                                    let body = handle.render();
                                    Ok::<_, hyper::Error>(
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .header("Content-Type", "text/plain; version=0.0.4")
                                            .body(Body::from(body))
                                            .unwrap(),
                                    )
                                }
                                _ => Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Body::from("Not Found"))
                                        .unwrap(),
                                ),
                            }
                        }
                    }))
                }
            });

            let server = Server::bind(&addr).serve(make_svc);
            if let Err(e) = server.await {
                eprintln!("metrics HTTP server error: {e}");
            }
        });
    }
}

/// ---- Logging ----

fn init_tracing(cfg: &Config) {
    let env_filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(cfg.log_level.clone())
    };

    if cfg.log_pretty {
        let fmt_layer = fmt::layer().with_target(true).with_line_number(true);
        tracing_subscriber::registry().with(env_filter).with(fmt_layer).init();
    } else {
        let fmt_layer = fmt::layer()
            .event_format(fmt::format().json().flatten_event(true))
            .with_target(true)
            .with_line_number(true)
            .with_file(true)
            .with_timer(fmt::time::UtcTime::rfc_3339());
        tracing_subscriber::registry().with(env_filter).with(fmt_layer).init();
    }
}

/// ---- JSON-RPC Types ----

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
    #[allow(dead_code)]
    data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Clone, Deserialize)]
struct EthTx {
    hash: String,
    nonce: String,
    from: String,
    to: Option<String>,
    value: String,
    gas: String,
    gasPrice: Option<String>,
    maxFeePerGas: Option<String>,
    maxPriorityFeePerGas: Option<String>,
    input: String,
    transactionIndex: String,
    blockHash: String,
    blockNumber: String,
}

#[derive(Debug, Clone, Deserialize)]
struct EthBlock {
    number: String,
    hash: String,
    parentHash: String,
    timestamp: String,
    gasUsed: String,
    gasLimit: String,
    baseFeePerGas: Option<String>,
    transactions: Vec<EthTx>,
}

/// ---- RPC Client ----

#[derive(Clone)]
struct RpcClient {
    http: reqwest::Client,
    url: String,
    rng: Arc<tokio::sync::Mutex<StdRng>>,
}

impl RpcClient {
    fn new(url: String) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("http client"),
            url,
            rng: Arc::new(tokio::sync::Mutex::new(StdRng::from_entropy())),
        }
    }

    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<T> {
        let id: u64 = {
            let mut r = self.rng.lock().await;
            r.gen()
        };
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let mut attempt = 0u32;
        loop {
            let res = self.http.post(&self.url).json(&req).send().await;
            match res {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    if !status.is_success() {
                        attempt += 1;
                        let dur = backoff(attempt);
                        warn!(target: "rpc", %status, method, attempt, "rpc http error; retrying in {:?}: {}", dur, text);
                        sleep(dur).await;
                        continue;
                    }
                    let parsed: RpcResponse<T> = serde_json::from_str(&text)?;
                    if let Some(err) = parsed.error {
                        attempt += 1;
                        let dur = backoff(attempt);
                        warn!(target: "rpc", code=%err.code, method, attempt, "rpc error; retrying in {:?}", dur);
                        sleep(dur).await;
                        continue;
                    }
                    if let Some(result) = parsed.result {
                        return Ok(result);
                    }
                    attempt += 1;
                    let dur = backoff(attempt);
                    warn!(target: "rpc", method, attempt, "rpc empty result; retrying in {:?}", dur);
                    sleep(dur).await;
                }
                Err(e) => {
                    attempt += 1;
                    let dur = backoff(attempt);
                    warn!(target: "rpc", error=%e, method, attempt, "rpc transport error; retrying in {:?}", dur);
                    sleep(dur).await;
                }
            }
        }
    }

    async fn head_block_number(&self) -> anyhow::Result<u64> {
        let hex: String = self.call("eth_blockNumber", json!([])).await?;
        Ok(hex_to_u64(&hex))
    }

    async fn get_block_by_number(&self, n: u64) -> anyhow::Result<EthBlock> {
        let hex_n = format!("0x{:x}", n);
        self.call("eth_getBlockByNumber", json!([hex_n, true])).await
    }
}

/// ---- DB Schema & IO ----

async fn bootstrap_schema(pool: &PgPool) -> anyhow::Result<()> {
    // Keep simple types; numeric for big values.
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS blocks (
          hash TEXT PRIMARY KEY,
          number BIGINT UNIQUE NOT NULL,
          parent_hash TEXT NOT NULL,
          timestamp BIGINT NOT NULL,
          gas_used NUMERIC NOT NULL,
          gas_limit NUMERIC NOT NULL,
          base_fee NUMERIC,
          tx_count INT NOT NULL
        );
        "#,
    )
    .execute(&mut tx)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS transactions (
          hash TEXT PRIMARY KEY,
          block_hash TEXT NOT NULL REFERENCES blocks(hash) ON DELETE CASCADE,
          block_number BIGINT NOT NULL,
          tx_index INT NOT NULL,
          "from" TEXT NOT NULL,
          "to" TEXT,
          value NUMERIC NOT NULL,
          gas NUMERIC NOT NULL,
          gas_price NUMERIC,
          max_fee_per_gas NUMERIC,
          max_priority_fee_per_gas NUMERIC,
          input TEXT NOT NULL
        );
        "#,
    )
    .execute(&mut tx)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS indexer_state (
          id TEXT PRIMARY KEY,
          last_block BIGINT NOT NULL
        );
        "#,
    )
    .execute(&mut tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

async fn load_checkpoint(pool: &PgPool, name: &str) -> anyhow::Result<Option<u64>> {
    let row = sqlx::query("SELECT last_block FROM indexer_state WHERE id = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("last_block") as u64))
}

async fn save_checkpoint(tx: &mut Transaction<'_, Postgres>, name: &str, last_block: u64) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO indexer_state (id, last_block)
        VALUES ($1, $2)
        ON CONFLICT (id) DO UPDATE SET last_block = EXCLUDED.last_block
        "#,
    )
    .bind(name)
    .bind(last_block as i64)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

use sqlx::Row;

async fn upsert_block_and_txs(
    tx: &mut Transaction<'_, Postgres>,
    b: &EthBlock,
) -> anyhow::Result<()> {
    let number = hex_to_u64(&b.number) as i64;
    let ts = hex_to_u64(&b.timestamp) as i64;
    let gas_used = hex_to_u128(&b.gasUsed).to_string();
    let gas_limit = hex_to_u128(&b.gasLimit).to_string();
    let base_fee = b.baseFeePerGas.as_ref().map(|x| hex_to_u128(x).to_string());

    sqlx::query(
        r#"
        INSERT INTO blocks (hash, number, parent_hash, timestamp, gas_used, gas_limit, base_fee, tx_count)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (hash) DO NOTHING
        "#,
    )
    .bind(&b.hash)
    .bind(number)
    .bind(&b.parentHash)
    .bind(ts)
    .bind(&gas_used)
    .bind(&gas_limit)
    .bind(&base_fee)
    .bind(b.transactions.len() as i32)
    .execute(&mut *tx)
    .await?;

    // Insert transactions
    for t in &b.transactions {
        let bn = hex_to_u64(&t.blockNumber) as i64;
        let idx = hex_to_u64(&t.transactionIndex) as i32;
        let val = hex_to_u128(&t.value).to_string();
        let gas = hex_to_u128(&t.gas).to_string();
        let gas_price = t.gasPrice.as_ref().map(|x| hex_to_u128(x).to_string());
        let max_fee = t.maxFeePerGas.as_ref().map(|x| hex_to_u128(x).to_string());
        let max_prio = t
            .maxPriorityFeePerGas
            .as_ref()
            .map(|x| hex_to_u128(x).to_string());

        sqlx::query(
            r#"
            INSERT INTO transactions
              (hash, block_hash, block_number, tx_index, "from", "to", value, gas, gas_price, max_fee_per_gas, max_priority_fee_per_gas, input)
            VALUES
              ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            ON CONFLICT (hash) DO NOTHING
            "#,
        )
        .bind(&t.hash)
        .bind(&t.blockHash)
        .bind(bn)
        .bind(idx)
        .bind(&t.from)
        .bind(&t.to)
        .bind(&val)
        .bind(&gas)
        .bind(&gas_price)
        .bind(&max_fee)
        .bind(&max_prio)
        .bind(&t.input)
        .execute(&mut *tx)
        .await?;
    }

    Ok(())
}

/// ---- Helpers ----

fn hex_to_u64(s: &str) -> u64 {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).unwrap_or(0)
}
fn hex_to_u128(s: &str) -> u128 {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(s, 16).unwrap_or(0)
}

fn backoff(attempt: u32) -> Duration {
    // cap at ~5s + jitter
    let base_ms = 50u64.saturating_mul(1u64.saturating_shl(attempt.min(7)));
    let jitter = rand::thread_rng().gen_range(0..50);
    Duration::from_millis((base_ms + jitter).min(5_000))
}

/// ---- Indexing Loop ----

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();

    init_tracing(&cfg);
    init_metrics(cfg.metrics_bind).await;

    info!(version = env!("CARGO_PKG_VERSION"), "starting indexer");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&cfg.db_url)
        .await?;

    bootstrap_schema(&pool).await?;

    let rpc = RpcClient::new(cfg.rpc_url.clone());
    let poll_interval = Duration::from_millis(cfg.poll_interval_ms);
    let sem = Arc::new(Semaphore::new(cfg.concurrency));

    let mut shutdown = shutdown_signal();

    let start_block = if let Some(cp) = load_checkpoint(&pool, &cfg.indexer_name).await? {
        cp.saturating_add(1)
    } else {
        cfg.start_block
    };
    gauge!("indexer_start_block", start_block as f64);

    let mut next: u64 = start_block;

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received; exiting loop");
                break;
            }
            res = tick_iteration(&cfg, &pool, &rpc, &sem, next) => {
                match res {
                    Ok(Some(advanced_to)) => {
                        next = advanced_to;
                    }
                    Ok(None) => {
                        // head not far enough; wait
                        sleep(poll_interval).await;
                    }
                    Err(e) => {
                        error!(error=%e, "iteration error");
                        sleep(backoff(3)).await;
                    }
                }
            }
        }
    }

    info!("indexer stopped");
    Ok(())
}

/// One iteration: determine head-<confirmations>, process [next..end] if possible.
/// Returns Some(new_next) if advanced, None if slept.
async fn tick_iteration(
    cfg: &Config,
    pool: &PgPool,
    rpc: &RpcClient,
    sem: &Arc<Semaphore>,
    next: u64,
) -> anyhow::Result<Option<u64>> {
    let head = rpc.head_block_number().await?;
    if head < cfg.confirmations {
        return Ok(None);
    }
    let safe_head = head - cfg.confirmations;
    if next > safe_head {
        // nothing to do yet
        return Ok(None);
    }

    let end = std::cmp::min(next + cfg.batch_size - 1, safe_head);
    let span = end - next + 1;
    info!(next, end, head, safe_head, span, "indexing batch");

    histogram!("indexer_batch_size", span as f64);
    counter!("indexer_batches_total", 1);

    // Fetch blocks concurrently with a semaphore
    let block_numbers: Vec<u64> = (next..=end).collect();
    let blocks: Vec<EthBlock> = stream::iter(block_numbers)
        .map(|n| {
            let rpc = rpc.clone();
            let sem = sem.clone();
            async move {
                let _permit = sem.acquire_owned().await.expect("semaphore");
                rpc.get_block_by_number(n).await
            }
        })
        .buffer_unordered(cfg.concurrency)
        .try_collect()
        .await?;

    let mut tx = pool.begin().await?;
    for b in &blocks {
        upsert_block_and_txs(&mut tx, b).await?;
    }
    save_checkpoint(&mut tx, &cfg.indexer_name, end).await?;
    tx.commit().await?;

    gauge!("indexer_last_block", end as f64);
    counter!("indexer_blocks_total", blocks.len() as u64);

    Ok(Some(end.saturating_add(1)))
}

/// Shutdown signal combiner (Ctrl+C and SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("ctrl_c");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("sigterm");
        sigterm.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
