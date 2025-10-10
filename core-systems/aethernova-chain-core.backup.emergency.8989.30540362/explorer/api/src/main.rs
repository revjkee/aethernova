// Path: aethernova-chain-core/explorer/api/src/main.rs

//! Aethernova Explorer API (Axum + Tower + SQLx + Prometheus).
//!
//! Features:
//! - Axum 0.7 router; JSON handlers; error normalization.
//! - Tower middleware: request timeout, concurrency limit, compression, CORS, request-id.
//! - Structured JSON logs via tracing-subscriber.
//! - Prometheus metrics via metrics-exporter-prometheus handle at /metrics (with upkeep task).
//! - PostgreSQL connection pool (sqlx) and readiness probe.
//! - Graceful shutdown on SIGINT/SIGTERM.
//!
//! Env vars (reasonable defaults applied):
//!   APP_ADDR                 (default: 0.0.0.0:8080)
//!   APP_REQUEST_TIMEOUT_MS   (default: 5_000)
//!   APP_CONCURRENCY_LIMIT    (default: 1024)
//!   APP_ALLOWED_ORIGINS      (default: *)
//!   APP_DB_URL               (e.g. postgres://user:pass@host:5432/db)
//!
//! Build deps in Cargo.toml (indicative):
//!   axum = "0.7"
//!   tower = { version = "0.5", features = ["limit", "timeout"] }
//!   tower-http = { version = "0.5", features = ["cors", "compression-br", "request-id", "trace", "timeout"] }
//!   tracing = "0.1"
//!   tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
//!   metrics = "0.24"
//!   metrics-exporter-prometheus = "0.17"
//!   sqlx = { version = "0.7", features = ["runtime-tokio", "postgres", "macros", "uuid", "chrono"] }
//!   serde = { version = "1", features = ["derive"] }
//!   serde_json = "1"
//!   tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
//!
//! Notes:
//! - SQL schemas for blocks/transactions are sample; adjust to your DB.
//! - If you use `sqlx::query!` macros with offline feature, provide .sqlx data at build time.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, Router},
    Json,
};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use tokio::signal;
use tower::{limit::ConcurrencyLimitLayer, timeout::TimeoutLayer, ServiceBuilder};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{error, info, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    metrics: PrometheusHandle,
    request_id_header: HeaderName,
}

#[derive(Clone, Debug)]
struct SimpleRequestId;

impl MakeRequestId for SimpleRequestId {
    fn make_request_id<B>(&mut self, _request: &http::Request<B>) -> Option<RequestId> {
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        };
        static COUNTER: once_cell::sync::Lazy<Arc<AtomicU64>> =
            once_cell::sync::Lazy::new(|| Arc::new(AtomicU64::new(1)));
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        Some(RequestId::new(format!("{id:016x}").parse().ok()?))
    }
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    code: u16,
    message: String,
}

#[derive(Debug)]
struct ApiError(anyhow::Error, StatusCode);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.1;
        let body = ApiErrorBody {
            code: status.as_u16(),
            message: self.0.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: String,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Serialize, FromRow)]
struct Block {
    hash: String,
    height: i64,
    time: chrono::DateTime<chrono::Utc>,
    tx_count: i64,
}

#[derive(Debug, Serialize, FromRow)]
struct Tx {
    hash: String,
    block_hash: String,
    index: i32,
    from_addr: Option<String>,
    to_addr: Option<String>,
    value: Option<String>,
    fee: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::from_env()?;
    info!(?cfg, "starting Aethernova Explorer API");

    // Metrics: recorder + upkeep handle; we choose install_recorder + manual upkeep.
    // According to docs, install_recorder returns a PrometheusHandle for manual render
    // and requires calling run_upkeep periodically. :contentReference[oaicite:1]{index=1}
    let recorder_handle = PrometheusBuilder::new().install_recorder()?;
    // Spawn upkeep loop.
    {
        let handle = recorder_handle.clone();
        tokio::spawn(async move {
            // run_upkeep should be called periodically to drain histograms, etc. :contentReference[oaicite:2]{index=2}
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                handle.run_upkeep();
            }
        });
    }

    // DB pool (sqlx::Pool) with timeouts. :contentReference[oaicite:3]{index=3}
    let pool = PgPoolOptions::new()
        .max_connections(32)
        .min_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.db_url)
        .await?;

    // State
    let state = AppState {
        pool,
        metrics: recorder_handle,
        request_id_header: HeaderName::from_static("x-request-id"),
    };

    // Router
    let app = Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/metrics", get(metrics_handler))
        .route("/api/v1/blocks/:hash", get(get_block))
        .route("/api/v1/tx/:hash", get(get_tx))
        .route("/api/v1/search", get(search))
        .with_state(state.clone())
        // Tower middleware stack:
        // Timeout for requests (Tower TimeoutLayer). :contentReference[oaicite:4]{index=4}
        // Concurrency limit (Tower ConcurrencyLimitLayer). :contentReference[oaicite:5]{index=5}
        // CORS (tower-http). :contentReference[oaicite:6]{index=6}
        // Compression (tower-http). :contentReference[oaicite:7]{index=7}
        // Request-Id set/propagate (tower-http). :contentReference[oaicite:8]{index=8}
        // Trace layer around requests (tower-http TraceLayer).
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(cors_from_env(&cfg)?)
                .layer(ConcurrencyLimitLayer::new(cfg.concurrency_limit as usize))
                .layer(TimeoutLayer::new(Duration::from_millis(
                    cfg.request_timeout_ms as u64,
                )))
                .layer(PropagateRequestIdLayer::new(state.request_id_header.clone()))
                .layer(SetRequestIdLayer::new(
                    state.request_id_header.clone(),
                    SimpleRequestId,
                )),
        );

    // Bind address
    let addr: SocketAddr = cfg.addr.parse()?;

    // Axum runs atop Hyper with Tower service layers. :contentReference[oaicite:9]{index=9}
    let server = axum::Server::bind(&addr).serve(app.into_make_service());

    info!(%addr, "listening");

    // Graceful shutdown on SIGINT/SIGTERM. :contentReference[oaicite:10]{index=10}
    let graceful = server.with_graceful_shutdown(shutdown_signal());
    if let Err(e) = graceful.await {
        error!(error = ?e, "server error");
    }

    info!("stopped");
    Ok(())
}

fn init_tracing() {
    // JSON logs for production via tracing-subscriber. :contentReference[oaicite:11]{index=11}
    let fmt_layer = fmt::layer()
        .with_level(true)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .event_format(fmt::format().json());

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,sqlx=warn"));

    Registry::default().with(env_filter).with(fmt_layer).init();
}

#[derive(Clone, Debug)]
struct Config {
    addr: String,
    request_timeout_ms: u64,
    concurrency_limit: u32,
    allowed_origins: AllowedOrigins,
    db_url: String,
}

#[derive(Clone, Debug)]
enum AllowedOrigins {
    Any,
    List(Vec<HeaderValue>),
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let addr = std::env::var("APP_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let request_timeout_ms = std::env::var("APP_REQUEST_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5_000);
        let concurrency_limit = std::env::var("APP_CONCURRENCY_LIMIT")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1024);
        let allowed_origins = match std::env::var("APP_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "*".to_string())
            .as_str()
        {
            "*" => AllowedOrigins::Any,
            csv => AllowedOrigins::List(
                csv.split(',')
                    .filter_map(|s| HeaderValue::from_str(s.trim()).ok())
                    .collect(),
            ),
        };
        let db_url = std::env::var("APP_DB_URL")
            .map_err(|_| anyhow::anyhow!("APP_DB_URL is required (postgres://...)"))?;
        Ok(Self {
            addr,
            request_timeout_ms,
            concurrency_limit,
            allowed_origins,
            db_url,
        })
    }
}

fn cors_from_env(cfg: &Config) -> anyhow::Result<CorsLayer> {
    let mut layer = CorsLayer::new()
        .allow_methods([Method::GET])
        .allow_headers([HeaderName::from_static("x-request-id")]);
    layer = match &cfg.allowed_origins {
        AllowedOrigins::Any => layer.allow_origin(Any),
        AllowedOrigins::List(v) => layer.allow_origin(v.clone()),
    };
    Ok(layer)
}

// ------------------- Handlers -------------------

async fn liveness() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readiness(State(app): State<AppState>) -> ApiResult<impl IntoResponse> {
    // Lightweight readiness: SELECT 1.
    // sqlx::Pool::acquire + simple query.
    let mut conn = app
        .pool
        .acquire()
        .await
        .map_err(|e| ApiError(e.into(), StatusCode::SERVICE_UNAVAILABLE))?;
    let row: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| ApiError(e.into(), StatusCode::SERVICE_UNAVAILABLE))?;
    if row.0 == 1 {
        Ok((StatusCode::OK, "ready"))
    } else {
        Err(ApiError(
            anyhow::anyhow!("DB check failed"),
            StatusCode::SERVICE_UNAVAILABLE,
        ))
    }
}

async fn metrics_handler(State(app): State<AppState>) -> impl IntoResponse {
    // Render Prometheus exposition format via handle. :contentReference[oaicite:12]{index=12}
    let body = app.metrics.render();
    (StatusCode::OK, body)
}

async fn get_block(
    State(app): State<AppState>,
    Path(hash): Path<String>,
) -> ApiResult<Json<Block>> {
    histogram!("api.request.duration_ms", "endpoint" => "get_block");
    let blk = sqlx::query_as::<_, Block>(
        r#"
        SELECT hash, height, time, tx_count
        FROM blocks
        WHERE hash = $1
        "#,
    )
    .bind(&hash)
    .fetch_optional(&app.pool)
    .await
    .map_err(|e| ApiError(e.into(), StatusCode::INTERNAL_SERVER_ERROR))?
    .ok_or_else(|| ApiError(anyhow::anyhow!("block not found"), StatusCode::NOT_FOUND))?;

    counter!("api.request.ok", 1, "endpoint" => "get_block");
    Ok(Json(blk))
}

async fn get_tx(State(app): State<AppState>, Path(hash): Path<String>) -> ApiResult<Json<Tx>> {
    histogram!("api.request.duration_ms", "endpoint" => "get_tx");
    let tx = sqlx::query_as::<_, Tx>(
        r#"
        SELECT hash, block_hash, index, from_addr, to_addr, value, fee
        FROM transactions
        WHERE hash = $1
        "#,
    )
    .bind(&hash)
    .fetch_optional(&app.pool)
    .await
    .map_err(|e| ApiError(e.into(), StatusCode::INTERNAL_SERVER_ERROR))?
    .ok_or_else(|| ApiError(anyhow::anyhow!("tx not found"), StatusCode::NOT_FOUND))?;

    counter!("api.request.ok", 1, "endpoint" => "get_tx");
    Ok(Json(tx))
}

async fn search(
    State(app): State<AppState>,
    Query(q): Query<SearchQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let offset = q.offset.unwrap_or(0).max(0);

    // Heuristic: if hex length matches, try exact match by hash.
    if q.q.len() == 64 && q.q.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(b) = sqlx::query_as::<_, Block>(
            "SELECT hash, height, time, tx_count FROM blocks WHERE hash = $1",
        )
        .bind(&q.q)
        .fetch_optional(&app.pool)
        .await
        .map_err(|e| ApiError(e.into(), StatusCode::INTERNAL_SERVER_ERROR))?
        {
            return Ok(Json(serde_json::json!({ "type": "block", "block": b })));
        }
        if let Some(t) = sqlx::query_as::<_, Tx>(
            "SELECT hash, block_hash, index, from_addr, to_addr, value, fee FROM transactions WHERE hash = $1",
        )
        .bind(&q.q)
        .fetch_optional(&app.pool)
        .await
        .map_err(|e| ApiError(e.into(), StatusCode::INTERNAL_SERVER_ERROR))?
        {
            return Ok(Json(serde_json::json!({ "type": "tx", "tx": t })));
        }
    }

    // Fallback: prefix search by address in txs.
    let rows: Vec<Tx> = sqlx::query_as(
        r#"
        SELECT hash, block_hash, index, from_addr, to_addr, value, fee
        FROM transactions
        WHERE (from_addr ILIKE $1 OR to_addr ILIKE $1)
        ORDER BY index DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(format!("{}%", q.q))
    .bind(limit)
    .bind(offset)
    .fetch_all(&app.pool)
    .await
    .map_err(|e| ApiError(e.into(), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(serde_json::json!({
        "type": "tx_list",
        "limit": limit,
        "offset": offset,
        "items": rows
    })))
}

async fn shutdown_signal() {
    // SIGINT or SIGTERM. Recommended approach in Tokio. :contentReference[oaicite:13]{index=13}
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        term.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}
