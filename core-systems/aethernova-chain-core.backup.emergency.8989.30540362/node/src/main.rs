// aethernova-chain-core/node/src/main.rs
//! Production-grade каркас узла на Rust: Tokio + Axum + Tracing + Prometheus.
//!
//! Зависимости (в Cargo.toml):
//! tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
//! axum = { version = "0.7", features = ["macros"] }
//! tower = "0.4"
//! tower-http = { version = "0.5", features = ["trace", "timeout"] }
//! tracing = "0.1"
//! tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
//! clap = { version = "4", features = ["derive", "env"] }
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! prometheus = "0.13"
//! once_cell = "1"
//!
//! Ключевые паттерны подтверждены официальной документацией Axum/Tokio/Tracing/Prometheus.
//! - Router/TraceLayer: docs.rs Axum.  :contentReference[oaicite:3]{index=3}
//! - Graceful shutdown: Tokio guide.   :contentReference[oaicite:4]{index=4}
//! - EnvFilter для уровней логов.      :contentReference[oaicite:5]{index=5}
//! - Prometheus TextEncoder/Registry.  :contentReference[oaicite:6]{index=6}
//! - axum::serve.with_graceful_shutdown. :contentReference[oaicite:7]{index=7}

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use once_cell::sync::Lazy;
use prometheus::{
    opts, Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder,
};
use tokio::net::TcpListener;
use tower::{limit::ConcurrencyLimitLayer, ServiceBuilder};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{error, info, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Конфигурация процесса (CLI + ENV).
#[derive(Clone, Debug, Parser)]
#[command(name = "aethernova-node", version, disable_help_flag = false)]
struct AppConfig {
    /// HTTP bind адрес для административного / health / metrics API.
    #[arg(long, env = "AE_HTTP_BIND", default_value = "0.0.0.0:8080")]
    http_bind: SocketAddr,

    /// Таймаут обработки одного запроса.
    #[arg(long, env = "AE_HTTP_TIMEOUT_SECS", default_value_t = 15)]
    http_timeout_secs: u64,

    /// Максимальная конкурентность (лимит параллельных запросов).
    #[arg(long, env = "AE_MAX_CONCURRENCY", default_value_t = 1024)]
    max_concurrency: usize,

    /// Задержка перед установкой готовности (readiness) после старта.
    #[arg(long, env = "AE_READINESS_DELAY_SECS", default_value_t = 5)]
    readiness_delay_secs: u64,

    /// Формат логов: "json" или "pretty".
    #[arg(long, env = "AE_LOG_FORMAT", default_value = "json")]
    log_format: String,

    /// Уровень логирования (EnvFilter), например: "info,axum::rejection=trace".
    #[arg(long, env = "AE_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

/// Глобальные константы сборки.
static BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");
static BUILD_NAME: &str = env!("CARGO_PKG_NAME");
static BUILD_GIT_SHA: Option<&'static str> = option_env!("GIT_SHA");

/// Состояние приложения с метриками.
#[derive(Clone)]
struct AppState {
    start_instant: Instant,
    ready: Arc<AtomicBool>,
    registry: Arc<Registry>,
    http_requests_total: IntCounterVec,
    http_requests_duration: HistogramVec,
    build_info: IntGaugeVec,
}

impl AppState {
    fn new() -> Self {
        let registry = Arc::new(Registry::new_custom(Some("aethernova".into()), None).unwrap());

        // Счётчик запросов по методу/пути/коду.
        let http_requests_total = IntCounterVec::new(
            opts!("http_requests_total", "Total HTTP requests"),
            &["method", "path", "status"],
        )
        .expect("http_requests_total");

        // Гистограмма длительности запросов по пути/коду (в секундах).
        let http_requests_duration = HistogramVec::new(
            HistogramOpts {
                common_opts: Opts::new(
                    "http_request_duration_seconds",
                    "HTTP request duration seconds",
                ),
                buckets: vec![
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ],
            },
            &["path", "status"],
        )
        .expect("http_request_duration_seconds");

        // build_info: лейблы version/git_sha со значением 1.
        let build_info = IntGaugeVec::new(
            opts!("build_info", "Build information"),
            &["name", "version", "git_sha"],
        )
        .expect("build_info");

        registry
            .register(Box::new(http_requests_total.clone()))
            .expect("register http_requests_total");
        registry
            .register(Box::new(http_requests_duration.clone()))
            .expect("register http_request_duration_seconds");
        registry
            .register(Box::new(build_info.clone()))
            .expect("register build_info");

        // Инициализируем build_info=1.
        build_info
            .with_label_values(&[
                BUILD_NAME,
                BUILD_VERSION,
                BUILD_GIT_SHA.unwrap_or("unknown"),
            ])
            .set(1);

        Self {
            start_instant: Instant::now(),
            ready: Arc::new(AtomicBool::new(false)),
            registry,
            http_requests_total,
            http_requests_duration,
            build_info,
        }
    }
}

/// Middleware: учёт метрик по каждому запросу.
async fn metrics_middleware<B>(
    State(state): State<AppState>,
    mut req: Request<B>,
    next: axum::middleware::Next<B>,
) -> Response {
    let start = Instant::now();
    // Маркируем путь по роут-паттерну (MatchedPath), иначе берём сырой путь.
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let method = req.method().as_str().to_string();
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();

    // Инкремент счётчика.
    state
        .http_requests_total
        .with_label_values(&[&method, &path, &status])
        .inc();

    // Наблюдение длительности.
    let elapsed = start.elapsed().as_secs_f64();
    state
        .http_requests_duration
        .with_label_values(&[&path, &status])
        .observe(elapsed);

    response
}

/// GET /healthz/live — всегда ОК (процесс жив).
async fn live() -> impl IntoResponse {
    StatusCode::OK
}

/// GET /healthz/ready — ОК после readiness-delay.
async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    if state.ready.load(Ordering::Relaxed) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// GET /metrics — экспозиция Prometheus.
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let metric_families = state.registry.gather();
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        error!(error = %e, "failed to encode Prometheus metrics");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    (headers, buf).into_response()
}

/// GET /v1/status — минимальный статус процесса.
#[derive(serde::Serialize)]
struct StatusPayload<'a> {
    name: &'a str,
    version: &'a str,
    git_sha: &'a str,
    uptime_seconds: u64,
}
async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let payload = StatusPayload {
        name: BUILD_NAME,
        version: BUILD_VERSION,
        git_sha: BUILD_GIT_SHA.unwrap_or("unknown"),
        uptime_seconds: state.start_instant.elapsed().as_secs(),
    };
    Json(payload)
}

/// POST /v1/rpc — заглушка RPC-шлюза (реализация прокси — отдельно).
async fn rpc_stub() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "RPC upstream не сконфигурирован",
    )
}

/// Инициализация логирования (tracing + EnvFilter).
fn init_tracing(cfg: &AppConfig) {
    let env_filter = EnvFilter::new(cfg.log_level.clone());

    match cfg.log_format.as_str() {
        "pretty" => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_target(true))
                .init();
        }
        _ => {
            // JSON по умолчанию — структурированные логи.
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_target(true))
                .init();
        }
    }

    info!(
        name = BUILD_NAME,
        version = BUILD_VERSION,
        git_sha = BUILD_GIT_SHA.unwrap_or("unknown"),
        "tracing initialized"
    );
}

/// Ожидание сигналов для корректного завершения.
/// Паттерн соответствует рекомендациям Tokio. :contentReference[oaicite:8]{index=8}
async fn shutdown_signal() {
    // Ctrl+C
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    // SIGTERM (Unix)
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        term.recv().await;
    };

    // На Windows SIGTERM нет — ждём только Ctrl+C.
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cfg = AppConfig::parse();
    init_tracing(&cfg);

    // Состояние и readiness-флаг с отложенной установкой.
    let state = AppState::new();
    let ready = state.ready.clone();
    let readiness_delay = cfg.readiness_delay_secs;
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(readiness_delay)).await;
        ready.store(true, Ordering::Relaxed);
        info!("readiness set to true");
    });

    // Маршруты.
    let app = Router::new()
        .route("/healthz/live", get(live))
        .route("/healthz/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/rpc", post(rpc_stub))
        .with_state(state.clone())
        // Глобальные middleware: трассировка, лимит конкурентности, таймауты, сбор метрик
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http()) // Axum/Tower TraceLayer. :contentReference[oaicite:9]{index=9}
                .layer(ConcurrencyLimitLayer::new(cfg.max_concurrency))
                .layer(TimeoutLayer::new(Duration::from_secs(
                    cfg.http_timeout_secs,
                )))
                .into_inner(),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            metrics_middleware,
        ));

    // Прослушивание и сервер с graceful shutdown. :contentReference[oaicite:10]{index=10}
    let listener = TcpListener::bind(cfg.http_bind).await?;
    info!(bind = %cfg.http_bind, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("server stopped");
    Ok(())
}
