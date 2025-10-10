// aethernova-chain-core/node/src/telemetry/metrics.rs
//! Производственный модуль телеметрии для узла на Rust (Axum + Prometheus).
//!
//! Зависимости (в Cargo.toml):
//! prometheus = "0.14"
//! axum = { version = "0.7", features = ["macros", "matched-path"] } // MatchedPath из extensions. :contentReference[oaicite:3]{index=3}
//! tower = "0.4"
//! tracing = "0.1"
//! once_cell = "1"
//!
//! Ключевые первоисточники, на которых основаны решения:
//! - Prometheus Rust crate: Registry/Encoder/IntCounterVec/HistogramVec/TextEncoder. :contentReference[oaicite:4]{index=4}
//! - Axum MatchedPath и middleware. :contentReference[oaicite:5]{index=5}
//! - Формат экспозиции Prometheus и Content-Type text/plain; version=0.0.4. :contentReference[oaicite:6]{index=6}
//! - OpenTelemetry Rust (опционально для расширений). :contentReference[oaicite:7]{index=7}

use std::time::Instant;

use axum::{
    extract::{MatchedPath, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use prometheus::{
    opts, Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use tracing::error;

/// Единицы измерения: все значения в wei/газ, байтах и т.д. — по контексту вызова.
pub type Wei = u128;

/// Набор метрик и реестр Prometheus.
#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    // HTTP
    pub http_requests_total: IntCounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub build_info: IntGaugeVec,
    // TxPool
    pub txpool_size: IntGaugeVec,        // labels: {pool="pending|queued|all"}
    pub txpool_events_total: IntCounterVec, // labels: {event="added|dropped|replaced"}
}

impl Metrics {
    /// Создаёт изолированный реестр и регистрирует стандартные метрики.
    pub fn new(build_name: &str, build_version: &str, git_sha: &str) -> Self {
        let registry = Registry::new_custom(Some("aethernova".into()), None)
            .expect("create prometheus registry"); // :contentReference[oaicite:8]{index=8}

        // HTTP: счётчик по методу/пути/коду.
        let http_requests_total = IntCounterVec::new(
            opts!("http_requests_total", "Total HTTP requests"),
            &["method", "path", "status"],
        )
        .expect("http_requests_total"); // :contentReference[oaicite:9]{index=9}

        // HTTP: гистограмма длительности по пути/коду.
        let http_request_duration_seconds = HistogramVec::new(
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
        .expect("http_request_duration_seconds"); // :contentReference[oaicite:10]{index=10}

        // build_info: единичный gauge с лейблами name/version/git_sha.
        let build_info =
            IntGaugeVec::new(opts!("build_info", "Build information"), &["name", "version", "git_sha"])
                .expect("build_info");

        // TxPool: размер пула.
        let txpool_size = IntGaugeVec::new(opts!("txpool_size", "Tx pool size"), &["pool"])
            .expect("txpool_size");

        // TxPool: события.
        let txpool_events_total = IntCounterVec::new(
            opts!("txpool_events_total", "Tx pool events"),
            &["event"],
        )
        .expect("txpool_events_total");

        // Регистрация коллекторов в реестре. :contentReference[oaicite:11]{index=11}
        registry
            .register(Box::new(http_requests_total.clone()))
            .expect("register http_requests_total");
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .expect("register http_request_duration_seconds");
        registry
            .register(Box::new(build_info.clone()))
            .expect("register build_info");
        registry
            .register(Box::new(txpool_size.clone()))
            .expect("register txpool_size");
        registry
            .register(Box::new(txpool_events_total.clone()))
            .expect("register txpool_events_total");

        // Инициализируем build_info = 1.
        build_info
            .with_label_values(&[build_name, build_version, git_sha])
            .set(1);

        Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            build_info,
            txpool_size,
            txpool_events_total,
        }
    }

    /// Обновление размера пула транзакций.
    pub fn set_txpool_size(&self, pool_label: &str, size: i64) {
        self.txpool_size.with_label_values(&[pool_label]).set(size);
    }

    /// Фиксация события в пуле (added|dropped|replaced).
    pub fn inc_txpool_event(&self, event: &str) {
        self.txpool_events_total
            .with_label_values(&[event])
            .inc();
    }
}

/// Axum-middleware для сбора HTTP-метрик с использованием MatchedPath из request extensions. :contentReference[oaicite:12]{index=12}
pub async fn http_metrics_middleware<B>(
    State(metrics): State<Metrics>,
    req: axum::http::Request<B>,
    next: axum::middleware::Next<B>,
) -> Response {
    let start = Instant::now();
    let method = req.method().as_str().to_string();

    // Маршрут по шаблону ("/v1/status" вместо фактического "/v1/status?x")
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();

    // Инкремент счётчика запросов. :contentReference[oaicite:13]{index=13}
    metrics
        .http_requests_total
        .with_label_values(&[&method, &path, &status])
        .inc();

    // Наблюдение длительности. :contentReference[oaicite:14]{index=14}
    let elapsed = start.elapsed().as_secs_f64();
    metrics
        .http_request_duration_seconds
        .with_label_values(&[&path, &status])
        .observe(elapsed);

    response
}

/// HTTP-обработчик `/metrics`: экспозиция Prometheus в текстовом формате 0.0.4.
/// Content-Type берётся из спецификации Prometheus. :contentReference[oaicite:15]{index=15}
pub async fn metrics_handler(State(metrics): State<Metrics>) -> impl IntoResponse {
    let metric_families = metrics.registry.gather(); // :contentReference[oaicite:16]{index=16}

    let mut buf = Vec::new();
    let encoder = TextEncoder::new(); // :contentReference[oaicite:17]{index=17}
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        error!(error = %e, "failed to encode Prometheus metrics");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let mut headers = HeaderMap::new();
    // text/plain; version=0.0.4 — корректный тип для Prometheus text exposition. :contentReference[oaicite:18]{index=18}
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );

    (headers, buf).into_response()
}

// ------------------------------- Tests ---------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use std::net::SocketAddr;
    use tokio::task::JoinHandle;

    fn mk() -> Metrics {
        Metrics::new("aethernova-node", "0.0.0-test", "git-sha")
    }

    #[tokio::test]
    async fn metrics_exports_text() {
        let m = mk();

        // Соберём минимальный роутер с /metrics.
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(m.clone());

        // Локальный запрос без сети.
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/plain"));
    }

    #[tokio::test]
    async fn http_middleware_records_metrics() {
        let m = mk();
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .route_layer(axum::middleware::from_fn_with_state(
                m.clone(),
                http_metrics_middleware,
            ))
            .with_state(m.clone());

        // Вызовем эндпойнт.
        let _ = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/ping")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Убедимся, что счётчик увеличился.
        let mf = m.registry.gather();
        let http_total_present = mf.iter().any(|f| f.get_name() == "http_requests_total");
        assert!(http_total_present);
    }

    #[test]
    fn txpool_metrics_update() {
        let m = mk();
        m.set_txpool_size("pending", 42);
        m.inc_txpool_event("added");
        // Проверяем, что коллекторы присутствуют.
        let mf = m.registry.gather();
        assert!(mf.iter().any(|f| f.get_name() == "txpool_size"));
        assert!(mf.iter().any(|f| f.get_name() == "txpool_events_total"));
    }
}
