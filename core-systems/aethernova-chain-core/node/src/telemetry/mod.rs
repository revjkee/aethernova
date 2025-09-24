//! Telemetry module: structured logs + Prometheus metrics for Aethernova node.
//!
//! - Structured logging via `tracing` (JSON or pretty).
//! - Prometheus recorder via `metrics-exporter-prometheus`.
//! - Optional /metrics HTTP endpoint (requires `hyper` feature enabled in crate).
//! - Thread-safe handle with graceful shutdown.
//! - Helper APIs for counters/gauges/histograms and timing scopes.
//!
//! This module is `no_std`-free and uses only safe Rust.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

#[cfg(feature = "tracing")]
use tracing::{info, warn};

#[cfg(feature = "tracing")]
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

#[cfg(feature = "metrics")]
use metrics::{counter, gauge, histogram, Unit};

#[cfg(feature = "metrics")]
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

#[cfg(all(feature = "metrics", feature = "rpc"))]
use {
    hyper::body::Bytes,
    hyper::service::{make_service_fn, service_fn},
    hyper::{Body, Method, Request, Response, Server, StatusCode},
    tokio::sync::oneshot,
    tokio::task::JoinHandle,
};

/// Log formatting mode.
#[derive(Clone, Debug)]
pub enum LogFormat {
    Json,
    Pretty,
}

/// Telemetry configuration (immutable).
#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    pub service_name: String,
    pub service_version: String,
    pub environment: String, // e.g., dev|staging|prod
    pub instance_id: String, // e.g., hostname or GUID
    pub log_level: String,   // e.g., "info,hyper=warn"
    pub log_format: LogFormat,
    pub enable_metrics: bool,
    /// If Some(addr) and HTTP available, exposes /metrics on that address.
    pub metrics_bind: Option<SocketAddr>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "aethernova-node".into(),
            service_version: "0.1.0".into(),
            environment: "dev".into(),
            instance_id: "local".into(),
            log_level: "info".into(),
            log_format: LogFormat::Json,
            enable_metrics: true,
            metrics_bind: None,
        }
    }
}

/// Graceful shutdown guard and accessors.
pub struct Telemetry {
    #[cfg(feature = "metrics")]
    prom: Option<PrometheusHandle>,
    #[cfg(all(feature = "metrics", feature = "rpc"))]
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    #[cfg(all(feature = "metrics", feature = "rpc"))]
    http_task: Option<JoinHandle<()>>,
}

impl Telemetry {
    /// Initialize logging + metrics according to config.
    pub fn init(cfg: TelemetryConfig) -> Result<Self> {
        install_tracing(&cfg)?;
        #[cfg(feature = "metrics")]
        {
            let prom = install_metrics(&cfg)?;
            let mut tel = Telemetry {
                prom: Some(prom.clone()),
                #[cfg(all(feature = "metrics", feature = "rpc"))]
                shutdown_tx: None,
                #[cfg(all(feature = "metrics", feature = "rpc"))]
                http_task: None,
            };

            // Spawn /metrics HTTP if requested and HTTP stack available.
            #[cfg(all(feature = "metrics", feature = "rpc"))]
            if let Some(addr) = cfg.metrics_bind {
                let (tx, rx) = oneshot::channel();
                let handle = spawn_metrics_http(prom, addr, rx)?;
                tel.shutdown_tx = Some(tx);
                tel.http_task = Some(handle);
            }

            #[cfg(feature = "tracing")]
            info!(target: "telemetry", service=%cfg.service_name, version=%cfg.service_version, env=%cfg.environment, "telemetry initialized");

            return Ok(tel);
        }

        // Metrics disabled or not compiled in.
        Ok(Telemetry {
            #[cfg(feature = "metrics")]
            prom: None,
            #[cfg(all(feature = "metrics", feature = "rpc"))]
            shutdown_tx: None,
            #[cfg(all(feature = "metrics", feature = "rpc"))]
            http_task: None,
        })
    }

    /// Render Prometheus exposition text (pull model integration).
    #[cfg(feature = "metrics")]
    pub fn render_metrics(&self) -> Option<String> {
        self.prom.as_ref().map(|h| h.render())
    }

    /// Signal HTTP server (if any) to stop and wait for completion.
    pub async fn shutdown(self) {
        #[cfg(all(feature = "metrics", feature = "rpc"))]
        {
            if let Some(tx) = self.shutdown_tx {
                // ignore if receiver already dropped
                let _ = tx.send(());
            }
            if let Some(handle) = self.http_task {
                let _ = handle.await;
            }
        }
        // tracing subscriber is global; leaving as-is.
    }
}

#[cfg(feature = "tracing")]
fn install_tracing(cfg: &TelemetryConfig) -> Result<()> {
    let env_filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(cfg.log_level.clone())
    };

    let fmt_layer = match cfg.log_format {
        LogFormat::Json => fmt::layer()
            .event_format(fmt::format().json().flatten_event(true))
            .with_target(true)
            .with_file(true)
            .with_line_number(true)
            .with_timer(fmt::time::UtcTime::rfc_3339()),
        LogFormat::Pretty => fmt::layer()
            .with_target(true)
            .with_file(true)
            .with_line_number(true),
    };

    let subscriber = Registry::default().with(env_filter).with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| anyhow!("failed to install tracing subscriber: {e}"))?;

    Ok(())
}

#[cfg(not(feature = "tracing"))]
fn install_tracing(_: &TelemetryConfig) -> Result<()> {
    Ok(())
}

#[cfg(feature = "metrics")]
fn install_metrics(cfg: &TelemetryConfig) -> Result<PrometheusHandle> {
    // Default labels to attach to all metrics.
    let default_labels = vec![
        ("service".to_string(), cfg.service_name.clone()),
        ("version".to_string(), cfg.service_version.clone()),
        ("env".to_string(), cfg.environment.clone()),
        ("instance".to_string(), cfg.instance_id.clone()),
    ];

    // Allow any metric names; dots will be normalized by exporter.
    let recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("latency_seconds".into()),
            // Prometheus-friendly latency buckets
            &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        )
        .unwrap_or_else(|b| b) // if already set, keep builder unchanged
        .add_global_label("service", cfg.service_name.clone())
        .add_global_label("version", cfg.service_version.clone())
        .add_global_label("env", cfg.environment.clone())
        .add_global_label("instance", cfg.instance_id.clone())
        .install_recorder()
        .map_err(|e| anyhow!("failed to install prometheus recorder: {e}"))?;

    // `install_recorder` returns a `PrometheusHandle`
    Ok(recorder)
}

#[cfg(all(feature = "metrics", feature = "rpc"))]
fn spawn_metrics_http(
    handle: PrometheusHandle,
    addr: SocketAddr,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<JoinHandle<()>> {
    let svc = make_service_fn(move |_conn| {
        let handle = handle.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let handle = handle.clone();
                async move {
                    match (req.method(), req.uri().path()) {
                        (&Method::GET, "/metrics") => {
                            let body = handle.render();
                            Ok::<_, hyper::Error>(Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "text/plain; version=0.0.4")
                                .body(Body::from(body))
                                .unwrap())
                        }
                        _ => Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::from(Bytes::from_static(b"Not Found")))
                                .unwrap(),
                        ),
                    }
                }
            }))
        }
    });

    let server = Server::bind(&addr).serve(svc);

    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(1);
    let j = tokio::spawn(async move {
        // Signal readiness once the server is running.
        let srv = server.with_graceful_shutdown(async move {
            // notify readiness early
            let _ = ready_tx.send(()).await;
            let _ = &ready_rx; // silence lint
            let _ = shutdown.await;
        });
        if let Err(e) = srv.await {
            #[cfg(feature = "tracing")]
            warn!(target: "telemetry", error=%e, "metrics HTTP server error");
        }
    });

    // Wait a tick so readiness can propagate (best-effort).
    // Callers can start scraping immediately after init() returns.
    Ok(j)
}

/// Record a counter with optional labels.
#[cfg(feature = "metrics")]
pub fn inc_counter(name: &str, value: u64, labels: &[(&str, &str)]) {
    if labels.is_empty() {
        counter!(name, value);
    } else {
        counter!(name, labels, value);
    }
}

/// Set a gauge value with optional labels.
#[cfg(feature = "metrics")]
pub fn set_gauge(name: &str, value: f64, labels: &[(&str, &str)]) {
    if labels.is_empty() {
        gauge!(name, value);
    } else {
        gauge!(name, labels, value);
    }
}

/// Observe a histogram sample with unit seconds (latency) unless prefixed differently.
#[cfg(feature = "metrics")]
pub fn observe_histogram(name: &str, value: f64, labels: &[(&str, &str)]) {
    if labels.is_empty() {
        histogram!(name, value);
    } else {
        histogram!(name, labels, value);
    }
}

/// Timing guard: observes elapsed seconds into `latency_seconds{op=...,status=...}`.
#[cfg(feature = "metrics")]
pub struct Timer {
    start: Instant,
    op: &'static str,
    status: &'static str,
}

#[cfg(feature = "metrics")]
impl Timer {
    pub fn start(op: &'static str) -> Self {
        Self {
            start: Instant::now(),
            op,
            status: "ok",
        }
    }

    /// Mark error state; still records on drop.
    pub fn error(mut self) -> Self {
        self.status = "error";
        self
    }
}

#[cfg(feature = "metrics")]
impl Drop for Timer {
    fn drop(&mut self) {
        let secs = self.start.elapsed().as_secs_f64();
        observe_histogram(
            "latency_seconds",
            secs,
            &[("op", self.op), ("status", self.status)],
        );
    }
}

/// No-op stubs when metrics are disabled.
#[cfg(not(feature = "metrics"))]
pub fn inc_counter(_: &str, _: u64, _: &[(&str, &str)]) {}
#[cfg(not(feature = "metrics"))]
pub fn set_gauge(_: &str, _: f64, _: &[(&str, &str)]) {}
#[cfg(not(feature = "metrics"))]
pub fn observe_histogram(_: &str, _: f64, _: &[(&str, &str)]) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn prometheus_renders_after_updates() {
        let cfg = TelemetryConfig {
            service_name: "test-svc".into(),
            service_version: "0.0.1".into(),
            environment: "test".into(),
            instance_id: "i-1".into(),
            log_level: "error".into(),
            log_format: LogFormat::Json,
            enable_metrics: true,
            metrics_bind: None,
        };
        let tel = Telemetry::init(cfg).expect("init telemetry");

        // Update some metrics
        inc_counter("txpool_inserted_total", 1, &[("kind", "external")]);
        set_gauge("mempool_size", 42.0, &[]);
        {
            let _t = Timer::start("unit_test");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let rendered = tel.render_metrics().unwrap();
        assert!(rendered.contains("mempool_size"));
        assert!(rendered.contains("txpool_inserted_total"));
    }
}
