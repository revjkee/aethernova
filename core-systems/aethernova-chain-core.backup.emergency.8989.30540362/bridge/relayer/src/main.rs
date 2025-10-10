//! Aethernova Bridge Relayer — production-grade main()
//!
//! Components:
//! - CLI (clap derive) for config/flags;
//! - Structured logging (tracing_subscriber, JSON or text) with EnvFilter;
//! - Config loader (TOML via serde);
//! - Metrics/Health server (axum) with Prometheus TextEncoder;
//! - Relayer workers with graceful shutdown (tokio::signal + CancellationToken);
//! - Exponential backoff for transient failures.
//!
//! See docs:
//! - tokio::signal::ctrl_c (graceful shutdown) — https://docs.rs/tokio/latest/tokio/signal/fn.ctrl_c.html
//! - tracing_subscriber::EnvFilter & JSON formatter — https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
//! - clap derive (Parser/Subcommand) — https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html
//! - axum server/routing — https://docs.rs/axum-server
//! - tokio_util::sync::CancellationToken — https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html
//! - prometheus::TextEncoder — https://docs.rs/prometheus/latest/prometheus/struct.TextEncoder.html
//! - toml::from_str — https://docs.rs/toml/latest/toml/de/fn.from_str.html
//! - backoff crate — https://docs.rs/backoff

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unused_must_use)]

use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use backoff::{future::retry, ExponentialBackoff};
use clap::Parser;
use prometheus::{register_int_counter, Encoder, IntCounter, Opts, Registry, TextEncoder};
use serde::Deserialize;
use tokio::{select, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry as TracingRegistry};

/// CLI
#[derive(Debug, Parser)]
#[command(name = "aethernova-relayer", author, version, about = "Aethernova Bridge Relayer")]
struct Cli {
    /// Путь к конфигу TOML
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Адрес для метрик/health (перекрывает конфиг)
    #[arg(long, default_value = None)]
    metrics_addr: Option<String>,

    /// JSON-логирование (true/false)
    #[arg(long, default_value_t = true)]
    json_logs: bool,

    /// Перекрыть фильтр логов (пример: info,aethernova=debug)
    #[arg(long)]
    log_filter: Option<String>,
}

/// Конфигурация из TOML
#[derive(Debug, Clone, Deserialize)]
struct AppConfig {
    #[serde(default = "default_metrics_addr")]
    metrics_addr: String,

    #[serde(default = "default_concurrency")]
    concurrency: usize,

    #[serde(default = "default_source_endpoint")]
    source_endpoint: String,

    #[serde(default = "default_destination_endpoint")]
    destination_endpoint: String,

    #[serde(default = "default_backoff_max_elapsed_secs")]
    backoff_max_elapsed_secs: u64,
}

fn default_metrics_addr() -> String {
    "0.0.0.0:9090".into()
}
fn default_concurrency() -> usize {
    8
}
fn default_source_endpoint() -> String {
    "http://source.example".into()
}
fn default_destination_endpoint() -> String {
    "http://dest.example".into()
}
fn default_backoff_max_elapsed_secs() -> u64 {
    120
}

/// Метрики
#[derive(Clone)]
struct Metrics {
    registry: Registry,
    relayed_total: IntCounter,
    failures_total: IntCounter,
}

impl Metrics {
    fn new() -> Result<Self> {
        let registry = Registry::new();
        let relayed_total = register_int_counter!(
            Opts::new("aethernova_relayer_relayed_total", "Total relayed items")
        )?;
        let failures_total = register_int_counter!(
            Opts::new("aethernova_relayer_failures_total", "Total relay failures")
        )?;
        registry.register(Box::new(relayed_total.clone()))?;
        registry.register(Box::new(failures_total.clone()))?;

        Ok(Self {
            registry,
            relayed_total,
            failures_total,
        })
    }

    fn gather(&self) -> Result<Vec<u8>> {
        let mf = self.registry.gather();
        let mut buf = vec![];
        TextEncoder::new().encode(&mf, &mut buf)?;
        Ok(buf)
    }
}

/// Глобальное состояние HTTP
#[derive(Clone)]
struct HttpState {
    metrics: Metrics,
    cancel: CancellationToken,
}

/// Маршрут /health
async fn health(State(st): State<HttpState>) -> impl IntoResponse {
    if st.cancel.is_cancelled() {
        (StatusCode::SERVICE_UNAVAILABLE, "shutting down").into_response()
    } else {
        (StatusCode::OK, "ok").into_response()
    }
}

/// Маршрут /metrics (Prometheus text)
async fn metrics(State(st): State<HttpState>) -> Response {
    match st.metrics.gather() {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            body,
        )
            .into_response(),
        Err(e) => {
            error!(error = %e, "encode metrics failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Инициализация логирования (EnvFilter + JSON/текст + RFC3339 time)
fn init_tracing(json_logs: bool, filter: Option<String>) -> Result<()> {
    let filter = filter
        .and_then(|s| EnvFilter::try_new(s).ok())
        .or_else(|| EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    let fmt_layer = {
        let base = fmt::layer()
            .with_target(true)
            .with_file(true)
            .with_line_number(true)
            .with_timer(fmt::time::UtcTime::rfc_3339());

        if json_logs {
            base.json().with_current_span(true).with_span_list(true).boxed()
        } else {
            base.boxed()
        }
    };

    TracingRegistry::default()
        .with(filter)
        .with(fmt_layer)
        .init();

    Ok(())
}

/// Старт HTTP сервера (health + metrics)
async fn serve_http(addr: SocketAddr, state: HttpState) -> Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state.clone());

    info!(%addr, "starting http server");
    axum_server::bind(addr)
        .handle(axum_server::Handle::new())
        .serve(app.into_make_service())
        .await
        .map_err(|e| anyhow!(e))
}

/// Демо-сущность для передачи
#[derive(Clone, Debug)]
struct RelayItem {
    id: u64,
}

/// Получение из источника
async fn fetch_from_source(_cfg: &AppConfig, last: u64) -> Result<Vec<RelayItem>> {
    // В реальности — RPC/gRPC/WS. Здесь имитируем приход новых элементов.
    let mut out = vec![];
    let start = last + 1;
    for id in start..=start + 4 {
        out.push(RelayItem { id });
    }
    Ok(out)
}

/// Отправка в назначение
async fn submit_to_destination(_cfg: &AppConfig, item: RelayItem) -> Result<()> {
    // В реальности — RPC/gRPC/подпись/публикация.
    // Имитация работы/сбоев:
    if item.id % 17 == 0 {
        return Err(anyhow!("transient error for id={}", item.id));
    }
    Ok(())
}

/// Обертка с экспоненциальным бэкофом вокруг submit
async fn submit_with_backoff(cfg: &AppConfig, item: RelayItem) -> Result<()> {
    let mut policy = ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(cfg.backoff_max_elapsed_secs)),
        ..ExponentialBackoff::default()
    };

    retry(policy, || async {
        submit_to_destination(cfg, item.clone()).await.map_err(|e| {
            backoff::Error::transient(anyhow!(e))
        })
    })
    .await
}

/// Воркеры релея (конкурентная отправка)
async fn relayer_workers(
    cfg: AppConfig,
    metrics: Metrics,
    cancel: CancellationToken,
) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<RelayItem>(1024);

    // Производитель: периодически выкачивает новые элементы из источника
    let producer = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut last_id = 0u64;
            loop {
                select! {
                    _ = cancel.cancelled() => {
                        info!("producer: cancelled");
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {
                        match fetch_from_source(&cfg, last_id).await {
                            Ok(items) => {
                                for it in items {
                                    last_id = it.id;
                                    if let Err(_e) = tx.send(it).await {
                                        warn!("producer: channel closed");
                                        return;
                                    }
                                }
                            }
                            Err(e) => warn!(error=%e, "producer: fetch failed"),
                        }
                    }
                }
            }
        })
    };

    // Пул потребителей: конкурентная отправка с ретраями
    let mut workers = JoinSet::new();
    for idx in 0..cfg.concurrency {
        let metrics = metrics.clone();
        let cfg = cfg.clone();
        let cancel = cancel.clone();

        workers.spawn(async move {
            info!(worker=%idx, "worker started");
            loop {
                select! {
                    _ = cancel.cancelled() => {
                        info!(worker=%idx, "worker cancelled");
                        break;
                    }
                    maybe = rx.recv() => {
                        let Some(item) = maybe else { break };
                        match submit_with_backoff(&cfg, item.clone()).await {
                            Ok(_) => {
                                metrics.relayed_total.inc();
                                debug!(worker=%idx, id=item.id, "relayed");
                            }
                            Err(e) => {
                                metrics.failures_total.inc();
                                error!(worker=%idx, id=item.id, error=%e, "failed to relay after backoff");
                            }
                        }
                    }
                }
            }
        });
    }

    // Дожидаемся завершения
    let _ = producer.await;
    while let Some(res) = workers.join_next().await {
        if let Err(e) = res {
            error!(?e, "worker task join error");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // ---- CLI ----
    let cli = Cli::parse();

    // ---- Logging ----
    init_tracing(cli.json_logs, cli.log_filter.clone())?;

    // ---- Config ----
    let raw = fs::read_to_string(&cli.config)
        .with_context(|| format!("read config: {}", cli.config.display()))?;
    let mut cfg: AppConfig = toml::from_str(&raw).context("parse TOML config")?;

    if let Some(addr) = cli.metrics_addr {
        cfg.metrics_addr = addr;
    }

    info!(?cfg, "config loaded");

    // ---- Metrics/HTTP ----
    let metrics = Metrics::new()?;
    let cancel = CancellationToken::new();
    let http_state = HttpState {
        metrics: metrics.clone(),
        cancel: cancel.clone(),
    };

    let http_addr: SocketAddr = cfg.metrics_addr.parse().context("parse metrics addr")?;
    let http_task = tokio::spawn(serve_http(http_addr, http_state));

    // ---- Relayer ----
    let relay_task = tokio::spawn(relayer_workers(cfg.clone(), metrics.clone(), cancel.clone()));

    // ---- Shutdown (Ctrl-C) ----
    info!("press Ctrl-C to stop");
    select! {
        _ = tokio::signal::ctrl_c() => {
            warn!("shutdown signal received");
        }
        res = &mut tokio::spawn(async { relay_task.await }) => {
            // Нормальный выход релеяера
            if let Ok(Ok(_)) = res { info!("relayer finished early"); }
        }
    }

    cancel.cancel();

    // Даем таскам корректно завершиться
    let _ = relay_task.await;
    let _ = http_task.await;

    info!("bye");
    Ok(())
}
