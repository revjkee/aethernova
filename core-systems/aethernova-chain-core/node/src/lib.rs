//! Aethernova Chain Node — core library
//! Производственный каркас ноды: конфигурация, телеметрия, запуск сервисов,
//! управление жизненным циклом, метрики и тестовые заглушки сервисов.

#![forbid(unsafe_code)]
#![deny(
    rust_2018_idioms,
    broken_intra_doc_links,
    missing_debug_implementations,
    missing_docs
)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::{fmt, path::PathBuf, time::Duration};

pub use config::Config;
pub use error::{Error, Result};
pub use node::{Node, NodeBuilder, NodeHandle};
pub use telemetry::{init_tracing, TelemetryGuard};

/// Модуль ошибок: единый тип для всей ноды.
mod error {
    use std::io;

    use thiserror::Error;

    /// Унифицированная ошибка ноды.
    #[derive(Debug, Error)]
    pub enum Error {
        /// Ошибки ввода-вывода (диски, сети, файлы).
        #[error("io error: {0}")]
        Io(#[from] io::Error),

        /// Ошибка сериализации/десериализации конфигурации.
        #[error("config error: {0}")]
        Config(String),

        /// Ошибки телеметрии/трассировки.
        #[error("telemetry error: {0}")]
        Telemetry(String),

        /// Ошибки времени выполнения сервисов.
        #[error("runtime error: {0}")]
        Runtime(String),

        /// Таймаут операции.
        #[error("timeout after {0:?}")]
        Timeout(std::time::Duration),

        /// Прочие ошибки.
        #[error("{0}")]
        Other(String),
    }

    /// Результат ноды.
    pub type Result<T, E = Error> = std::result::Result<T, E>;
}

/// Конфигурация приложения с (де)сериализацией и дефолтами.
mod config {
    use super::error::{Error, Result};
    use serde::{Deserialize, Serialize};
    use std::{fs, path::Path};

    /// Точки входа в сеть.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkCfg {
        /// Адрес p2p слушателя.
        pub p2p_bind: String,
        /// Сид-нод для первичного коннекта.
        #[serde(default)]
        pub seeds: Vec<String>,
        /// Максимум пиров.
        #[serde(default = "default_max_peers")]
        pub max_peers: usize,
    }

    fn default_max_peers() -> usize {
        64
    }

    impl Default for NetworkCfg {
        fn default() -> Self {
            Self {
                p2p_bind: "0.0.0.0:30303".into(),
                seeds: vec![],
                max_peers: default_max_peers(),
            }
        }
    }

    /// RPC настройки.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RpcCfg {
        /// Адрес RPC.
        pub http_bind: String,
        /// Включать ли WebSocket.
        #[serde(default)]
        pub ws_enabled: bool,
        /// Максимальная конкаррентность.
        #[serde(default = "default_rpc_max_concurrency")]
        pub max_concurrency: usize,
    }

    fn default_rpc_max_concurrency() -> usize {
        1024
    }

    impl Default for RpcCfg {
        fn default() -> Self {
            Self {
                http_bind: "0.0.0.0:8545".into(),
                ws_enabled: true,
                max_concurrency: default_rpc_max_concurrency(),
            }
        }
    }

    /// Хранилище.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StorageCfg {
        /// Директория данных.
        pub data_dir: String,
        /// Размер кэша (МиБ).
        #[serde(default = "default_cache_mib")]
        pub cache_mib: u64,
    }

    fn default_cache_mib() -> u64 {
        512
    }

    impl Default for StorageCfg {
        fn default() -> Self {
            Self {
                data_dir: "./data".into(),
                cache_mib: default_cache_mib(),
            }
        }
    }

    /// Телеметрия и логирование.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TelemetryCfg {
        /// Уровень логов (RUST_LOG совместим).
        #[serde(default = "default_log_level")]
        pub log_level: String,
        /// JSON-формат логов.
        #[serde(default)]
        pub json: bool,
        /// Включить OpenTelemetry OTLP (при включённой фиче `otlp`).
        #[serde(default)]
        pub otlp: bool,
    }

    fn default_log_level() -> String {
        "info".to_string()
    }

    impl Default for TelemetryCfg {
        fn default() -> Self {
            Self {
                log_level: default_log_level(),
                json: true,
                otlp: false,
            }
        }
    }

    /// Вся конфигурация ноды.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Config {
        /// Идентификатор сети (mainnet/testnet/dev).
        #[serde(default = "default_chain_id")]
        pub chain_id: String,
        /// Сеть p2p.
        #[serde(default)]
        pub network: NetworkCfg,
        /// RPC.
        #[serde(default)]
        pub rpc: RpcCfg,
        /// Хранилище.
        #[serde(default)]
        pub storage: StorageCfg,
        /// Телеметрия.
        #[serde(default)]
        pub telemetry: TelemetryCfg,
    }

    fn default_chain_id() -> String {
        "aethernova-dev".into()
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                chain_id: default_chain_id(),
                network: NetworkCfg::default(),
                rpc: RpcCfg::default(),
                storage: StorageCfg::default(),
                telemetry: TelemetryCfg::default(),
            }
        }
    }

    impl Config {
        /// Загрузка из TOML/YAML файла по расширению.
        pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
            let path = path.as_ref();
            let text = fs::read_to_string(path)?;
            match path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .as_deref()
            {
                Some("toml") => toml::from_str(&text)
                    .map_err(|e| Error::Config(format!("toml parse: {e}"))),
                Some("yaml") | Some("yml") => serde_yaml::from_str(&text)
                    .map_err(|e| Error::Config(format!("yaml parse: {e}"))),
                _ => Err(Error::Config("unknown config format".into())),
            }
        }
    }
}

/// Телеметрия: инициализация `tracing` + опциональный OTLP.
mod telemetry {
    use super::error::{Error, Result};

    /// RAII-гард телеметрии (для корректного shutdown провайдеров).
    #[derive(Debug)]
    pub struct TelemetryGuard {
        #[cfg(feature = "otlp")]
        _otlp: Option<opentelemetry::sdk::trace::Tracer>,
    }

    impl Default for TelemetryGuard {
        fn default() -> Self {
            Self {
                #[cfg(feature = "otlp")]
                _otlp: None,
            }
        }
    }

    /// Инициализация `tracing` на основе уровня и формата.
    pub fn init_tracing(level: &str, json: bool, otlp: bool) -> Result<TelemetryGuard> {
        use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

        let env_filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
        let fmt_layer = if json {
            fmt::layer().json().with_target(true).with_timer(fmt::time::UtcTime::rfc_3339())
        } else {
            fmt::layer().with_target(true).with_timer(fmt::time::UtcTime::rfc_3339())
        };

        #[cfg(not(feature = "otlp"))]
        {
            let subscriber = Registry::default().with(env_filter).with(fmt_layer);
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| Error::Telemetry(format!("set_global_default: {e}")))?;
            Ok(TelemetryGuard::default())
        }

        #[cfg(feature = "otlp")]
        {
            use opentelemetry::sdk::{
                self,
                trace::{self, Sampler},
                Resource,
            };
            use opentelemetry_otlp::WithExportConfig;
            use tracing_opentelemetry::OpenTelemetryLayer;

            let tracer = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(opentelemetry_otlp::new_exporter().tonic())
                .with_trace_config(
                    trace::config()
                        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                            0.10,
                        ))))
                        .with_resource(Resource::new(vec![sdk::Resource::SERVICE_NAME
                            .string("aethernova-node")])),
                )
                .install_batch(opentelemetry::runtime::Tokio)
                .map_err(|e| Error::Telemetry(format!("otlp install: {e}")))?;

            let otel_layer = OpenTelemetryLayer::new(tracer.clone());
            let subscriber = Registry::default()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer);

            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| Error::Telemetry(format!("set_global_default: {e}")))?;

            Ok(TelemetryGuard { _otlp: Some(tracer) })
        }
    }
}

/// Общая система завершения: сигнал, бродкаст, таймауты.
mod shutdown {
    use super::error::{Error, Result};
    use std::time::Duration;
    use tokio::sync::broadcast;

    /// Сигнал завершения для тасков.
    #[derive(Clone, Debug)]
    pub struct Shutdown {
        tx: broadcast::Sender<()>,
    }

    impl Shutdown {
        /// Создать новый контроллер завершения.
        pub fn new() -> (Self, broadcast::Receiver<()>) {
            let (tx, rx) = broadcast::channel(8);
            (Self { tx }, rx)
        }

        /// Подписаться на сигнал.
        pub fn subscribe(&self) -> broadcast::Receiver<()> {
            self.tx.subscribe()
        }

        /// Отправить сигнал завершения.
        pub fn signal(&self) -> Result<()> {
            let _ = self.tx.send(());
            Ok(())
        }

        /// Ожидать завершения с таймаутом (для join на тасках).
        pub async fn wait_with_timeout<F>(&self, fut: F, timeout: Duration) -> Result<()>
        where
            F: std::future::Future<Output = ()>,
        {
            tokio::select! {
                _ = tokio::time::sleep(timeout) => Err(Error::Timeout(timeout)),
                _ = fut => Ok(())
            }
        }
    }
}

/// Интерфейсы сервисов ноды: P2P, RPC, и т.п.
mod services {
    use async_trait::async_trait;
    use std::fmt::Debug;
    use tokio::sync::broadcast;

    use crate::error::Result;

    /// Унифицированный сервисный интерфейс.
    #[async_trait]
    pub trait Service: Send + Sync + Debug {
        /// Имя сервиса для логов/метрик.
        fn name(&self) -> &'static str;

        /// Асинхронный запуск. Должен возвратиться после получения сигнала shutdown.
        async fn run(self: Box<Self>, mut shutdown: broadcast::Receiver<()>) -> Result<()>;
    }

    /// Заглушка P2P сервиса (пример).
    #[derive(Debug)]
    pub struct P2PService {
        pub bind: String,
        pub max_peers: usize,
    }

    #[async_trait]
    impl Service for P2PService {
        fn name(&self) -> &'static str {
            "p2p"
        }

        async fn run(self: Box<Self>, mut shutdown: broadcast::Receiver<()>) -> Result<()> {
            tracing::info!(target: "node", bind=%self.bind, max_peers=%self.max_peers, "P2P started");
            // Здесь должен быть реальный event-loop p2p; мы имитируем его ожиданием shutdown.
            let _ = shutdown.recv().await;
            tracing::info!(target: "node", "P2P stopped");
            Ok(())
        }
    }

    /// Заглушка RPC сервиса (пример).
    #[derive(Debug)]
    pub struct RpcService {
        pub http_bind: String,
        pub ws: bool,
        pub max_concurrency: usize,
    }

    #[async_trait]
    impl Service for RpcService {
        fn name(&self) -> &'static str {
            "rpc"
        }

        async fn run(self: Box<Self>, mut shutdown: broadcast::Receiver<()>) -> Result<()> {
            tracing::info!(target: "node", http=%self.http_bind, ws=%self.ws, conc=%self.max_concurrency, "RPC started");
            let _ = shutdown.recv().await;
            tracing::info!(target: "node", "RPC stopped");
            Ok(())
        }
    }
}

/// Метрики: no-op по умолчанию, Prometheus при feature = "metrics".
mod metrics {
    #[cfg(feature = "metrics")]
    use once_cell::sync::Lazy;
    #[cfg(feature = "metrics")]
    use prometheus::{register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec};

    /// Трекер метрик ноды.
    #[derive(Debug, Default)]
    pub struct NodeMetrics;

    #[cfg(feature = "metrics")]
    static SVC_STARTS: Lazy<IntCounterVec> = Lazy::new(|| {
        register_int_counter_vec!(
            "aethernova_service_starts_total",
            "Service start events",
            &["service"]
        )
        .expect("metric")
    });

    #[cfg(feature = "metrics")]
    static SVC_RUNTIME: Lazy<HistogramVec> = Lazy::new(|| {
        register_histogram_vec!(
            "aethernova_service_runtime_seconds",
            "Service runtime duration",
            &["service"]
        )
        .expect("metric")
    });

    impl NodeMetrics {
        /// Сигнализировать о старте сервиса.
        pub fn service_started(&self, name: &str) {
            #[cfg(feature = "metrics")]
            SVC_STARTS.with_label_values(&[name]).inc();
        }

        /// Наблюдать длительность выполнения сервиса (возвращает guard).
        pub fn observe_service<'a>(&'a self, _name: &'a str) -> ServiceTimer<'a> {
            #[cfg(feature = "metrics")]
            {
                ServiceTimer::Start(std::time::Instant::now(), _name)
            }
            #[cfg(not(feature = "metrics"))]
            {
                ServiceTimer::Noop
            }
        }
    }

    /// Guard для записи длительности.
    pub enum ServiceTimer<'a> {
        /// No-op вариант.
        Noop,
        /// Прометей-вариант.
        #[cfg(feature = "metrics")]
        Start(std::time::Instant, &'a str),
    }

    impl<'a> Drop for ServiceTimer<'a> {
        fn drop(&mut self) {
            #[cfg(feature = "metrics")]
            if let ServiceTimer::Start(start, name) = self {
                let secs = start.elapsed().as_secs_f64();
                SVC_RUNTIME.with_label_values(&[*name]).observe(secs);
            }
        }
    }
}

/// Узел: билдер, запуск, остановка.
mod node {
    use super::config::Config;
    use super::error::{Error, Result};
    use super::metrics::NodeMetrics;
    use super::services::{P2PService, RpcService, Service};
    use super::shutdown::Shutdown;

    use std::{fmt, future::Future, sync::Arc, time::Duration};
    use tokio::{select, task::JoinSet};

    /// Хендл раннинга ноды.
    #[derive(Debug)]
    pub struct NodeHandle {
        shutdown: Shutdown,
    }

    impl NodeHandle {
        /// Инициировать graceful shutdown.
        pub fn shutdown(&self) -> Result<()> {
            self.shutdown.signal()
        }
    }

    /// Экземпляр ноды.
    pub struct Node {
        cfg: Config,
        metrics: NodeMetrics,
    }

    impl fmt::Debug for Node {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Node")
                .field("chain_id", &self.cfg.chain_id)
                .finish_non_exhaustive()
        }
    }

    impl Node {
        fn new(cfg: Config) -> Self {
            Self {
                cfg,
                metrics: NodeMetrics::default(),
            }
        }

        /// Запуск ноды и ожидание завершения.
        pub async fn run(self) -> Result<()> {
            let (shutdown, root_rx) = Shutdown::new();
            let handle = NodeHandle {
                shutdown: shutdown.clone(),
            };

            let mut set = JoinSet::new();
            let metrics = Arc::new(self.metrics);

            // P2P
            {
                let rx = shutdown.subscribe();
                let svc = P2PService {
                    bind: self.cfg.network.p2p_bind.clone(),
                    max_peers: self.cfg.network.max_peers,
                };
                let m = metrics.clone();
                set.spawn(run_service(Box::new(svc), rx, m));
            }

            // RPC
            {
                let rx = shutdown.subscribe();
                let svc = RpcService {
                    http_bind: self.cfg.rpc.http_bind.clone(),
                    ws: self.cfg.rpc.ws_enabled,
                    max_concurrency: self.cfg.rpc.max_concurrency,
                };
                let m = metrics.clone();
                set.spawn(run_service(Box::new(svc), rx, m));
            }

            // Сигнал ОС (Ctrl+C) — останавливаемся.
            #[cfg(feature = "tokio")]
            let os_sig = async {
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::warn!(target:"node", error=%e, "ctrl_c wait failed");
                }
            };

            #[cfg(not(feature = "tokio"))]
            let os_sig = async { futures::future::pending::<()>().await };

            tracing::info!(target: "node", chain_id = %self.cfg.chain_id, "node started");
            select! {
                _ = os_sig => {
                    tracing::info!(target:"node", "shutdown signal received (os)");
                    let _ = handle.shutdown();
                }
                // Если любой таск упал — валим всю ноду.
                res = wait_any(&mut set) => {
                    if let Err(e) = res {
                        tracing::error!(target:"node", error=%e, "service failed — shutting down");
                        let _ = handle.shutdown();
                    }
                }
            }

            // Ждём закрытия всех задач с таймаутом.
            let drained = drain_joinset(&mut set, Duration::from_secs(15)).await;
            if let Err(e) = drained {
                tracing::warn!(target:"node", error=%e, "graceful drain incomplete");
            }

            // Ждём финальный сигнал root_rx (чтобы сервисы успели выйти).
            let _ = root_rx;

            tracing::info!(target:"node", "node stopped");
            Ok(())
        }
    }

    /// Запуск конкретного сервиса с обвязкой метрик/логов.
    async fn run_service(
        svc: Box<dyn Service>,
        shutdown: tokio::sync::broadcast::Receiver<()>,
        metrics: std::sync::Arc<NodeMetrics>,
    ) -> Result<()> {
        let name = svc.name();
        metrics.service_started(name);
        let _timer = metrics.observe_service(name);
        tracing::info!(target:"node", service=%name, "starting");
        let res = svc.run(shutdown).await;
        match &res {
            Ok(_) => tracing::info!(target:"node", service=%name, "stopped ok"),
            Err(e) => tracing::error!(target:"node", service=%name, error=%e, "stopped with error"),
        }
        res
    }

    /// Ожидать завершения любого таска и вернуть его результат.
    async fn wait_any(set: &mut tokio::task::JoinSet<Result<()>>) -> Result<()> {
        if let Some(res) = set.join_next().await {
            res.map_err(|e| Error::Runtime(format!("join error: {e}")))?
        } else {
            Ok(())
        }
    }

    /// Дождаться завершения всех задач с таймаутом.
    async fn drain_joinset(set: &mut tokio::task::JoinSet<Result<()>>, t: Duration) -> Result<()> {
        let fut = async {
            while let Some(res) = set.join_next().await {
                res.map_err(|e| Error::Runtime(format!("join error: {e}")))?;
            }
            Ok::<(), super::error::Error>(())
        };
        tokio::select! {
            _ = tokio::time::sleep(t) => Err(super::error::Error::Timeout(t)),
            r = fut => r,
        }
    }

    /// Билдер для `Node`.
    #[derive(Debug, Default)]
    pub struct NodeBuilder {
        cfg: Option<Config>,
    }

    impl NodeBuilder {
        /// Новый билдер.
        pub fn new() -> Self {
            Self { cfg: None }
        }

        /// Установить конфигурацию.
        pub fn with_config(mut self, cfg: Config) -> Self {
            self.cfg = Some(cfg);
            self
        }

        /// Сконструировать `Node`.
        pub fn build(self) -> Result<Node> {
            let cfg = self.cfg.unwrap_or_default();
            Ok(Node::new(cfg))
        }

        /// Построить и запустить.
        pub async fn build_and_run(self) -> Result<()> {
            self.build()?.run().await
        }
    }
}

/// Вспомогательные импорты внешних зависимостей (serde/toml/yaml/tracing)
/// подключаются через Cargo.toml. Этот файл не содержит `main`, он — библиотека.
mod prelude {
    pub use crate::{Config, Node, NodeBuilder, TelemetryGuard};
}

// === ВНЕШНИЕ КРЕЙТЫ, используемые через Cargo.toml ===
// serde = { version = "1", features = ["derive"] }
// serde_yaml = "0.9"
// toml = "0.8"
// thiserror = "1"
// tracing = "0.1"
// tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
// tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal", "time"] }
// async-trait = "0.1"
// once_cell = "1"            # optional, for metrics
// prometheus = "0.13"        # optional, feature = "metrics"
// opentelemetry = "0.22"     # optional, feature = "otlp"
// opentelemetry-otlp = "0.14" # optional, feature = "otlp"
// tracing-opentelemetry = "0.22" # optional, feature = "otlp"

// === ПРИМЕР ИНИЦИАЛИЗАЦИИ (интеграционный, в бинаре) ===
// fn main() -> anyhow::Result<()> {
//     let cfg = Config::from_file("config.toml")?;
//     let _guard = init_tracing(&cfg.telemetry.log_level, cfg.telemetry.json, cfg.telemetry.otlp)?;
//     tokio::runtime::Builder::new_multi_thread()
//         .enable_all()
//         .build()?
//         .block_on(NodeBuilder::new().with_config(cfg).build_and_run())?;
//     Ok(())
// }
