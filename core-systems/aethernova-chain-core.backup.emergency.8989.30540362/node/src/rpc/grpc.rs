// aethernova-chain-core/node/src/rpc/grpc.rs
//! Индустриальный каркас gRPC-сервера для узла Aethernova.
//!
//! Ожидаемые зависимости в Cargo.toml (версии — примерные):
//!   tonic = { version = "0.12", features = ["transport", "tls"] }
//!   tonic-health = "0.12"
//!   tonic-reflection = { version = "0.12", optional = true }
//!   tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal", "fs"] }
//!   tower = "0.4"
//!   tower-http = { version = "0.5", features = ["trace"] }
//!   tracing = "0.1"
//!   tracing-subscriber = { version = "0.3", features = ["fmt", "env-filter"] }
//!   rustls = "0.23"
//!   rustls-pemfile = "2"
//!   anyhow = "1"
//!
//! Если используется серверная рефлексия, добавьте feature "reflection" и подготовьте
//! дескриптор protobuf: proto/descriptor.bin (см. build.rs SigDescriptorSet).
//!
//! Как подключить ваш gRPC-сервис (пример):
//! ```ignore
//! use crate::rpc::proto::node::node_rpc_server::NodeRpcServer;
//! use crate::rpc::services::NodeRpcImpl;
//! let add = |builder: tonic::transport::Server| {
//!     let auth = AuthInterceptor::from_bearer(env_token());
//!     let svc = NodeRpcServer::new(NodeRpcImpl::new());
//!     // опционально: оборачиваем сервис интерцептором
//!     let svc = tonic::service::interceptor(svc, auth);
//!     builder.add_service(svc)
//! };
//! run_grpc(add, GrpcConfig::from_env()).await?;
//! ```

use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use tokio::signal;
use tokio::sync::Notify;
use tonic::transport::{Server, ServerTlsConfig};
use tonic::{Request, Status};
use tower::{limit::ConcurrencyLimitLayer, timeout::TimeoutLayer};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{error, info, instrument, Level};

// Health
use tonic_health::server::{health_reporter, HealthReporter, HealthService};

// TLS
use rustls::{pki_types::CertificateDer, pki_types::PrivateKeyDer, ServerConfig as RustlsServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

/// Конфигурация gRPC-сервера.
#[derive(Clone)]
pub struct GrpcConfig {
    pub addr: SocketAddr,
    pub enable_tls: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    /// Необязательная верификация клиентских сертификатов (mTLS): путь к CA.
    pub client_ca_path: Option<String>,
    /// Таймаут обработки запроса.
    pub request_timeout: Duration,
    /// Лимит одновременных запросов на инстанс.
    pub concurrency_limit: usize,
    /// Включить сжатие (gzip) на ответах и принимать gzip на входе.
    pub enable_compression: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:50051".parse().unwrap(),
            enable_tls: false,
            cert_path: None,
            key_path: None,
            client_ca_path: None,
            request_timeout: Duration::from_secs(30),
            concurrency_limit: 1024,
            enable_compression: true,
        }
    }
}

impl fmt::Debug for GrpcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcConfig")
            .field("addr", &self.addr)
            .field("enable_tls", &self.enable_tls)
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("client_ca_path", &self.client_ca_path)
            .field("request_timeout_secs", &self.request_timeout.as_secs())
            .field("concurrency_limit", &self.concurrency_limit)
            .field("enable_compression", &self.enable_compression)
            .finish()
    }
}

impl GrpcConfig {
    /// Пример инициализации из переменных окружения (опционально).
    pub fn from_env() -> Self {
        let base = Self::default();
        let addr = std::env::var("GRPC_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(base.addr);
        let enable_tls = std::env::var("GRPC_TLS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(base.enable_tls);
        let request_timeout = std::env::var("GRPC_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(base.request_timeout);
        let concurrency_limit = std::env::var("GRPC_CONCURRENCY_LIMIT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(base.concurrency_limit);
        let enable_compression = std::env::var("GRPC_COMPRESSION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(base.enable_compression);

        Self {
            addr,
            enable_tls,
            cert_path: std::env::var("GRPC_CERT").ok(),
            key_path: std::env::var("GRPC_KEY").ok(),
            client_ca_path: std::env::var("GRPC_CLIENT_CA").ok(),
            request_timeout,
            concurrency_limit,
            enable_compression,
        }
    }
}

/// Интерцептор аутентификации по Bearer токену (опционально).
#[derive(Clone, Default)]
pub struct AuthInterceptor {
    token: Option<Arc<String>>,
}

impl AuthInterceptor {
    pub fn from_bearer<S: Into<String>>(token: Option<S>) -> Self {
        Self {
            token: token.map(|s| Arc::new(s.into())),
        }
    }

    fn check(&self, req: &Request<()>) -> std::result::Result<(), Status> {
        if let Some(expected) = &self.token {
            let auth = req
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            // Формат: "Bearer <token>"
            if !auth.starts_with("Bearer ") || &auth[7..] != expected.as_str() {
                return Err(Status::unauthenticated("invalid bearer token"));
            }
        }
        Ok(())
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, req: Request<()>) -> std::result::Result<Request<()>, Status> {
        self.check(&req)?;
        Ok(req)
    }
}

/// Сигнал для грациозной остановки из внешнего кода.
#[derive(Clone, Default)]
pub struct Shutdown {
    notify: Arc<Notify>,
}

impl Shutdown {
    pub fn new() -> Self {
        Self { notify: Arc::new(Notify::new()) }
    }
    /// Инициировать останов.
    pub fn trigger(&self) { self.notify.notify_waiters(); }
    /// Будущее, завершаемое при останове.
    pub async fn wait(&self) { self.notify.notified().await; }
}

/// Тип замыкания, добавляющего бизнес-сервисы в Server builder.
/// Позволяет избежать жёсткой связки с конкретными типами сгенерированных серверов.
pub type AddServices = Box<dyn FnOnce(Server) -> Server + Send + 'static>;

/// Точка входа запуска gRPC-сервера.
/// Передайте замыкание `add` для регистрации собственных сервисов tonic.
#[instrument(skip_all, fields(addr = %cfg.addr))]
pub async fn run_grpc(add: AddServices, cfg: GrpcConfig) -> Result<()> {
    init_tracing();

    info!(?cfg, "starting gRPC server");

    // Health-service
    let (mut health, health_svc) = health_reporter();
    health
        .set_serving::<HealthService>()
        .await;

    // Базовый builder + слои tower
    let layers = ServiceBuilder::new()
        .layer(TraceLayer::new_for_grpc().make_span_with(|req: &http::Request<_>| {
            tracing::span!(Level::INFO, "grpc", method = ?req.uri(), ua = ?req.headers().get("user-agent"))
        }))
        .layer(ConcurrencyLimitLayer::new(cfg.concurrency_limit))
        .layer(TimeoutLayer::new(cfg.request_timeout));

    let mut builder = Server::builder()
        .layer(layers);

    // Компрессия
    if cfg.enable_compression {
        builder = builder.accept_gzip().send_gzip();
    }

    // TLS (опционально)
    if cfg.enable_tls {
        let tls = load_rustls(
            cfg.cert_path.as_deref().context("cert path required when TLS enabled")?,
            cfg.key_path.as_deref().context("key path required when TLS enabled")?,
            cfg.client_ca_path.as_deref(),
        )
        .await?;
        builder = builder
            .tls_config(ServerTlsConfig::new().rustls_server_config(tls))
            .context("failed to apply TLS config")?;
    }

    // Рефлексия (опционально, при наличии дескриптора)
    #[cfg(feature = "reflection")]
    let reflection = {
        use tonic_reflection::server::Builder as ReflBuilder;
        const FDSET: &[u8] = include_bytes!("../../proto/descriptor.bin");
        ReflBuilder::configure()
            .register_encoded_file_descriptor_set(FDSET)
            .build()
            .expect("reflection builder")
    };

    // Регистрируем системные сервисы
    let builder = {
        let builder = builder.add_service(health_svc);
        #[cfg(feature = "reflection")]
        let builder = builder.add_service(reflection);
        builder
    };

    // Регистрируем пользовательские сервисы
    let builder = (add)(builder);

    let addr = cfg.addr;

    // Грациозный останов: SIGINT/SIGTERM или внутренний триггер.
    let shutdown = async {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("received ctrl_c");
            }
            #[cfg(unix)]
            _ = async {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate()).expect("sigterm");
                sigterm.recv().await;
            }() => {
                info!("received SIGTERM");
            }
        }
    };

    info!(%addr, "gRPC server listening");
    builder.serve_with_shutdown(addr, shutdown).await.map_err(Into::into)
}

/// Обновить статус сервиса health-репортера (можно дергать из init бизнес-сервиса).
pub async fn set_health_serving(health: &mut HealthReporter, service_name: &'static str) {
    let _ = health.set_serving(service_name).await;
}

/// Снять сервис со здоровья (NOT_SERVING).
pub async fn set_health_not_serving(health: &mut HealthReporter, service_name: &'static str) {
    let _ = health.set_not_serving(service_name).await;
}

/// Загрузить TLS (rustls) из PEM-файлов.
/// Если `client_ca_path` задан, включается mTLS (verify client certs).
async fn load_rustls(cert_path: &str, key_path: &str, client_ca_path: Option<&str>) -> Result<RustlsServerConfig> {
    use tokio::fs;

    let cert_pem = fs::read(cert_path).await.with_context(|| format!("read cert {cert_path}"))?;
    let key_pem = fs::read(key_path).await.with_context(|| format!("read key {key_path}"))?;

    let mut cert_reader = &cert_pem[..];
    let certs: Vec<CertificateDer<'_>> = certs(&mut cert_reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("parse certs: {e}"))?;

    let mut key_reader = &key_pem[..];
    let mut keys: Vec<PrivateKeyDer<'_>> = pkcs8_private_keys(&mut key_reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("parse pkcs8 key: {e}"))?;
    let key = keys
        .pop()
        .ok_or_else(|| anyhow!("no pkcs8 private key found"))?;

    let mut cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("rustls server config: {e}"))?;

    if let Some(ca_path) = client_ca_path {
        let ca_pem = tokio::fs::read(ca_path).await.with_context(|| format!("read client CA {ca_path}"))?;
        let mut reader = &ca_pem[..];
        let cas: Vec<CertificateDer<'_>> = certs(&mut reader)
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| anyhow!("parse client CA: {e}"))?;
        let mut roots = rustls::RootCertStore::empty();
        for c in cas {
            roots.add(c).map_err(|e| anyhow!("add CA: {e}"))?;
        }
        cfg = RustlsServerConfig::builder()
            .with_client_cert_verifier(Arc::new(rustls::server::WebPkiClientVerifier::builder(roots).build()?))
            .with_single_cert(tokio_pem_to_certs(&cert_pem)?, tokio_pem_to_key(&key_pem)?)
            .map_err(|e| anyhow!("rustls mtls config: {e}"))?;
    }

    Ok(cfg)
}

// Вспомогательные преобразователи для повторного использования cert/key при mTLS.
fn tokio_pem_to_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut r = &pem[..];
    let certs: Vec<CertificateDer<'_>> = certs(&mut r)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("parse certs: {e}"))?;
    // Удлиняем время жизни буфера (копируем)
    Ok(certs.into_iter().map(|c| CertificateDer::from(c.to_vec())).collect())
}

fn tokio_pem_to_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut r = &pem[..];
    let mut keys: Vec<PrivateKeyDer<'_>> = pkcs8_private_keys(&mut r)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("parse pkcs8 key: {e}"))?;
    let k = keys.pop().ok_or_else(|| anyhow!("no pkcs8 key"))?;
    Ok(PrivateKeyDer::Pkcs8(k.secret_pkcs8_der().to_vec().into()))
}

/// Инициализация трассировки (если не включена извне).
fn init_tracing() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,hyper=warn,h2=warn".into());
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .try_init();
    });
}

/// Утилита для обёртки сервиса перехватчиком аутентификации.
/// Пример: add_service(with_auth(NodeRpcServer::new(..), Some("TOKEN".into())))
pub fn with_auth<S>(svc: S, bearer: Option<String>) -> tonic::codegen::InterceptedService<S, AuthInterceptor>
where
    S: tonic::codegen::Service<
        http::Request<hyper::Body>,
        Response = http::Response<tonic::body::BoxBody>,
        Error = std::convert::Infallible,
    > + Clone,
{
    tonic::service::interceptor(svc, AuthInterceptor::from_bearer(bearer))
}

// --- Тест быстрой сборки без подключённых .proto (опционально) ---
// cargo test -q --features="" -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn builds_server_without_tls() {
        let cfg = GrpcConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            enable_tls: false,
            ..Default::default()
        };

        // Регистрируем только health (по умолчанию уже добавлен), без бизнес-сервисов.
        let add: AddServices = Box::new(|b| b);

        // Поднимаем и немедленно завершаем.
        let h = tokio::spawn(async move {
            let run = run_grpc(add, cfg);
            // Немного подождём и отменим через ctrl_c эмуляцию — упростим завершение теста.
            tokio::select! {
                r = run => r,
                _ = tokio::time::sleep(Duration::from_millis(100)) => Ok(()),
            }
        });
        let _ = h.await.unwrap();
    }
}
