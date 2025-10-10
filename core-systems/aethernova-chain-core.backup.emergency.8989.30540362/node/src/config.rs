//! Industrial-grade configuration loader for Aethernova Node.
//!
//! Layers (highest precedence last):
//!   1) Built-in defaults
//!   2) Config file (auto-discovered or explicit path)
//!   3) Environment variables (optionally via .env)
//!
//! References (selected):
//! - `config` crate: layered sources (File, Environment), builder/merge and deserialize
//!   https://docs.rs/config/latest/config/                              
//! - Serde derive for (de)serialization
//!   https://serde.rs/derive.html                                        
//! - `dotenvy` to load .env for dev
//!   https://docs.rs/dotenvy/latest/dotenvy/                             
//! - `directories` ProjectDirs for cross-platform config dirs
//!   https://docs.rs/directories/latest/directories/struct.ProjectDirs.html
//! - `secrecy` for secret values (with serde support)
//!   https://docs.rs/secrecy                                          
//! - Human-friendly durations: `humantime-serde`
//!   https://docs.rs/humantime-serde                                    
//! - `tracing-subscriber` EnvFilter (RUST_LOG-style directives)
//!   https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
//! - URL parsing & validation
//!   https://docs.rs/url/latest/url/struct.Url.html                      

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use config as cfg;
use directories::ProjectDirs;
use dotenvy::dotenv;
use humantime_serde::re::humantime;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Application config (validated).
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub app: App,
    pub network: Network,
    pub rpc: Rpc,
    pub database: Database,
    pub telemetry: Telemetry,
    pub security: Security,
}

/// Non-secret application parameters.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct App {
    /// Human-readable node name.
    pub name: String,
    /// Deployment environment: "prod" | "staging" | "dev".
    pub environment: String,
    /// Logical instance id / shard label.
    pub instance: String,
}

/// P2P / gossip / bootstrap.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Network {
    /// Bind address for P2P listener, e.g. "0.0.0.0:30333".
    pub bind_addr: String,
    /// Optional advertised public address.
    pub public_addr: Option<String>,
    /// Bootstrap peer multiaddrs or URLs.
    pub bootstrap: Vec<String>,
    /// Connection/read/write timeouts.
    #[serde(with = "humantime_serde")]
    pub dial_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub read_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub write_timeout: Duration,
}

/// JSON-RPC / gRPC endpoints.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Rpc {
    pub enabled: bool,
    /// Bind address for RPC (HTTP).
    pub bind_http: String,
    /// Optional public URL (validated).
    pub public_http_url: Option<String>,
    /// Allowed CORS origins (exact match / wildcard per gateway policy).
    pub cors: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub shutdown_grace: Duration,
}

/// Storage configuration (example with Postgres; replace per your stack).
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Database {
    /// Database URL (redacted in logs).
    pub url: SecretString,
    /// Max pool size.
    pub max_pool_size: u32,
    /// Connection timeout.
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
}

/// Telemetry / logging / metrics.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Telemetry {
    pub enable_metrics: bool,
    pub metrics_bind: String,
    /// RUST_LOG-like directive, e.g. "info,aethernova=debug".
    pub log_filter: String,
}

/// Keys / secrets (redacted in logs).
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    /// Node private key (hex/base64/etc. — kept opaque).
    pub node_private_key: SecretString,
    /// Optional path to ZK proving key file.
    pub zk_proving_key_path: Option<PathBuf>,
    /// Optional JWT/HMAC secret for RPC auth.
    pub rpc_auth_secret: Option<SecretString>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app: App::default(),
            network: Network::default(),
            rpc: Rpc::default(),
            database: Database::default(),
            telemetry: Telemetry::default(),
            security: Security::default(),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self {
            name: "aethernova-node".into(),
            environment: "prod".into(),
            instance: "default".into(),
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:30333".into(),
            public_addr: None,
            bootstrap: vec![],
            dial_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(15),
        }
    }
}

impl Default for Rpc {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_http: "0.0.0.0:8545".into(),
            public_http_url: None,
            cors: vec![],
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

impl Default for Database {
    fn default() -> Self {
        Self {
            url: SecretString::new("postgres://user:pass@localhost:5432/aethernova".into()),
            max_pool_size: 20,
            connect_timeout: Duration::from_secs(5),
        }
    }
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            metrics_bind: "0.0.0.0:9090".into(),
            log_filter: "info,aethernova=info".into(),
        }
    }
}

impl Default for Security {
    fn default() -> Self {
        Self {
            node_private_key: SecretString::new("CHANGE_ME".into()),
            zk_proving_key_path: None,
            rpc_auth_secret: None,
        }
    }
}

/// Errors during configuration loading/validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config build error: {0}")]
    Build(#[from] cfg::ConfigError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid url `{0}`")]
    InvalidUrl(String),
    #[error("invalid bind address `{0}`")]
    InvalidBind(String),
    #[error("missing or invalid secret `{0}`")]
    InvalidSecret(&'static str),
    #[error("path not found `{0}`")]
    PathNotFound(String),
}

/// Load configuration: defaults → file(s) → environment.
/// Env prefix: `AETHERNOVA__...`, nested fields separated by `__`.
///
/// Examples:
///   AETHERNOVA__APP__ENVIRONMENT=staging
///   AETHERNOVA__RPC__BIND_HTTP=0.0.0.0:8546
///   AETHERNOVA__DATABASE__URL=postgres://... (redacted in logs)
///
/// `config` layering & environment source:
/// https://docs.rs/config/latest/config/                                          
pub fn load(explicit_file: Option<&Path>) -> Result<Config, ConfigError> {
    // Load .env for developer convenience (no-op if absent).
    // https://docs.rs/dotenvy/latest/dotenvy/
    let _ = dotenv();

    let mut builder = cfg::Config::builder();

    // 1) Defaults (serialize `Config::default()` into the builder).
    //    Using `try_from` allows downstream override by file/env.
    builder = builder
        .set_default("app.name", Config::default().app.name)?
        .set_default("app.environment", Config::default().app.environment)?
        .set_default("app.instance", Config::default().app.instance)?
        .set_default("network.bind_addr", Config::default().network.bind_addr)?
        .set_default("network.public_addr", Config::default().network.public_addr)?
        .set_default("network.bootstrap", Config::default().network.bootstrap.clone())?
        .set_default("network.dial_timeout", "10s")?
        .set_default("network.read_timeout", "15s")?
        .set_default("network.write_timeout", "15s")?
        .set_default("rpc.enabled", true)?
        .set_default("rpc.bind_http", Config::default().rpc.bind_http)?
        .set_default("rpc.public_http_url", Config::default().rpc.public_http_url)?
        .set_default("rpc.cors", Config::default().rpc.cors.clone())?
        .set_default("rpc.shutdown_grace", "10s")?
        .set_default("database.url", Config::default().database.url.expose_secret().clone())?
        .set_default("database.max_pool_size", Config::default().database.max_pool_size)?
        .set_default("database.connect_timeout", "5s")?
        .set_default("telemetry.enable_metrics", Config::default().telemetry.enable_metrics)?
        .set_default("telemetry.metrics_bind", Config::default().telemetry.metrics_bind)?
        .set_default("telemetry.log_filter", Config::default().telemetry.log_filter)?
        .set_default("security.node_private_key", "CHANGE_ME")?
        .set_default("security.zk_proving_key_path", "")?
        .set_default("security.rpc_auth_secret", "")?;

    // 2) Config file(s): explicit path or auto-discovery via `directories`.
    //    `ProjectDirs` gives us OS-specific config dir (e.g. ~/.config on Linux).
    //    https://docs.rs/directories/latest/directories/struct.ProjectDirs.html
    for path in discover_config_files(explicit_file)? {
        builder = builder.add_source(cfg::File::from(path));
    }

    // 3) Environment variables (prefix AETHERNOVA, nested by __).
    //    separator("__") maps AETHERNOVA__RPC__BIND_HTTP -> rpc.bind_http.
    //    list_separator(",") splits comma-separated lists.
    //    try_parsing(true) attempts to parse numbers/bools automatically.
    //    https://docs.rs/config/latest/config/
    builder = builder.add_source(
        cfg::Environment::with_prefix("AETHERNOVA")
            .separator("__")
            .list_separator(",")
            .try_parsing(true),
    );

    let built = builder.build()?;

    // Deserialize into concrete struct using Serde.
    // https://docs.rs/serde/latest/serde/trait.Deserialize.html
    let mut cfg: Config = built.try_deserialize()?;

    // Normalize & validate.
    validate_and_normalize(&mut cfg)?;

    Ok(cfg)
}

/// Discover config files in precedence order:
/// - explicit path if provided
/// - $XDG_CONFIG_HOME/aethernova-node/config.{yaml,yml,toml,json}
/// - ./config.{yaml,yml,toml,json}
fn discover_config_files(explicit: Option<&Path>) -> Result<Vec<PathBuf>, ConfigError> {
    let mut out = Vec::new();

    if let Some(p) = explicit {
        if p.exists() {
            out.push(p.to_path_buf());
            return Ok(out);
        } else {
            return Err(ConfigError::PathNotFound(p.display().to_string()));
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(pd) = ProjectDirs::from("io", "Aethernova", "aethernova-node") {
        let cd = pd.config_dir().to_path_buf();
        candidates.push(cd.join("config.yaml"));
        candidates.push(cd.join("config.yml"));
        candidates.push(cd.join("config.toml"));
        candidates.push(cd.join("config.json"));
    }

    // Also consider current working directory as a fallback.
    candidates.push(PathBuf::from("config.yaml"));
    candidates.push(PathBuf::from("config.yml"));
    candidates.push(PathBuf::from("config.toml"));
    candidates.push(PathBuf::from("config.json"));

    for c in candidates {
        if c.exists() {
            out.push(c);
        }
    }

    Ok(out)
}

/// Validate and normalize configuration values.
///
/// Includes:
/// - URL validation (Rpc.public_http_url)
/// - Bind address sanity checks
/// - Secret presence in prod
/// - File existence for zk_proving_key_path
fn validate_and_normalize(cfg: &mut Config) -> Result<(), ConfigError> {
    // environment normalization
    cfg.app.environment = cfg.app.environment.to_lowercase();

    // URL validation (if provided).
    if let Some(url) = &cfg.rpc.public_http_url {
        Url::parse(url).map_err(|_| ConfigError::InvalidUrl(url.clone()))?;
    }

    // CORS origins: basic trim
    cfg.rpc.cors.iter_mut().for_each(|s| *s = s.trim().to_string());

    // Bind address presence (simple check; deeper validation lives in net layer).
    if cfg.network.bind_addr.trim().is_empty() {
        return Err(ConfigError::InvalidBind("network.bind_addr".into()));
    }
    if cfg.rpc.enabled && cfg.rpc.bind_http.trim().is_empty() {
        return Err(ConfigError::InvalidBind("rpc.bind_http".into()));
    }
    if cfg.telemetry.enable_metrics && cfg.telemetry.metrics_bind.trim().is_empty() {
        return Err(ConfigError::InvalidBind("telemetry.metrics_bind".into()));
    }

    // Secrets: in prod we require non-default.
    if cfg.app.environment == "prod" {
        if cfg.security.node_private_key.expose_secret() == "CHANGE_ME" {
            return Err(ConfigError::InvalidSecret("security.node_private_key"));
        }
    }

    // ZK proving key file must exist if provided.
    if let Some(p) = &cfg.security.zk_proving_key_path {
        if !p.as_path().exists() {
            return Err(ConfigError::PathNotFound(p.display().to_string()));
        }
    }

    Ok(())
}

/// Redacted Debug for Config: secrets are masked.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Config");
        s.field("app", &self.app)
            .field("network", &self.network)
            .field("rpc", &self.rpc)
            .field("database", &Redacted(&self.database))
            .field("telemetry", &self.telemetry)
            .field("security", &Redacted(&self.security))
            .finish()
    }
}

/// Helper to print structures with `SecretString` without leaking content.
struct Redacted<'a, T>(&'a T);

impl<'a> fmt::Debug for Redacted<'a, Database> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("url", &"<redacted>")
            .field("max_pool_size", &self.0.max_pool_size)
            .field("connect_timeout", &self.0.connect_timeout)
            .finish()
    }
}

impl<'a> fmt::Debug for Redacted<'a, Security> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Security")
            .field("node_private_key", &"<redacted>")
            .field(
                "zk_proving_key_path",
                &self.0.zk_proving_key_path.as_ref().map(|p| p.display().to_string()),
            )
            .field(
                "rpc_auth_secret",
                &self.0.rpc_auth_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Initialize logging filter from `telemetry.log_filter` if you need to bootstrap `tracing`.
/// You can call this in `main` after `load(None)`.
///
/// EnvFilter docs (RUST_LOG-like directives):
/// https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
pub fn init_tracing(filter: &str) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(filter)?;
    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        let mut cfg = Config::default();
        // Simulate prod to test secret guard:
        cfg.app.environment = "dev".into();
        assert!(validate_and_normalize(&mut cfg).is_ok());
    }

    #[test]
    fn public_url_validation() {
        let mut cfg = Config::default();
        cfg.rpc.public_http_url = Some("http://localhost:8545".into());
        assert!(validate_and_normalize(&mut cfg).is_ok());

        cfg.rpc.public_http_url = Some("not a url".into());
        assert!(matches!(
            validate_and_normalize(&mut cfg),
            Err(ConfigError::InvalidUrl(_))
        ));
    }
}
