//! RPC module: industrial HTTP JSON-RPC 2.0 server for Aethernova Node.
//!
//! Stack:
//! - Axum router + tower-http (CORS, Trace) + tower layers (timeouts, limits) .
//! - Graceful shutdown via axum::serve.with_graceful_shutdown + Tokio Ctrl-C.
//! - Optional Bearer auth using constant-time equality (`subtle`).
//!
//! References:
//! - Axum web framework (routing, extractors, serve): https://docs.rs/axum/latest/axum/
//! - tower-http CORS: https://docs.rs/tower-http/latest/tower_http/cors/
//! - tower-http Trace: https://docs.rs/tower-http/latest/tower_http/trace/
//! - Tokio Ctrl-C: https://docs.rs/tokio/latest/tokio/signal/fn.ctrl_c.html
//! - axum graceful shutdown: https://docs.rs/axum/latest/axum/serve/struct.WithGracefulShutdown.html
//! - JSON-RPC 2.0 spec: https://www.jsonrpc.org/specification
//! - tracing-subscriber EnvFilter: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
//! - subtle::ConstantTimeEq: https://docs.rs/subtle/latest/subtle/trait.ConstantTimeEq.html

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{State, FromRef},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{select, sync::Notify};
use tower::{ServiceBuilder, limit::ConcurrencyLimitLayer, timeout::TimeoutLayer};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use subtle::ConstantTimeEq;

// Reuse your existing config if available. Minimal local copy for decoupled build.
#[derive(Clone)]
pub struct RpcConfig {
    pub bind_http: String,
    pub cors: Vec<String>,
    pub shutdown_grace: Duration,
    pub bearer_secret: Option<String>, // if Some => require "Authorization: Bearer <secret>"
}

impl FromRef<RpcConfig> for RpcConfig {
    fn from_ref(input: &RpcConfig) -> Self { input.clone() }
}

/// Public handle for controlling the server (programmatic shutdown).
#[derive(Clone)]
pub struct RpcHandle {
    notify: Arc<Notify>,
}

impl RpcHandle {
    pub fn shutdown(&self) {
        self.notify.notify_waiters();
    }
}

/// Boot the HTTP JSON-RPC server; returns a handle and the spawned task.
///
/// Cancellation is graceful: either Ctrl-C or handle.shutdown().
pub async fn start_http(config: RpcConfig) -> anyhow::Result<RpcHandle> {
    let state = AppState::new(config.clone());

    let cors = build_cors(&config.cors)?;
    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http()) // access-log & spans
        .layer(ConcurrencyLimitLayer::new(512))
        .layer(TimeoutLayer::new(Duration::from_secs(15)));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/rpc", post(jsonrpc))
        .with_state(state)
        .layer(cors)
        .layer(middleware);

    let addr: SocketAddr = config.bind_http
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind_http: {} ({e})", config.bind_http))?;

    let handle = RpcHandle { notify: Arc::new(Notify::new()) };

    info!("rpc: starting HTTP server at http://{addr}");
    let server = axum::serve(
        tokio::net::TcpListener::bind(addr).await?,
        app.into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal(handle.clone(), config.shutdown_grace));

    tokio::spawn(async move {
        if let Err(err) = server.await {
            error!("rpc: server error: {err}");
        }
    });

    Ok(handle)
}

/// Wait for either Ctrl-C or programmatic signal, then wait `grace` and return.
async fn shutdown_signal(handle: RpcHandle, grace: Duration) {
    // OS signal future:
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("rpc: failed to install Ctrl-C handler: {e}");
        }
    };

    // Programmatic notify future:
    let notified = handle.notify.notified();

    select! {
        _ = ctrl_c => info!("rpc: Ctrl-C received, shutting down..."),
        _ = notified => info!("rpc: shutdown requested, shutting down..."),
    }

    // Optional grace period to drain in-flight requests.
    if !grace.is_zero() {
        info!("rpc: waiting graceful shutdown grace={:?}", grace);
        tokio::time::sleep(grace).await;
    }
}

fn build_cors(origins: &[String]) -> anyhow::Result<CorsLayer> {
    // If `*` present -> allow any origin; else allow explicit list.
    let cors = if origins.iter().any(|o| o == "*" ) {
        CorsLayer::new()
            .allow_methods([Method::POST, Method::OPTIONS, Method::GET])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
            .allow_origin(Any)
    } else {
        let parsed: Vec<HeaderValue> = origins.iter()
            .filter_map(|s| s.parse::<HeaderValue>().ok())
            .collect();
        CorsLayer::new()
            .allow_methods([Method::POST, Method::OPTIONS, Method::GET])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
            .allow_origin(parsed)
    };
    Ok(cors)
}

#[derive(Clone)]
struct AppState {
    cfg: RpcConfig,
}

impl AppState {
    fn new(cfg: RpcConfig) -> Self { Self { cfg } }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    id: Option<Value>, // number | string | null
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse<'a> {
    jsonrpc: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl JsonRpcError {
    fn invalid_request() -> Self {
        Self { code: -32600, message: "Invalid Request".into(), data: None }
    }
    fn method_not_found() -> Self {
        Self { code: -32601, message: "Method not found".into(), data: None }
    }
    fn invalid_params(msg: &str) -> Self {
        Self { code: -32602, message: "Invalid params".into(), data: Some(json!(msg)) }
    }
    fn internal(msg: &str) -> Self {
        Self { code: -32603, message: "Internal error".into(), data: Some(json!(msg)) }
    }
}

// Health endpoint
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

// JSON-RPC entrypoint
async fn jsonrpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<JsonRpcRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    // Auth (if configured)
    if let Some(secret) = &state.cfg.bearer_secret {
        match bearer_token(&headers) {
            Some(token) if ct_eq(token.as_bytes(), secret.as_bytes()) => {}
            _ => return unauthorized(),
        }
    }

    // Parse JSON
    let req = match payload {
        Ok(Json(req)) => req,
        Err(rej) => {
            let resp = JsonRpcResponse {
                jsonrpc: "2.0",
                result: None,
                error: Some(JsonRpcError::invalid_request()),
                id: None,
            };
            return (StatusCode::BAD_REQUEST, Json(resp)).into_response();
        }
    };

    // Validate version
    if req.jsonrpc != "2.0" {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError::invalid_request()),
            id: req.id.clone(),
        };
        return (StatusCode::BAD_REQUEST, Json(resp)).into_response();
    }

    // Dispatch
    let result = match req.method.as_str() {
        "ping" => Ok(json!("pong")),
        "version" => Ok(json!(env!("CARGO_PKG_VERSION"))),
        // add real methods here
        _ => Err(JsonRpcError::method_not_found()),
    };

    // Build response (exactly one of result/error, per JSON-RPC 2.0)
    let resp = match result {
        Ok(val) => JsonRpcResponse { jsonrpc: "2.0", result: Some(val), error: None, id: req.id },
        Err(err) => JsonRpcResponse { jsonrpc: "2.0", result: None, error: Some(err), id: req.id },
    };

    (StatusCode::OK, Json(resp)).into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let prefix = "Bearer ";
    if auth.len() > prefix.len() && auth.starts_with(prefix) {
        Some(auth[prefix.len()..].to_owned())
    } else {
        None
    }
}

/// Constant-time equality for secrets
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

fn unauthorized() -> Response {
    let mut res = (StatusCode::UNAUTHORIZED, Json(json!({
        "jsonrpc": "2.0",
        "error": { "code": -32001, "message": "Unauthorized" },
        "id": null
    }))).into_response();
    res.headers_mut().insert(axum::http::header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_constant_time() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"other"));
    }

    #[test]
    fn bearer_parsing() {
        let mut hm = HeaderMap::new();
        hm.insert(axum::http::header::AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert_eq!(bearer_token(&hm).as_deref(), Some("abc"));
    }
}
