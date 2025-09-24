//! Aethernova JSON-RPC 2.0 server module (HTTP).
//!
//! Implements JSON-RPC 2.0 per spec:
//! - Request object & "jsonrpc":"2.0", method, params, id (String | Number | Null). [Spec §4, §4.2]
//! - Notification is a request *without* "id"; MUST NOT reply (incl. in batch). [Spec §4.1, §6]
//! - Response object: result *or* error; echo id; Null id if id undetectable. [Spec §5, §5.1]
//! - Batch: array of 1..N; empty array -> single Invalid Request; all-notifications -> no response. [Spec §6]
//! Error codes: -32700 (Parse error), -32600 (Invalid Request), -32601 (Method not found),
//!              -32602 (Invalid params), -32603 (Internal error). [Spec §5.1]
//!
//! References:
//! - JSON-RPC 2.0 specification: https://www.jsonrpc.org/specification
//! - axum (HTTP framework): https://docs.rs/axum/latest/axum/
//! - tower_http CORS: https://docs.rs/tower-http/latest/tower_http/cors/
//! - serde_json: https://docs.rs/serde_json
//! - futures::future::BoxFuture: https://docs.rs/futures/latest/futures/future/type.BoxFuture.html
//! - tokio mpsc: https://docs.rs/tokio/latest/tokio/sync/mpsc/

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unused_must_use, unreachable_pub)]

use axum::{
    body::Bytes,
    extract::{State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use futures::{future::BoxFuture, FutureExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Number, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::RwLock;
use tower::{limit::ConcurrencyLimitLayer, timeout::TimeoutLayer, ServiceBuilder};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, instrument, warn};

/// JSON-RPC version string constant.
pub const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC reserved error codes. [Spec §5.1]
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    // -32000..-32099 are server-defined
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Str(String),
    Num(Number),
    Null,
}

impl From<Option<Value>> for Id {
    fn from(v: Option<Value>) -> Self {
        match v {
            None => Id::Null,
            Some(Value::String(s)) => Id::Str(s),
            Some(Value::Number(n)) => Id::Num(n),
            Some(Value::Null) => Id::Null,
            // Any other type is invalid for id; caller should have rejected earlier,
            // but fallback to Null per spec when id is undetectable. [Spec §5:id]
            _ => Id::Null,
        }
    }
}

impl From<&Id> for Value {
    fn from(id: &Id) -> Self {
        match id {
            Id::Str(s) => Value::String(s.clone()),
            Id::Num(n) => Value::Number(n.clone()),
            Id::Null => Value::Null,
        }
    }
}

/// Incoming request as a loose shape to validate by spec.
#[derive(Debug, Deserialize)]
struct RawRequest {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>, // Array|Object only when present [Spec §4.2]
    #[serde(default)]
    id: Option<Value>, // String|Number|Null when present [Spec §4]
}

#[derive(Debug, Serialize)]
struct ResponseSuccess<'a> {
    jsonrpc: &'a str,
    result: Value,
    id: Value,
}

#[derive(Debug, Serialize)]
struct ErrorObject {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Debug, Serialize)]
struct ResponseError<'a> {
    jsonrpc: &'a str,
    error: ErrorObject,
    id: Value, // MUST be same id; Null if id undetectable [Spec §5]
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("parse error")]
    Parse(#[source] serde_json::Error),
    #[error("invalid request")]
    InvalidRequest(String),
    #[error("method not found")]
    MethodNotFound,
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("internal error")]
    Internal(anyhow::Error),
}

impl RpcError {
    fn code(&self) -> ErrorCode {
        match self {
            RpcError::Parse(_) => ErrorCode::ParseError,
            RpcError::InvalidRequest(_) => ErrorCode::InvalidRequest,
            RpcError::MethodNotFound => ErrorCode::MethodNotFound,
            RpcError::InvalidParams(_) => ErrorCode::InvalidParams,
            RpcError::Internal(_) => ErrorCode::InternalError,
        }
    }
    fn message(&self) -> &'static str {
        match self {
            RpcError::Parse(_) => "Parse error",
            RpcError::InvalidRequest(_) => "Invalid Request",
            RpcError::MethodNotFound => "Method not found",
            RpcError::InvalidParams(_) => "Invalid params",
            RpcError::Internal(_) => "Internal error",
        }
    }
}

/// Request context (minimal; extend as needed).
#[derive(Clone, Debug)]
pub struct RequestContext {
    pub headers: HeaderMap,
    pub deadline: Option<Duration>,
}

/// Async method handler signature.
pub type RpcHandler =
    Arc<dyn Fn(Option<Value>, RequestContext) -> BoxFuture<'static, Result<Value, RpcError>> + Send + Sync>;

/// Create handler from async closure.
pub fn handler<F, Fut>(f: F) -> RpcHandler
where
    F: Fn(Option<Value>, RequestContext) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Value, RpcError>> + Send + 'static,
{
    Arc::new(move |params, ctx| f(params, ctx).boxed())
}

/// Method registry (thread-safe).
#[derive(Clone, Default)]
pub struct MethodRegistry {
    inner: Arc<RwLock<HashMap<String, RpcHandler>>>,
}

impl MethodRegistry {
    pub async fn register(&self, method: impl Into<String>, h: RpcHandler) {
        self.inner.write().await.insert(method.into(), h);
    }
    async fn get(&self, method: &str) -> Option<RpcHandler> {
        self.inner.read().await.get(method).cloned()
    }
}

/// Server state.
#[derive(Clone)]
pub struct AppState {
    registry: MethodRegistry,
}

impl AppState {
    pub fn new(registry: MethodRegistry) -> Self {
        Self { registry }
    }
}

/// Build axum router with middleware (CORS, timeouts, concurrency).
pub fn router(state: AppState) -> Router {
    let middleware = ServiceBuilder::new()
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(ConcurrencyLimitLayer::new(1024));

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    Router::new()
        .route("/", post(http_entrypoint))
        .with_state(state)
        .layer(middleware)
        .layer(cors)
}

/// HTTP entrypoint: reads raw body to control JSON parse errors (-32700). [Spec §5.1 Parse error]
#[instrument(name = "jsonrpc_http", skip_all, fields(len = body.len()))]
async fn http_entrypoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Parse raw JSON
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let err = error_response(None, RpcError::Parse(e));
            return (StatusCode::OK, axum::Json(err)).into_response();
        }
    };

    let ctx = RequestContext { headers, deadline: None };

    // Batch or single
    match value {
        Value::Array(arr) => {
            if arr.is_empty() {
                // Empty batch -> single Invalid Request with id null. [Spec §6, Examples]
                let err = error_response(None, RpcError::InvalidRequest("empty batch".into()));
                return (StatusCode::OK, axum::Json(err)).into_response();
            }

            // Process each element; skip notifications (no id) from response array.
            let mut futures = Vec::with_capacity(arr.len());
            for v in arr {
                futures.push(process_single(&state, v, ctx.clone()));
            }
            let results = futures::future::join_all(futures).await;

            let mut responses = Vec::new();
            for r in results {
                if let Some(resp) = r {
                    responses.push(resp);
                }
            }

            if responses.is_empty() {
                // All were notifications -> MUST NOT return anything. [Spec §6, all notifications]
                return StatusCode::NO_CONTENT.into_response();
            }
            (StatusCode::OK, axum::Json(Value::Array(responses))).into_response()
        }
        _ => {
            match process_single(&state, value, ctx).await {
                None => StatusCode::NO_CONTENT.into_response(), // single notification (no id) -> no response. [Spec §4.1]
                Some(resp) => (StatusCode::OK, axum::Json(resp)).into_response(),
            }
        }
    }
}

/// Process a single request object or return error.
async fn process_single(state: &AppState, v: Value, ctx: RequestContext) -> Option<Value> {
    // Must be object. [Spec §4]
    let obj = match v {
        Value::Object(m) => m,
        _ => {
            // Invalid Request; id undetectable -> id: null. [Spec §5:id]
            return Some(serde_json::to_value(error_response(None, RpcError::InvalidRequest("not an object".into()))).unwrap());
        }
    };

    // Deserialize loosely, then validate members.
    let raw: RawRequest = match serde_json::from_value(Value::Object(obj)) {
        Ok(r) => r,
        Err(e) => {
            return Some(serde_json::to_value(error_response(None, RpcError::Parse(e))).unwrap());
        }
    };

    // Validate "jsonrpc"
    if raw.jsonrpc.as_deref() != Some(JSONRPC_VERSION) {
        return Some(serde_json::to_value(error_response(raw.id.clone(), RpcError::InvalidRequest("jsonrpc != 2.0".into()))).unwrap());
    }

    // Validate method
    let method = match raw.method {
        Some(m) if !m.is_empty() => m,
        _ => {
            return Some(serde_json::to_value(error_response(raw.id.clone(), RpcError::InvalidRequest("method missing/invalid".into()))).unwrap());
        }
    };

    // Validate params when present (must be array or object) [Spec §4.2]
    if let Some(ref p) = raw.params {
        match p {
            Value::Array(_) | Value::Object(_) => {}
            _ => {
                return Some(serde_json::to_value(error_response(raw.id.clone(), RpcError::InvalidParams("params must be array or object".into()))).unwrap());
            }
        }
    }

    // Notification: no "id" member -> no response. [Spec §4.1]
    let is_notification = raw.id.is_none();
    let id = Id::from(raw.id);

    // Lookup and call method.
    let handler = state.registry.get(&method).await;
    let handler = match handler {
        Some(h) => h,
        None => {
            if is_notification {
                // Notifications MUST NOT receive a response; on unknown method, do nothing. [Spec §4.1]
                return None;
            }
            return Some(serde_json::to_value(error_response(Some(Value::from(&id)), RpcError::MethodNotFound)).unwrap());
        }
    };

    let res = handler(raw.params, ctx).await;

    if is_notification {
        return None;
    }

    match res {
        Ok(result) => Some(serde_json::to_value(ResponseSuccess {
            jsonrpc: JSONRPC_VERSION,
            result,
            id: Value::from(&id),
        }).unwrap()),
        Err(e) => Some(serde_json::to_value(error_response(Some(Value::from(&id)), e)).unwrap()),
    }
}

fn error_response(id: Option<Value>, err: RpcError) -> ResponseError<'static> {
    let idv = id.unwrap_or(Value::Null); // id undetectable -> Null [Spec §5:id]
    let data = match &err {
        RpcError::Parse(e) => Some(json!({ "detail": e.to_string() })),
        RpcError::InvalidRequest(msg) => Some(json!({ "detail": msg })),
        RpcError::InvalidParams(msg) => Some(json!({ "detail": msg })),
        RpcError::MethodNotFound => None,
        RpcError::Internal(e) => Some(json!({ "detail": format!("{:#}", e) })),
    };

    ResponseError {
        jsonrpc: JSONRPC_VERSION,
        error: ErrorObject {
            code: err.code() as i64,
            message: err.message().to_string(),
            data,
        },
        id: idv,
    }
}

/// Optional helper: register built-in methods (e.g., health).
pub async fn register_builtin(registry: &MethodRegistry) {
    registry
        .register(
            "rpc.health",
            handler(|_, _| async move { Ok(json!({"status":"ok"})) }),
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn state_with_echo() -> AppState {
        let reg = MethodRegistry::default();
        tokio_test::block_on(async {
            reg.register("echo", handler(|p, _| async move {
                Ok(json!({ "params": p }))
            })).await;
        });
        AppState::new(reg)
    }

    #[tokio::test]
    async fn parse_error_invalid_json() {
        let state = state_with_echo();
        let headers = HeaderMap::new();
        // broken JSON -> -32700 Parse error
        let resp = super::http_entrypoint(
            axum::extract::State(state),
            headers,
            Bytes::from_static(br#"{"jsonrpc": "2.0", "method": "echo", "#),
        ).await;

        let (status, body) = split(resp);
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#""code":-32700"#), "expect Parse error");
    }

    #[tokio::test]
    async fn empty_batch_invalid_request() {
        let state = state_with_echo();
        let headers = HeaderMap::new();
        let resp = super::http_entrypoint(
            axum::extract::State(state),
            headers,
            Bytes::from_static(br#"[]"#),
        ).await;

        let (status, body) = split(resp);
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#""code":-32600"#), "expect Invalid Request");
    }

    #[tokio::test]
    async fn notification_no_response() {
        let state = state_with_echo();
        let headers = HeaderMap::new();
        // Notification: no "id"
        let resp = super::http_entrypoint(
            axum::extract::State(state),
            headers,
            Bytes::from_static(br#"{"jsonrpc":"2.0","method":"echo","params":[1,2,3]}"#),
        ).await;

        let (status, body) = split(resp);
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
    }

    fn split(resp: Response) -> (StatusCode, String) {
        use axum::body::to_bytes;
        use futures::executor::block_on;
        let status = resp.status();
        let body = block_on(to_bytes(resp.into_body())).unwrap();
        (status, String::from_utf8_lossy(&body).to_string())
    }
}
