//! Explorer API routes (Axum).
//!
//! Crate deps (Cargo.toml excerpt):
//!   axum = { version = "0.7", features = ["macros", "json"] }
//!   axum-extra = { version = "0.9", features = ["typed-header"] }
//!   tower = { version = "0.4", features = ["limit", "timeout"] }
//!   tower-http = { version = "0.5", features = ["cors", "trace", "compression-gzip", "decompression-gzip"] }
//!   serde = { version = "1", features = ["derive"] }
//!   serde_json = "1"
//!   utoipa = { version = "5", features = ["axum_extras", "uuid", "chrono"] }
//!   utoipa-swagger-ui = { version = "7", features = ["axum"] }
//!   http = "1"
//!   headers = "0.4"
//!   thiserror = "1"
//!   tracing = "0.1"
//!   sha2 = "0.10"
//!   hex = "0.4"
//!
//! NOTE: Реальная реализация сервисов подставляется через `AppState<S: ExplorerService>`.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::TypedHeader;
use headers::{ETag, HeaderMapExt, IfNoneMatch};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower::{limit::rate::RateLimitLayer, timeout::TimeoutLayer};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, instrument};
use sha2::{Digest, Sha256};

/// Public API types
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Block {
    pub id: String,
    pub height: u64,
    pub hash: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Tx {
    pub hash: String,
    pub block_id: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub fee: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AddressBalance {
    pub address: String,
    pub balance: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub page_size: u32,
    pub total: u64,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct Paging {
    /// Номер страницы (>=1)
    #[param(minimum = 1)]
    pub page: Option<u32>,
    /// Размер страницы (1..=100)
    #[param(minimum = 1, maximum = 100)]
    pub page_size: Option<u32>,
}

impl Paging {
    fn normalize(self) -> (u32, u32) {
        let p = self.page.unwrap_or(1).max(1);
        let ps = self.page_size.unwrap_or(25).clamp(1, 100);
        (p, ps)
    }
}

/// Service abstraction to decouple routes from storage/index.
#[allow(async_fn_in_trait)]
pub trait ExplorerService: Send + Sync + 'static {
    async fn get_block_by_id(&self, id: &str) -> Result<Option<Block>, ApiError>;
    async fn list_blocks(&self, page: u32, page_size: u32) -> Result<Page<Block>, ApiError>;
    async fn get_tx_by_hash(&self, hash: &str) -> Result<Option<Tx>, ApiError>;
    async fn list_txs(&self, page: u32, page_size: u32) -> Result<Page<Tx>, ApiError>;
    async fn get_address_balance(&self, addr: &str) -> Result<Option<AddressBalance>, ApiError>;
    async fn total_blocks(&self) -> Result<u64, ApiError>;
}

#[derive(Clone)]
pub struct AppState<S: ExplorerService> {
    pub svc: Arc<S>,
    /// Версия API для заголовков/ETag-соли
    pub api_version: &'static str,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response(),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response(),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":"internal"}))).into_response(),
        }
    }
}

/// OpenAPI
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        health,
        metrics,
        get_block,
        list_blocks,
        get_tx,
        list_txs,
        get_address_balance
    ),
    components(
        schemas(Block, Tx, AddressBalance, Page<Block>, Page<Tx>)
    ),
    tags(
        (name = "explorer", description = "Explorer read-only API")
    )
)]
pub struct ApiDoc;

/// Build router with middlewares and routes.
pub fn router<S: ExplorerService>(state: AppState<S>) -> Router {
    // CORS: permissive by default (customize for production origins)
    let cors = CorsLayer::new()
        .allow_methods([http::Method::GET, http::Method::POST, http::Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        .route("/healthz", get(health::<S>))
        .route("/metrics", get(metrics::<S>))
        .route("/v1/blocks/:id", get(get_block::<S>))
        .route("/v1/blocks", get(list_blocks::<S>))
        .route("/v1/txs/:hash", get(get_tx::<S>))
        .route("/v1/txs", get(list_txs::<S>))
        .route("/v1/address/:addr", get(get_address_balance::<S>))
        // OpenAPI JSON and Swagger UI (optional mount at /docs)
        .merge(utoipa_swagger_ui::SwaggerUi::new("/docs").url("/docs/openapi.json", ApiDoc::openapi()))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(RateLimitLayer::new(200, Duration::from_secs(1))) // 200 rps на инстанс
        .layer(cors)
        .with_state(state)
}

/// ETag helper: weak tag over stable JSON with API version salt.
fn compute_etag(api_version: &str, body: &[u8]) -> ETag {
    let mut hasher = Sha256::new();
    hasher.update(api_version.as_bytes());
    hasher.update(body);
    let hex = hex::encode(hasher.finalize());
    // Weak ETag (W/), т.к. gzip/transport могут менять представление
    ETag::from(format!("W/\"{}\"", hex))
}

/* ------------------------------- handlers ------------------------------- */

/// Health
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "explorer",
    responses(
        (status = 200, description = "OK")
    )
)]
#[instrument(skip_all)]
pub async fn health<S: ExplorerService>() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Metrics (Prometheus text exposition).
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "explorer",
    responses(
        (status = 200, description = "Prometheus metrics")
    )
)]
#[instrument(skip(state))]
pub async fn metrics<S: ExplorerService>(State(state): State<AppState<S>>) -> impl IntoResponse {
    // Минимальный пример метрик; в реальном коде интегрируйте prometheus::Registry.
    let total = state.svc.total_blocks().await.unwrap_or(0);
    let body = format!(
        "# HELP explorer_blocks_total Total number of indexed blocks\n# TYPE explorer_blocks_total counter\nexplorer_blocks_total {}\n",
        total
    );
    (StatusCode::OK, body)
}

/// GET /v1/blocks/{id}
#[utoipa::path(
    get,
    path = "/v1/blocks/{id}",
    params(
        ("id" = String, Path, description = "Block id (height or hash)")
    ),
    responses(
        (status = 200, body = Block),
        (status = 404, description = "Not found")
    )
)]
#[instrument(skip(state, if_none_match))]
pub async fn get_block<S: ExplorerService>(
    State(state): State<AppState<S>>,
    Path(id): Path<String>,
    if_none_match: Option<TypedHeader<IfNoneMatch>>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(block) = state.svc.get_block_by_id(&id).await? else {
        return Err(ApiError::NotFound);
    };
    let body = serde_json::to_vec(&block).map_err(|_| ApiError::Internal)?;
    let etag = compute_etag(state.api_version, &body);

    // If-None-Match handling (RFC 9110)
    if let Some(TypedHeader(cond)) = if_none_match {
        if cond.precondition_passes(&etag) == headers::etag::Precondition::NotModified {
            return Ok((StatusCode::NOT_MODIFIED, [ (header::ETAG, etag.to_string()) ]).into_response());
        }
    }

    let mut headers = HeaderMap::new();
    headers.typed_insert(etag);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=5"));
    Ok((StatusCode::OK, headers, Json(block)).into_response())
}

/// GET /v1/blocks?page=&page_size=
#[utoipa::path(
    get,
    path = "/v1/blocks",
    params(Paging),
    responses(
        (status = 200, body = Page<Block>)
    )
)]
#[instrument(skip(state, if_none_match))]
pub async fn list_blocks<S: ExplorerService>(
    State(state): State<AppState<S>>,
    Query(paging): Query<Paging>,
    if_none_match: Option<TypedHeader<IfNoneMatch>>,
) -> Result<impl IntoResponse, ApiError> {
    let (page, page_size) = paging.normalize();
    let page_data = state.svc.list_blocks(page, page_size).await?;
    let body = serde_json::to_vec(&page_data).map_err(|_| ApiError::Internal)?;
    let etag = compute_etag(state.api_version, &body);
    if let Some(TypedHeader(cond)) = if_none_match {
        if cond.precondition_passes(&etag) == headers::etag::Precondition::NotModified {
            return Ok((StatusCode::NOT_MODIFIED, [ (header::ETAG, etag.to_string()) ]).into_response());
        }
    }
    let mut headers = HeaderMap::new();
    headers.typed_insert(etag);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3"));
    Ok((StatusCode::OK, headers, Json(page_data)).into_response())
}

/// GET /v1/txs/{hash}
#[utoipa::path(
    get,
    path = "/v1/txs/{hash}",
    params(
        ("hash" = String, Path, description = "Transaction hash")
    ),
    responses(
        (status = 200, body = Tx),
        (status = 404, description = "Not found")
    )
)]
#[instrument(skip(state, if_none_match))]
pub async fn get_tx<S: ExplorerService>(
    State(state): State<AppState<S>>,
    Path(hash): Path<String>,
    if_none_match: Option<TypedHeader<IfNoneMatch>>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(tx) = state.svc.get_tx_by_hash(&hash).await? else {
        return Err(ApiError::NotFound);
    };
    let body = serde_json::to_vec(&tx).map_err(|_| ApiError::Internal)?;
    let etag = compute_etag(state.api_version, &body);
    if let Some(TypedHeader(cond)) = if_none_match {
        if cond.precondition_passes(&etag) == headers::etag::Precondition::NotModified {
            return Ok((StatusCode::NOT_MODIFIED, [ (header::ETAG, etag.to_string()) ]).into_response());
        }
    }
    let mut headers = HeaderMap::new();
    headers.typed_insert(etag);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3"));
    Ok((StatusCode::OK, headers, Json(tx)).into_response())
}

/// GET /v1/txs?page=&page_size=
#[utoipa::path(
    get,
    path = "/v1/txs",
    params(Paging),
    responses(
        (status = 200, body = Page<Tx>)
    )
)]
#[instrument(skip(state, if_none_match))]
pub async fn list_txs<S: ExplorerService>(
    State(state): State<AppState<S>>,
    Query(paging): Query<Paging>,
    if_none_match: Option<TypedHeader<IfNoneMatch>>,
) -> Result<impl IntoResponse, ApiError> {
    let (page, page_size) = paging.normalize();
    let page_data = state.svc.list_txs(page, page_size).await?;
    let body = serde_json::to_vec(&page_data).map_err(|_| ApiError::Internal)?;
    let etag = compute_etag(state.api_version, &body);
    if let Some(TypedHeader(cond)) = if_none_match {
        if cond.precondition_passes(&etag) == headers::etag::Precondition::NotModified {
            return Ok((StatusCode::NOT_MODIFIED, [ (header::ETAG, etag.to_string()) ]).into_response());
        }
    }
    let mut headers = HeaderMap::new();
    headers.typed_insert(etag);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=2"));
    Ok((StatusCode::OK, headers, Json(page_data)).into_response())
}

/// GET /v1/address/{addr}
#[utoipa::path(
    get,
    path = "/v1/address/{addr}",
    params(
        ("addr" = String, Path, description = "Address")
    ),
    responses(
        (status = 200, body = AddressBalance),
        (status = 404, description = "Not found")
    )
)]
#[instrument(skip(state, if_none_match))]
pub async fn get_address_balance<S: ExplorerService>(
    State(state): State<AppState<S>>,
    Path(addr): Path<String>,
    if_none_match: Option<TypedHeader<IfNoneMatch>>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(bal) = state.svc.get_address_balance(&addr).await? else {
        return Err(ApiError::NotFound);
    };
    let body = serde_json::to_vec(&bal).map_err(|_| ApiError::Internal)?;
    let etag = compute_etag(state.api_version, &body);
    if let Some(TypedHeader(cond)) = if_none_match {
        if cond.precondition_passes(&etag) == headers::etag::Precondition::NotModified {
            return Ok((StatusCode::NOT_MODIFIED, [ (header::ETAG, etag.to_string()) ]).into_response());
        }
    }
    let mut headers = HeaderMap::new();
    headers.typed_insert(etag);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=5"));
    Ok((StatusCode::OK, headers, Json(bal)).into_response())
}

/* --------------------------------- impls -------------------------------- */

impl From<anyhow::Error> for ApiError {
    fn from(_: anyhow::Error) -> Self { ApiError::Internal }
}

impl From<std::io::Error> for ApiError {
    fn from(_: std::io::Error) -> Self { ApiError::Internal }
}
