//! telemetry/tracing.rs
//! Промышленная инициализация tracing + OpenTelemetry (OTLP).
//!
//! Зависимости (Cargo.toml):
//!   tracing = "0.1"
//!   tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "json"] }
//!   tracing-error = "0.2"
//!   tracing-opentelemetry = "0.28"
//!   opentelemetry = "0.30"
//!   opentelemetry_sdk = { version = "0.30", features = ["rt-tokio"] }
//!   opentelemetry-otlp = { version = "0.30", features = ["grpc-tonic", "http-proto", "http-json"] }
//!   opentelemetry-semantic-conventions = "0.16"
//!   tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
//!   anyhow = "1"
//!
//! Подтверждения ключевых API:
//! - EnvFilter, fmt layer: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
//! - ErrorLayer: https://docs.rs/tracing-error
//! - tracing-opentelemetry Layer: https://docs.rs/tracing-opentelemetry
//! - OTLP exporter (gRPC/HTTP): https://docs.rs/opentelemetry-otlp/latest
//! - service.* ресурсы: https://opentelemetry.io/docs/specs/semconv/resource/
//! - Пропагаторы: https://docs.rs/opentelemetry/latest/opentelemetry/propagation/
//! - Shutdown провайдера: https://docs.rs/opentelemetry_sdk/latest/opentelemetry_sdk/

use std::time::Duration;

use anyhow::Result;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue};
use opentelemetry_sdk::propagation::{BaggagePropagator, TextMapCompositePropagator, TraceContextPropagator};
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::trace::{self as sdktrace, Sampler};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Registry};
use tracing_error::ErrorLayer;

#[derive(Clone, Debug)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Clone, Debug)]
pub enum OtelProtocol {
    /// OTLP/gRPC (4317)
    Grpc,
    /// OTLP/HTTP Protobuf (обычно 4318, путь /v1/traces)
    HttpProtobuf,
    /// OTLP/HTTP JSON (обычно 4318, путь /v1/traces)
    HttpJson,
}

#[derive(Clone, Debug)]
pub struct OtelConfig {
    pub endpoint: String,            // пример: http://otel-collector:4317 или http://otel-collector:4318/v1/traces
    pub protocol: OtelProtocol,
    pub timeout: Duration,
    /// Доля семплирования [0.0..1.0] (None = дефолт провайдера).
    pub trace_ratio: Option<f64>,
    /// Подмешивать OTEL_RESOURCE_ATTRIBUTES / OTEL_SERVICE_NAME из окружения.
    pub merge_env_resource: bool,
}

#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    pub service_name: String,
    pub service_namespace: Option<String>,
    pub service_version: Option<String>,
    pub service_instance_id: Option<String>,
    pub deployment_env: Option<String>,

    pub log_filter: String,   // синтаксис RUST_LOG (e.g. "info,hyper=warn,mycrate=trace")
    pub log_format: LogFormat,
    pub with_span_events: bool,       // логировать открытие/закрытие span'ов
    pub include_source_location: bool, // file!()/line!()
    pub with_thread_ids: bool,

    pub otel: Option<OtelConfig>, // если None — только локальные логи без экспорта
}

/// Guard для корректного завершения провайдера при drop().
pub struct TelemetryGuard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Корректный shutdown провайдера: должен завершать процессоры и экспортер.
            // См. спецификацию SDK (Shutdown MUST be called once). 
            // https://opentelemetry.io/docs/specs/otel/trace/sdk/
            let _ = provider.shutdown();
        }
    }
}

/// Инициализация глобального subscriber'а tracing + опциональный OTLP Layer.
/// Вызывать один раз при старте процесса.
pub fn init(config: TelemetryConfig) -> Result<TelemetryGuard> {
    // Установим глобальный propagator: W3C TraceContext + Baggage.
    // https://docs.rs/opentelemetry/latest/opentelemetry/propagation/
    global::set_text_map_propagator(TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ]));

    // Фильтрация через EnvFilter (совместимо с RUST_LOG).
    // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
    let filter = EnvFilter::try_new(config.log_filter).unwrap_or_else(|_| EnvFilter::new("info"));

    // Форматирование логов.
    let mut fmt_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(config.with_thread_ids)
        .with_level(true);

    if config.include_source_location {
        fmt_layer = fmt_layer.with_file(true).with_line_number(true);
    }

    let fmt_layer = match config.log_format {
        LogFormat::Text => fmt_layer.boxed(),
        LogFormat::Json => fmt_layer.json().flatten_event(true).boxed(),
    };

    // ErrorLayer добавляет контекст ошибок к событиям.
    // https://docs.rs/tracing-error
    let error_layer = ErrorLayer::default();

    // Базовый реестр.
    let registry = Registry::default().with(filter).with(error_layer).with(fmt_layer);

    // Опционально добавим OpenTelemetry Layer.
    if let Some(otel_cfg) = config.otel.clone() {
        let (provider, tracer) = build_otel_tracer(&config, &otel_cfg)?;

        // Связка tracing → OpenTelemetry.
        // https://docs.rs/tracing-opentelemetry
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        registry.with(otel_layer).init();

        // Возвращаем guard, чтобы shutdown сработал корректно.
        Ok(TelemetryGuard {
            provider: Some(provider),
        })
    } else {
        // Только локальные логи без экспорта.
        registry.init();
        Ok(TelemetryGuard { provider: None })
    }
}

fn build_resource(config: &TelemetryConfig, merge_env: bool) -> Resource {
    use opentelemetry_semantic_conventions::resource as rsc;

    // Базовые атрибуты ресурса по семантическим конвенциям.
    // https://opentelemetry.io/docs/specs/semconv/resource/
    let mut attrs = vec![KeyValue::new(rsc::SERVICE_NAME, config.service_name.clone())];

    if let Some(ns) = &config.service_namespace {
        attrs.push(KeyValue::new(rsc::SERVICE_NAMESPACE, ns.clone()));
    }
    if let Some(ver) = &config.service_version {
        attrs.push(KeyValue::new(rsc::SERVICE_VERSION, ver.clone()));
    }
    if let Some(inst) = &config.service_instance_id {
        attrs.push(KeyValue::new(rsc::SERVICE_INSTANCE_ID, inst.clone()));
    }
    if let Some(env) = &config.deployment_env {
        attrs.push(KeyValue::new(rsc::DEPLOYMENT_ENVIRONMENT, env.clone()));
    }

    // Базовый ресурс из явных атрибутов.
    let base = Resource::new(attrs);

    // По необходимости объединяем с ресурсами из окружения (OTEL_RESOURCE_ATTRIBUTES / OTEL_SERVICE_NAME).
    // https://docs.rs/opentelemetry_sdk/latest/opentelemetry_sdk/resource/
    if merge_env {
        let env_res = opentelemetry_sdk::resource::EnvResourceDetector::new()
            .detect(std::time::Duration::from_secs(2));
        base.merge(&env_res)
    } else {
        base
    }
}

fn build_otel_tracer(
    svc: &TelemetryConfig,
    otel: &OtelConfig,
) -> Result<(opentelemetry_sdk::trace::SdkTracerProvider, opentelemetry_sdk::trace::Tracer)> {
    use opentelemetry_otlp::WithExportConfig;

    // Ресурсы
    let resource = build_resource(svc, otel.merge_env_resource);

    // Семплер
    // Sampler::TraceIdRatioBased(f) — доля от [0..1]; при None используем дефолт SDK.
    // https://prisma.github.io/prisma-engines/doc/opentelemetry/sdk/trace/enum.Sampler.html
    let sampler = otel
        .trace_ratio
        .map(|r| Sampler::TraceIdRatioBased(r))
        .unwrap_or(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)));

    // Билдим экспортер по протоколу.
    // Подтверждение протоколов и конфигурации OTLP: https://docs.rs/opentelemetry-otlp/latest
    let exporter = match otel.protocol {
        OtelProtocol::Grpc => {
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otel.endpoint.clone())
                .with_timeout(otel.timeout)
        }
        OtelProtocol::HttpProtobuf => {
            opentelemetry_otlp::new_exporter()
                .http() // HTTP Protobuf
                .with_endpoint(otel.endpoint.clone())
                .with_timeout(otel.timeout)
        }
        OtelProtocol::HttpJson => {
            opentelemetry_otlp::new_exporter()
                .http()
                .with_protocol(opentelemetry_otlp::Protocol::HttpJson)
                .with_endpoint(otel.endpoint.clone())
                .with_timeout(otel.timeout)
        }
    };

    // Провайдер + батч-процессор (требует Tokio runtime).
    // https://docs.rs/opentelemetry_sdk/latest/opentelemetry_sdk/trace/
    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            sdktrace::Config::default()
                .with_sampler(sampler)
                .with_resource(resource),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;

    let tracer = tracer_provider.tracer(env!("CARGO_PKG_NAME"));

    Ok((tracer_provider, tracer))
}

/// Пример удобного builder’a для конфигурации по умолчанию.
pub fn default_config(service_name: &str) -> TelemetryConfig {
    TelemetryConfig {
        service_name: service_name.to_string(),
        service_namespace: None,
        service_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        service_instance_id: None,
        deployment_env: None,

        log_filter: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        log_format: LogFormat::Text,
        with_span_events: false,
        include_source_location: true,
        with_thread_ids: true,

        otel: None,
    }
}

/// Утилита для интеграционных тестов: форсирует flush/Shutdown прямо сейчас.
pub fn force_flush(guard: &mut TelemetryGuard) {
    if let Some(provider) = guard.provider.as_ref() {
        let _ = provider.force_flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_resource() {
        let cfg = TelemetryConfig {
            service_name: "aethernova-node".into(),
            service_namespace: Some("aethernova".into()),
            service_version: Some("1.0.0".into()),
            service_instance_id: Some("node-1".into()),
            deployment_env: Some("prod".into()),
            log_filter: "info".into(),
            log_format: LogFormat::Json,
            with_span_events: true,
            include_source_location: true,
            with_thread_ids: true,
            otel: None,
        };
        let res = super::build_resource(&cfg, true);
        // smoke test
        assert!(res.len() >= 1);
    }
}
