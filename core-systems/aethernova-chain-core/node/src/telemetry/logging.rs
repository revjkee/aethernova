//! Aethernova — logging & telemetry bootstrap.
//!
//! - Формат: текст или JSON (переключаемый), таймстемпы RFC3339 (UTC).
//! - EnvFilter: RUST_LOG / явная строка уровня.
//! - Захват `log` -> `tracing`.
//! - Опционально: OpenTelemetry (OTLP) экспорт трейсов + W3C Trace Context пропагация.
//!
//! Подтверждения:
//! - JSON-форматтер `tracing-subscriber`: prod-ориентированная структурная запись. 
//! - Временные метки RFC3339 через `UtcTime::rfc_3339()`. 
//! - OTLP-трассировка из `tracing` через `tracing-opentelemetry` и `opentelemetry-otlp`.
//! - Ресурсные атрибуты `service.name`/`service.version`/`deployment.environment` — семантические конвенции OTel Resources.
//! - W3C Trace Context (`traceparent`, `tracestate`) как стандарт пропагации.
//!
//! Источники: см. README блока ниже.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_docs)]

use std::{env, time::Duration};

use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};

/// Конфигурация логирования/телеметрии.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Строка фильтра уровней (пример: "info,aethernova=debug"), если None — читается RUST_LOG или "info".
    pub env_filter: Option<String>,
    /// Включить JSON-логирование (`true`) или человекочитаемый текст (`false`).
    pub json: bool,
    /// Печатать target, файл и номер строки.
    pub with_targets_and_lines: bool,
    /// Печатать thread id/names (для отладки).
    pub with_threads: bool,
    /// ANSI-раскраска (только для текстового формата).
    pub ansi: bool,
    /// Включить экспорт трейсов в OpenTelemetry OTLP.
    #[cfg(feature = "otel")]
    pub otlp: Option<OtelConfig>,
}

/// Конфигурация OpenTelemetry (активна при фиче `otel`).
#[cfg(feature = "otel")]
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// gRPC или HTTP OTLP endpoint (например, http://otel-collector:4317 для gRPC).
    pub endpoint: String,
    /// Имя сервиса (обязательный атрибут).
    pub service_name: String,
    /// Версия сервиса (опционально).
    pub service_version: Option<String>,
    /// Окружение (dev|stage|prod и т.п.).
    pub environment: Option<String>,
    /// Таймаут экспорта.
    pub export_timeout: Duration,
    /// Семплер (например, 1.0 — всегда, 0.1 — 10%).
    pub sampler_ratio: f64,
    /// Доп. заголовки OTLP (например, аутентификация).
    pub otlp_headers: Vec<(String, String)>,
}

/// Объект, гарантирующий корректное выключение подсистем.
pub struct LoggingGuard {
    #[cfg(feature = "otel")]
    _otel: Option<OtelGuard>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            env_filter: None,
            json: true,
            with_targets_and_lines: true,
            with_threads: false,
            ansi: false,
            #[cfg(feature = "otel")]
            otlp: None,
        }
    }
}

/// Инициализация логирования и, опционально, OpenTelemetry.
/// Вызывать один раз в старте процесса.
pub fn init(cfg: LoggingConfig) -> anyhow::Result<LoggingGuard> {
    // 1) Захват log -> tracing (библиотеки на log!)
    let _ = tracing_log::LogTracer::init();

    // 2) EnvFilter
    let filter = match &cfg.env_filter {
        Some(s) => EnvFilter::try_new(s.as_str()).unwrap_or_else(|_| EnvFilter::new("info")),
        None => EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info")),
    };

    // 3) Формат вывода
    let fmt_layer = {
        let base = fmt::layer()
            .with_target(cfg.with_targets_and_lines)
            .with_file(cfg.with_targets_and_lines)
            .with_line_number(cfg.with_targets_and_lines)
            .with_thread_ids(cfg.with_threads)
            .with_thread_names(cfg.with_threads)
            // RFC3339 (UTC) таймер
            .with_timer(fmt::time::UtcTime::rfc_3339());

        if cfg.json {
            base.json()
                .with_ansi(false)
                .with_current_span(true)
                .with_span_list(true)
                .flatten_event(true)
                .boxed()
        } else {
            base
                .with_ansi(cfg.ansi)
                .boxed()
        }
    };

    // 4) Сборка Subscriber + (опционально) OTLP layer
    #[cfg(feature = "otel")]
    {
        if let Some(otel) = cfg.otlp.clone() {
            let (otel_layer, guard) = build_otel_layer(otel)?;
            Registry::default()
                .with(filter)
                .with(otel_layer)
                .with(fmt_layer)
                .init();

            return Ok(LoggingGuard { _otel: Some(guard) });
        }
    }

    Registry::default()
        .with(filter)
        .with(fmt_layer)
        .init();

    Ok(LoggingGuard {
        #[cfg(feature = "otel")]
        _otel: None,
    })
}

#[cfg(feature = "otel")]
fn build_otel_layer(otel: OtelConfig) -> anyhow::Result<(tracing_opentelemetry::OpenTelemetryLayer<Registry, opentelemetry_sdk::trace::Tracer>, OtelGuard)> {
    use opentelemetry::{global, KeyValue};
    use opentelemetry::trace::TraceError;
    use opentelemetry_sdk::{
        propagation::TraceContextPropagator,
        resource::Resource,
        trace::{self as sdktrace, Sampler},
        Resource as _,
    };
    use opentelemetry_otlp::WithExportConfig;

    // Пропагатор W3C trace-context (traceparent/tracestate).
    // https://www.w3.org/TR/trace-context/
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Ресурсные атрибуты — см. семантические конвенции.
    // https://opentelemetry.io/docs/specs/semconv/resource/
    let mut resource = Resource::default().merge(&Resource::new(vec![
        KeyValue::new("service.name", otel.service_name.clone()),
    ]));

    if let Some(ver) = &otel.service_version {
        resource = resource.merge(&Resource::new(vec![KeyValue::new("service.version", ver.clone())]));
    }
    if let Some(env) = &otel.environment {
        resource = resource.merge(&Resource::new(vec![KeyValue::new("deployment.environment", env.clone())]));
    }

    // Семплер
    let sampler = if (otel.sampler_ratio - 1.0).abs() < f64::EPSILON {
        Sampler::AlwaysOn
    } else if (otel.sampler_ratio).abs() < f64::EPSILON {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(otel.sampler_ratio)
    };

    // Экспортер OTLP (gRPC или HTTP определяется по endpoint и feature-флагам `opentelemetry-otlp`).
    // https://crates.io/crates/opentelemetry-otlp
    let mut exporter = opentelemetry_otlp::new_exporter().tonic().with_endpoint(otel.endpoint.clone());
    for (k, v) in &otel.otlp_headers {
        exporter = exporter.with_metadata([(k.as_str(), v.as_str())]);
    }

    // Провайдер/трасер
    // https://docs.rs/opentelemetry
    let tracer_provider = sdktrace::TracerProvider::builder()
        .with_config(
            sdktrace::Config::default()
                .with_resource(resource)
                .with_sampler(sampler),
        )
        .with_batch_exporter(
            opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(exporter)
                .with_trace_config(Default::default())
                .build_exporter()?,
            // Настраиваем батчер (по умолчанию подходит большинству случаев)
        )
        .build();

    let tracer = tracer_provider.tracer("aethernova");

    // Подключаем слой `tracing-opentelemetry` к Registry.
    // https://docs.rs/tracing-opentelemetry
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Устанавливаем провайдер глобально для корректного shutdown.
    global::set_tracer_provider(tracer_provider);

    Ok((layer, OtelGuard))
}

/// Guard, корректно завершающий OTLP-экспорт при Drop.
#[cfg(feature = "otel")]
struct OtelGuard;

#[cfg(feature = "otel")]
impl Drop for OtelGuard {
    fn drop(&mut self) {
        // Завершает экспортер/провайдер корректно, чтобы не потерять батчи.
        opentelemetry::global::shutdown_tracer_provider();
    }
}

/// Быстрая инициализация из окружения:
/// - LOG_JSON=true|false
/// - LOG_ANSI=true|false
/// - LOG_THREADS=true|false
/// - RUST_LOG=<фильтр>
/// - OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME, OTEL_SERVICE_VERSION, OTEL_ENV, OTEL_SAMPLER_RATIO
pub fn init_from_env() -> anyhow::Result<LoggingGuard> {
    let json = env::var("LOG_JSON").map(|v| v == "true").unwrap_or(true);
    let ansi = env::var("LOG_ANSI").map(|v| v == "true").unwrap_or(false);
    let threads = env::var("LOG_THREADS").map(|v| v == "true").unwrap_or(false);

    #[cfg(feature = "otel")]
    let otlp = match env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        Ok(endpoint) if !endpoint.is_empty() => Some(OtelConfig {
            endpoint,
            service_name: env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "aethernova-node".into()),
            service_version: env::var("OTEL_SERVICE_VERSION").ok(),
            environment: env::var("OTEL_ENV").ok(),
            export_timeout: Duration::from_secs(10),
            sampler_ratio: env::var("OTEL_SAMPLER_RATIO").ok().and_then(|s| s.parse().ok()).unwrap_or(1.0),
            otlp_headers: vec![],
        }),
        _ => None,
    };

    let cfg = LoggingConfig {
        env_filter: None,
        json,
        with_targets_and_lines: true,
        with_threads: threads,
        ansi,
        #[cfg(feature = "otel")]
        otlp,
    };

    init(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_default_text() {
        let _ = init(LoggingConfig {
            env_filter: Some("debug".into()),
            json: false,
            with_targets_and_lines: true,
            with_threads: true,
            ansi: false,
            #[cfg(feature = "otel")]
            otlp: None,
        })
        .expect("init");
        tracing::info!(target: "aethernova::test", "hello from test");
    }
}

/* -------------------------- README (источники) --------------------------

- JSON-форматтер и прод-назначение: tracing-subscriber JSON formatter.
  https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/format/struct.Json.html  :contentReference[oaicite:1]{index=1}
  https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/format/fn.json.html      :contentReference[oaicite:2]{index=2}

- RFC3339 таймстемпы (UTC): 
  https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/time/struct.UtcTime.html  :contentReference[oaicite:3]{index=3}
  https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/time/index.html          :contentReference[oaicite:4]{index=4}

- Интеграция tracing -> OpenTelemetry:
  https://docs.rs/tracing-opentelemetry/latest/tracing_opentelemetry/                     :contentReference[oaicite:5]{index=5}
  https://crates.io/crates/tracing-opentelemetry                                           :contentReference[oaicite:6]{index=6}

- OpenTelemetry Rust и OTLP экспортер:
  https://docs.rs/opentelemetry/latest/opentelemetry/                                      :contentReference[oaicite:7]{index=7}
  https://crates.io/crates/opentelemetry-otlp                                              :contentReference[oaicite:8]{index=8}

- Семантические конвенции и ресурсные атрибуты (service.name, service.version, deployment.environment):
  https://opentelemetry.io/docs/specs/semconv/resource/                                    :contentReference[oaicite:9]{index=9}
  https://opentelemetry.io/docs/specs/semconv/                                             :contentReference[oaicite:10]{index=10}

- Пропагация W3C Trace Context (traceparent/tracestate):
  https://www.w3.org/TR/trace-context/                                                     :contentReference[oaicite:11]{index=11}
  https://www.w3.org/TR/trace-context-2/                                                   :contentReference[oaicite:12]{index=12}
-------------------------------------------------------------------------- */
