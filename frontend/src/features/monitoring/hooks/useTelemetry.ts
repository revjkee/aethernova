// frontend/src/features/monitoring/hooks/useTelemetry.ts
/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Унифицированный хук телеметрии для фронтенда.
 * Возможности:
 * - Инициализация OpenTelemetry (трейсинг) в браузере с OTLP HTTP экспортером
 * - Авто-инструментирование: DocumentLoad, XHR, Fetch, UserInteraction
 * - Сбор Web Vitals (FCP, LCP, CLS, TTFB, FID, INP) и отправка как события в активный спан/фоновый спан
 * - API: startSpan/withSpan/trackEvent/trackError/setUser/setGlobalAttributes
 * - SSR-safe, idempotent (повторные вызовы не переинициализируют провайдер)
 * - Плавная выгрузка (flush) при beforeunload/visibilitychange
 *
 * Требуемые зависимости (пример — добавьте в ваш манифест):
 *  - @opentelemetry/api
 *  - @opentelemetry/sdk-trace-web
 *  - @opentelemetry/exporter-trace-otlp-http
 *  - @opentelemetry/context-zone                (если используете ZoneContext)
 *  - @opentelemetry/instrumentation
 *  - @opentelemetry/auto-instrumentations-web   (или отдельные инструментаторы)
 *  - web-vitals
 */

import { useEffect, useMemo, useRef } from "react";

// OpenTelemetry API
import {
  context as otelContext,
  trace,
  Span,
  SpanStatusCode,
  diag,
  DiagLogLevel,
  SpanKind,
} from "@opentelemetry/api";

// Web SDK (trace)
import { WebTracerProvider } from "@opentelemetry/sdk-trace-web";
import { BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";

// Инструментирование
import { registerInstrumentations } from "@opentelemetry/instrumentation";
import { getWebAutoInstrumentations } from "@opentelemetry/auto-instrumentations-web";

// Web Vitals
import {
  onCLS,
  onFID,
  onLCP,
  onTTFB,
  onFCP,
  onINP,
  Metric as WebVitalMetric,
} from "web-vitals";

type Attributes = Record<string, string | number | boolean>;

export interface TelemetryConfig {
  serviceName?: string;
  serviceVersion?: string;
  environment?: string;
  otlpTraceUrl?: string; // OTLP HTTP endpoint для трейсов
  samplingRatio?: number; // 0..1
  enableDebug?: boolean;
  enableWebVitals?: boolean;
  globalAttributes?: Attributes;
  userId?: string | null;
}

/** Глобальный синглтон состояния инициализации */
const __telemetry = {
  initialized: false,
  provider: null as WebTracerProvider | null,
  exporter: null as OTLPTraceExporter | null,
  spanProcessor: null as BatchSpanProcessor | null,
  serviceName: "frontend-app",
  serviceVersion: "0.0.0",
  environment: "production",
  globalAttributes: {} as Attributes,
  userId: null as string | null,
};

/** Безопасная проверка среды исполнения */
function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined";
}

/** Настройка диагностики OTel */
function setupDiag(enableDebug?: boolean) {
  if (enableDebug) {
    // Лёгкий логгер в консоль
    diag.setLogger(
      {
        debug: (...args: unknown[]) => console.debug("[OTel]", ...args),
        error: (...args: unknown[]) => console.error("[OTel]", ...args),
        info: (...args: unknown[]) => console.info("[OTel]", ...args),
        warn: (...args: unknown[]) => console.warn("[OTel]", ...args),
        verbose: (...args: unknown[]) => console.log("[OTel:verbose]", ...args),
      },
      DiagLogLevel.DEBUG
    );
  }
}

/** Инициализация OpenTelemetry Web */
function initOpenTelemetry(cfg: TelemetryConfig) {
  if (!isBrowser()) return;
  if (__telemetry.initialized) return;

  const serviceName =
    cfg.serviceName ?? import.meta.env.VITE_OTEL_SERVICE_NAME ?? "frontend";
  const serviceVersion =
    cfg.serviceVersion ?? import.meta.env.VITE_APP_VERSION ?? "0.0.0";
  const environment =
    cfg.environment ?? import.meta.env.VITE_APP_ENV ?? "production";
  const otlpTraceUrl =
    cfg.otlpTraceUrl ?? import.meta.env.VITE_OTLP_TRACES_URL ?? "/v1/traces";
  const samplingRatio =
    typeof cfg.samplingRatio === "number" ? cfg.samplingRatio : 1.0;

  __telemetry.serviceName = serviceName;
  __telemetry.serviceVersion = serviceVersion;
  __telemetry.environment = environment;
  __telemetry.globalAttributes = { ...(cfg.globalAttributes ?? {}) };
  __telemetry.userId = cfg.userId ?? null;

  setupDiag(cfg.enableDebug);

  // Провайдер трейсинга
  const provider = new WebTracerProvider({
    resource: {
      attributes: {
        "service.name": serviceName,
        "service.version": serviceVersion,
        "deployment.environment": environment,
        ...__telemetry.globalAttributes,
        ...(cfg.userId ? { "enduser.id": cfg.userId } : {}),
      },
    } as any,
    sampler: {
      shouldSample: (_ctx, _traceId) => {
        const r = Math.random();
        return {
          decision: r < samplingRatio ? 1 : 0, // 1=RECORD_AND_SAMPLED, 0=NOT_RECORD
        } as any;
      },
      toString: () => `ParentOrRatioSampler(${samplingRatio})`,
    },
  });

  const exporter = new OTLPTraceExporter({
    url: otlpTraceUrl,
    // headers: { Authorization: `Bearer ${token}` } // при необходимости
  });

  const spanProcessor = new BatchSpanProcessor(exporter, {
    maxQueueSize: 2048,
    maxExportBatchSize: 512,
    scheduledDelayMillis: 3000,
    exportTimeoutMillis: 5000,
  });

  provider.addSpanProcessor(spanProcessor);
  provider.register();

  registerInstrumentations({
    instrumentations: [
      getWebAutoInstrumentations({
        // Отключайте/включайте по необходимости
        "@opentelemetry/instrumentation-document-load": {},
        "@opentelemetry/instrumentation-user-interaction": {
          eventNames: ["click", "submit"],
        },
        "@opentelemetry/instrumentation-xml-http-request": {},
        "@opentelemetry/instrumentation-fetch": {
          // пример: игнор внутренних эндпойнтов телеметрии
          ignoreUrls: [otlpTraceUrl],
        },
        // Можно подключить history API, long-task и т.п. при наличии пакетов
      }),
    ],
  });

  __telemetry.initialized = true;
  __telemetry.provider = provider;
  __telemetry.exporter = exporter;
  __telemetry.spanProcessor = spanProcessor;

  // Плавная выгрузка при закрытии вкладки/сворачивании
  const flush = async () => {
    try {
      await spanProcessor.forceFlush();
    } catch {
      // гасим ошибки при выгрузке
    }
  };
  window.addEventListener("beforeunload", flush);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") void flush();
  });
}

/** Отправка Web Vitals как события телеметрии */
function bindWebVitals(emit: (name: string, attrs?: Attributes) => void) {
  const handler = (metric: WebVitalMetric) => {
    emit(`webvitals.${metric.name.toLowerCase()}`, {
      value: Number(metric.value.toFixed(4)),
      rating: (metric as any).rating ?? "unknown",
      id: metric.id,
      navigationType: (metric as any).navigationType ?? "",
    });
  };
  onFCP(handler);
  onLCP(handler);
  onCLS(handler);
  onTTFB(handler);
  onFID(handler);
  onINP(handler);
}

/** Создать или получить tracer */
function getTracer() {
  return trace.getTracer(__telemetry.serviceName, __telemetry.serviceVersion);
}

/** Вспомогательный фоновый спан для событий без активного спана */
function withBackgroundSpan<T>(
  name: string,
  attrs: Attributes | undefined,
  fn: (span: Span) => T
): T {
  const tracer = getTracer();
  const span = tracer.startSpan(name, { kind: SpanKind.INTERNAL });
  if (attrs) span.setAttributes(attrs as any);
  try {
    const ctx = trace.setSpan(otelContext.active(), span);
    return otelContext.with(ctx, fn, undefined, span);
  } catch (e: any) {
    span.recordException(e);
    span.setStatus({ code: SpanStatusCode.ERROR, message: String(e?.message) });
    throw e;
  } finally {
    span.end();
  }
}

/** Публичный API хука */
export interface Telemetry {
  startSpan: (name: string, attrs?: Attributes) => Span;
  withSpan: <T>(
    name: string,
    attrs: Attributes | undefined,
    fn: () => T | Promise<T>
  ) => Promise<T>;
  trackEvent: (name: string, attrs?: Attributes) => void;
  trackError: (error: unknown, attrs?: Attributes) => void;
  setUser: (userId: string | null, attrs?: Attributes) => void;
  setGlobalAttributes: (attrs: Attributes) => void;
}

/** Основной React-хук */
export function useTelemetry(config: TelemetryConfig = {}): Telemetry {
  const initOnce = useRef(false);

  useEffect(() => {
    if (!isBrowser() || initOnce.current) return;

    initOpenTelemetry(config);

    if (config.enableWebVitals) {
      const emit = (name: string, attrs?: Attributes) => {
        // Событие в активный контекст; если нет — в фоновый спан
        const activeSpan = trace.getSpan(otelContext.active());
        if (activeSpan) {
          activeSpan.addEvent(name, attrs);
        } else {
          withBackgroundSpan("webvitals", undefined, (s) => {
            s.addEvent(name, attrs);
          });
        }
      };
      bindWebVitals(emit);
    }

    initOnce.current = true;
  }, [config.enableWebVitals]);

  const api = useMemo<Telemetry>(() => {
    const startSpan = (name: string, attrs?: Attributes): Span => {
      const tracer = getTracer();
      const span = tracer.startSpan(name);
      if (attrs) span.setAttributes(attrs as any);
      return span;
    };

    const withSpan = async <T,>(
      name: string,
      attrs: Attributes | undefined,
      fn: () => T | Promise<T>
    ): Promise<T> => {
      const tracer = getTracer();
      const span = tracer.startSpan(name);
      if (attrs) span.setAttributes(attrs as any);
      try {
        const ctx = trace.setSpan(otelContext.active(), span);
        return await otelContext.with(ctx, async () => await fn());
      } catch (e: any) {
        span.recordException(e);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: String(e?.message ?? "error"),
        });
        throw e;
      } finally {
        span.end();
      }
    };

    const trackEvent = (name: string, attrs?: Attributes) => {
      const activeSpan = trace.getSpan(otelContext.active());
      if (activeSpan) {
        activeSpan.addEvent(name, attrs);
        return;
      }
      withBackgroundSpan("event", attrs, (s) => {
        s.addEvent(name, attrs);
      });
    };

    const trackError = (error: unknown, attrs?: Attributes) => {
      const err =
        error instanceof Error
          ? error
          : new Error(typeof error === "string" ? error : "Unknown error");
      const activeSpan = trace.getSpan(otelContext.active());
      if (activeSpan) {
        activeSpan.recordException(err);
        activeSpan.setStatus({
          code: SpanStatusCode.ERROR,
          message: err.message,
        });
      } else {
        withBackgroundSpan("error", attrs, (s) => {
          s.recordException(err);
          s.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
        });
      }
    };

    const setUser = (userId: string | null, attrs?: Attributes) => {
      __telemetry.userId = userId;
      __telemetry.globalAttributes = {
        ...__telemetry.globalAttributes,
        ...(attrs ?? {}),
        ...(userId ? { "enduser.id": userId } : { "enduser.id": "" }),
      };
      // обновить resource-атрибуты через новый спан (resource нельзя менять на лету в провайдере),
      // поэтому добавляем их в каждый создаваемый спан:
      const prevStartSpan = startSpan;
      (api as any).startSpan = (name: string, a?: Attributes) => {
        const merged = {
          ...__telemetry.globalAttributes,
          ...(a ?? {}),
        };
        const span = prevStartSpan(name, merged);
        return span;
      };
    };

    const setGlobalAttributes = (attrs: Attributes) => {
      __telemetry.globalAttributes = {
        ...__telemetry.globalAttributes,
        ...attrs,
      };
    };

    return {
      startSpan,
      withSpan,
      trackEvent,
      trackError,
      setUser,
      setGlobalAttributes,
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return api;
}

/**
 * Рекомендуемая инициализация в приложении:
 *
 * const telemetry = useTelemetry({
 *   serviceName: "neurocity-frontend",
 *   serviceVersion: import.meta.env.VITE_APP_VERSION,
 *   environment: import.meta.env.VITE_APP_ENV,
 *   otlpTraceUrl: import.meta.env.VITE_OTLP_TRACES_URL,
 *   samplingRatio: 0.2,
 *   enableDebug: import.meta.env.DEV,
 *   enableWebVitals: true,
 *   globalAttributes: { app_tier: "web", region: "eu" },
 *   userId: currentUser?.id ?? null
 * });
 *
 * // Пример использования:
 * await telemetry.withSpan("fetch.profile", { userId }, async () => {
 *   const res = await fetch("/api/profile");
 *   telemetry.trackEvent("profile.fetch.completed", { ok: res.ok });
 * });
 *
 * try { risky(); } catch (e) { telemetry.trackError(e, { area: "risky" }); }
 */
