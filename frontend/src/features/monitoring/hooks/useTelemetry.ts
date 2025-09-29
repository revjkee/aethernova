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

// We'll lazy-load OpenTelemetry packages at runtime (inside browser-only init)
// to avoid SSR/build-time errors when packages are not available or cause bundler issues.
// Web Vitals will be lazy-loaded inside bindWebVitals to avoid static dependency.

// Module-level placeholders (populated by dynamic imports in initOpenTelemetry)
let otelContext: any = null;
let traceApi: any = null;
let SpanStatusCodeLocal: any = null;
let SpanKindLocal: any = null;
let diagLocal: any = null;
let DiagLogLevelLocal: any = null;

let WebTracerProviderLocal: any = null;
let BatchSpanProcessorLocal: any = null;
let OTLPTraceExporterLocal: any = null;
let registerInstrumentationsLocal: any = null;
let getWebAutoInstrumentationsLocal: any = null;

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
  provider: null as any,
  exporter: null as any,
  spanProcessor: null as any,
  serviceName: "frontend-app",
  serviceVersion: "0.0.0",
  environment: "production",
  globalAttributes: {} as Attributes,
  userId: null as string | null,
};

// Type aliases to avoid compile-time dependency on OTel types
type Span = any;
type SpanStatusCode = any;
type SpanKind = any;
type WebVitalMetricLocal = any;

/** Безопасная проверка среды исполнения */
function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined";
}

/** Настройка диагностики OTel */
function setupDiag(enableDebug?: boolean) {
  if (enableDebug && diagLocal && DiagLogLevelLocal) {
    // Лёгкий логгер в консоль
    diagLocal.setLogger(
      {
        debug: (...args: unknown[]) => console.debug("[OTel]", ...args),
        error: (...args: unknown[]) => console.error("[OTel]", ...args),
        info: (...args: unknown[]) => console.info("[OTel]", ...args),
        warn: (...args: unknown[]) => console.warn("[OTel]", ...args),
        verbose: (...args: unknown[]) => console.log("[OTel:verbose]", ...args),
      },
      DiagLogLevelLocal.DEBUG
    );
  }
}

/** Инициализация OpenTelemetry Web */
async function initOpenTelemetry(cfg: TelemetryConfig) {
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
  // Dynamic imports: try to load OTel packages only in browser at runtime
  try {
    // @ts-ignore - dynamic import: may be absent in some environments
    const api = await import("@opentelemetry/api");
    otelContext = api.context;
    traceApi = api.trace ?? api;
    diagLocal = api.diag ?? null;
    SpanStatusCodeLocal = api.SpanStatusCode ?? null;
    SpanKindLocal = api.SpanKind ?? null;
    DiagLogLevelLocal = api.DiagLogLevel ?? null;
  } catch (e) {
    // If @opentelemetry/api isn't available, bail silently
    // This allows the app to run without OTel packages present
  }

  try {
    // @ts-ignore - dynamic import
    const mod = await import("@opentelemetry/sdk-trace-web");
    WebTracerProviderLocal = mod.WebTracerProvider ?? mod.default ?? mod;
  } catch {}
  try {
    // @ts-ignore - dynamic import
    const mod2 = await import("@opentelemetry/sdk-trace-base");
    BatchSpanProcessorLocal = mod2.BatchSpanProcessor ?? mod2.default ?? mod2;
  } catch {}
  try {
    // @ts-ignore - dynamic import
    const mod3 = await import("@opentelemetry/exporter-trace-otlp-http");
    OTLPTraceExporterLocal = mod3.OTLPTraceExporter ?? mod3.default ?? mod3;
  } catch {}
  try {
    // @ts-ignore - dynamic import
    const mod4 = await import("@opentelemetry/instrumentation");
    registerInstrumentationsLocal = mod4.registerInstrumentations ?? mod4.default ?? mod4;
  } catch {}
  try {
    // @ts-ignore - dynamic import
    const mod5 = await import("@opentelemetry/auto-instrumentations-web");
    getWebAutoInstrumentationsLocal = mod5.getWebAutoInstrumentations ?? mod5.default ?? mod5;
  } catch {}

  setupDiag(cfg.enableDebug);

  if (!WebTracerProviderLocal || !BatchSpanProcessorLocal || !OTLPTraceExporterLocal || !traceApi) {
    // Required modules not available - skip initialization
    __telemetry.initialized = false;
    return;
  }

  // Провайдер трейсинга
  const provider = new WebTracerProviderLocal({
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
      shouldSample: (_ctx: any, _traceId: any) => {
        const r = Math.random();
        return {
          decision: r < samplingRatio ? 1 : 0, // 1=RECORD_AND_SAMPLED, 0=NOT_RECORD
        } as any;
      },
      toString: () => `ParentOrRatioSampler(${samplingRatio})`,
    },
  });

  const exporter = new OTLPTraceExporterLocal({
    url: otlpTraceUrl,
  });

  const spanProcessor = new BatchSpanProcessorLocal(exporter, {
    maxQueueSize: 2048,
    maxExportBatchSize: 512,
    scheduledDelayMillis: 3000,
    exportTimeoutMillis: 5000,
  });

  provider.addSpanProcessor(spanProcessor);
  provider.register();

  if (registerInstrumentationsLocal && getWebAutoInstrumentationsLocal) {
    try {
      registerInstrumentationsLocal({
        instrumentations: [
          getWebAutoInstrumentationsLocal({
            "@opentelemetry/instrumentation-document-load": {},
            "@opentelemetry/instrumentation-user-interaction": {
              eventNames: ["click", "submit"],
            },
            "@opentelemetry/instrumentation-xml-http-request": {},
            "@opentelemetry/instrumentation-fetch": {
              ignoreUrls: [otlpTraceUrl],
            },
          }),
        ],
      });
    } catch {
      // ignore instrumentation errors
    }
  }

  __telemetry.initialized = true;
  __telemetry.provider = provider;
  __telemetry.exporter = exporter;
  __telemetry.spanProcessor = spanProcessor;

  // Плавная выгрузка при закрытии вкладки/сворачивании
  const flush = async () => {
    try {
      if (spanProcessor && typeof spanProcessor.forceFlush === "function") {
        await spanProcessor.forceFlush();
      }
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
  // Lazy-load web-vitals; do not make bindWebVitals async to keep useEffect simple
  (async () => {
    try {
      // @ts-ignore - web-vitals may be absent in build env
      const web = await import("web-vitals");
      const { onFCP, onLCP, onCLS, onTTFB, onFID, onINP } = web;
      const handler = (metric: any) => {
        try {
          emit(`webvitals.${String(metric.name).toLowerCase()}`, {
            value: Number(metric.value ?? 0),
            rating: metric.rating ?? "unknown",
            id: metric.id ?? "",
            navigationType: metric.navigationType ?? "",
          });
        } catch {}
      };
      onFCP(handler);
      onLCP(handler);
      onCLS(handler);
      onTTFB(handler);
      onFID(handler);
      onINP(handler);
    } catch {
      // web-vitals not available or failed
    }
  })();
}

/** Создать или получить tracer */
function getTracer() {
  if (traceApi && typeof traceApi.getTracer === "function") {
    return traceApi.getTracer(__telemetry.serviceName, __telemetry.serviceVersion);
  }
  // fallback stub tracer
  return {
    startSpan: (..._args: any[]) => ({
      setAttributes: () => {},
      addEvent: () => {},
      recordException: () => {},
      setStatus: () => {},
      end: () => {},
    }),
  } as any;
}

/** Вспомогательный фоновый спан для событий без активного спана */
function withBackgroundSpan<T>(
  name: string,
  attrs: Attributes | undefined,
  fn: (span: Span) => T
): T {
  const tracer = getTracer();
  const span = tracer.startSpan(name, { kind: SpanKindLocal?.INTERNAL ?? 0 });
  if (attrs) span.setAttributes(attrs as any);
  try {
    const activeCtx = otelContext ? otelContext.active() : undefined;
    if (otelContext && traceApi && typeof traceApi.setSpan === "function") {
      const ctx = traceApi.setSpan(activeCtx, span);
      return otelContext.with ? otelContext.with(ctx, fn, undefined, span) : (fn(span) as T);
    }
    return fn(span);
  } catch (e: any) {
    try {
      span.recordException(e);
      span.setStatus({ code: SpanStatusCodeLocal?.ERROR ?? 2, message: String(e?.message) });
    } catch {}
    throw e;
  } finally {
    try {
      span.end();
    } catch {}
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

    void initOpenTelemetry(config);

    if (config.enableWebVitals) {
      const emit = (name: string, attrs?: Attributes) => {
        // Событие в активный контекст; если нет — в фоновый спан
        const activeSpan = traceApi && otelContext && typeof traceApi.getSpan === "function" ? traceApi.getSpan(otelContext.active()) : null;
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
        const activeCtx = otelContext ? otelContext.active() : undefined;
        if (otelContext && traceApi && typeof traceApi.setSpan === "function") {
          const ctx = traceApi.setSpan(activeCtx, span);
          return await (otelContext.with ? otelContext.with(ctx, async () => await fn()) : (fn() as any));
        }
        return await fn();
      } catch (e: any) {
        try {
          span.recordException(e);
          span.setStatus({
            code: SpanStatusCodeLocal?.ERROR ?? 2,
            message: String(e?.message ?? "error"),
          });
        } catch {}
        throw e;
      } finally {
        try {
          span.end();
        } catch {}
      }
    };

      const trackEvent = (name: string, attrs?: Attributes) => {
      const activeSpan = traceApi && otelContext && typeof traceApi.getSpan === "function" ? traceApi.getSpan(otelContext.active()) : null;
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
      const activeSpan = traceApi && otelContext && typeof traceApi.getSpan === "function" ? traceApi.getSpan(otelContext.active()) : null;
      if (activeSpan) {
        activeSpan.recordException(err);
        activeSpan.setStatus({
          code: SpanStatusCodeLocal?.ERROR ?? 2,
          message: err.message,
        });
      } else {
        withBackgroundSpan("error", attrs, (s) => {
          s.recordException(err);
          s.setStatus({ code: SpanStatusCodeLocal?.ERROR ?? 2, message: err.message });
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
