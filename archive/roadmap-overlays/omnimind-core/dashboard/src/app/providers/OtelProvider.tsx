import React, { createContext, useContext, useEffect, useMemo, useRef } from "react";

/**
 * OpenTelemetry (Web) — промышленная инициализация для React/Vite
 * Безопасно для HMR, единичная инициализация, гибкая конфигурация через import.meta.env
 *
 * ВНИМАНИЕ: Требуемые зависимости:
 *   @opentelemetry/api
 *   @opentelemetry/resources
 *   @opentelemetry/semantic-conventions
 *   @opentelemetry/sdk-trace-web
 *   @opentelemetry/exporter-trace-otlp-http
 *   @opentelemetry/instrumentation
 *   @opentelemetry/instrumentation-document-load
 *   @opentelemetry/instrumentation-user-interaction
 *   @opentelemetry/instrumentation-xml-http-request
 *   @opentelemetry/instrumentation-fetch
 */

import { context, trace, diag, DiagConsoleLogger, DiagLogLevel } from "@opentelemetry/api";
import { Resource } from "@opentelemetry/resources";
import { SemanticResourceAttributes } from "@opentelemetry/semantic-conventions";
import {
  WebTracerProvider,
  BatchSpanProcessor,
  AlwaysOnSampler,
  AlwaysOffSampler,
  ParentBasedSampler,
  TraceIdRatioBasedSampler,
} from "@opentelemetry/sdk-trace-web";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { registerInstrumentations } from "@opentelemetry/instrumentation";
import { DocumentLoadInstrumentation } from "@opentelemetry/instrumentation-document-load";
import { UserInteractionInstrumentation } from "@opentelemetry/instrumentation-user-interaction";
import { XMLHttpRequestInstrumentation } from "@opentelemetry/instrumentation-xml-http-request";
import { FetchInstrumentation } from "@opentelemetry/instrumentation-fetch";

/** ===================== Конфигурация из окружения ===================== **/

type OtelEnv = {
  ENABLED: boolean;                 // включить/выключить Otel полностью
  DEBUG: boolean;                   // детальный лог SDK
  SERVICE_NAME: string;             // имя сервиса
  SERVICE_VERSION: string;          // версия (из build/meta)
  DEPLOY_ENV: string;               // prod|staging|dev|local
  OTLP_URL: string;                 // OTLP/HTTP endpoint (например, http://localhost:4318/v1/traces)
  OTLP_HEADERS: string;             // кастомные заголовки "k1=v1,k2=v2"
  SAMPLE_RATIO: number;             // 0..1
  BATCH_MAX_QUEUE_SIZE: number;     // очередь батча
  BATCH_MAX_EXPORT_BATCH_SIZE: number;
  BATCH_SCHEDULE_DELAY_MS: number;
  INSTRUMENT_FETCH: boolean;
  INSTRUMENT_XHR: boolean;
  INSTRUMENT_DOCLOAD: boolean;
  INSTRUMENT_UI: boolean;
  PROPAGATE_TRACEPARENT: boolean;   // W3C traceparent (в браузере по умолчанию)
};

const readEnv = (): OtelEnv => {
  const v = (k: string, d?: string) => (import.meta as any).env?.[k] ?? d;
  const bool = (s: any, def = false) =>
    typeof s === "string" ? ["1", "true", "yes", "on"].includes(s.toLowerCase()) : !!(s ?? def);
  const num = (s: any, def: number) => {
    const n = Number(s);
    return Number.isFinite(n) ? n : def;
  };

  return {
    ENABLED: bool(v("VITE_OTEL_ENABLED", "1")),
    DEBUG: bool(v("VITE_OTEL_DEBUG", "0")),
    SERVICE_NAME: String(v("VITE_OTEL_SERVICE_NAME", "omnimind-dashboard")),
    SERVICE_VERSION: String(v("VITE_APP_VERSION", v("VITE_OTEL_SERVICE_VERSION", "0.0.0"))),
    DEPLOY_ENV: String(v("VITE_DEPLOY_ENV", "local")),
    OTLP_URL: String(v("VITE_OTEL_OTLP_URL", "http://localhost:4318/v1/traces")),
    OTLP_HEADERS: String(v("VITE_OTEL_HEADERS", "")),
    SAMPLE_RATIO: num(v("VITE_OTEL_SAMPLE_RATIO", "1"), 1),
    BATCH_MAX_QUEUE_SIZE: num(v("VITE_OTEL_BATCH_MAX_QUEUE_SIZE", "2048"), 2048),
    BATCH_MAX_EXPORT_BATCH_SIZE: num(v("VITE_OTEL_BATCH_MAX_EXPORT_BATCH_SIZE", "512"), 512),
    BATCH_SCHEDULE_DELAY_MS: num(v("VITE_OTEL_BATCH_SCHEDULE_DELAY_MS", "5000"), 5000),
    INSTRUMENT_FETCH: bool(v("VITE_OTEL_INSTR_FETCH", "1")),
    INSTRUMENT_XHR: bool(v("VITE_OTEL_INSTR_XHR", "1")),
    INSTRUMENT_DOCLOAD: bool(v("VITE_OTEL_INSTR_DOCLOAD", "1")),
    INSTRUMENT_UI: bool(v("VITE_OTEL_INSTR_UI", "1")),
    PROPAGATE_TRACEPARENT: bool(v("VITE_OTEL_PROPAGATE_TRACEPARENT", "1")),
  };
};

/** ===================== Глобальные одиночки (HMR-стойко) ===================== **/

declare global {
  interface Window {
    __OTEL__?: {
      initialized: boolean;
      provider?: WebTracerProvider;
      shutdown?: () => Promise<void>;
    };
  }
}

const getGlobal = () => {
  if (!window.__OTEL__) window.__OTEL__ = { initialized: false };
  return window.__OTEL__!;
};

/** ===================== Инициализация SDK ===================== **/

type InitResult = {
  tracer: ReturnType<typeof trace.getTracer>;
  shutdown: () => Promise<void>;
};

const headerKV = (raw: string): Record<string, string> => {
  const out: Record<string, string> = {};
  if (!raw) return out;
  raw.split(",").forEach((pair) => {
    const [k, v] = pair.split("=").map((s) => s?.trim());
    if (k && v) out[k] = v;
  });
  return out;
};

const selectSampler = (ratio: number) => {
  if (ratio <= 0) return new AlwaysOffSampler();
  if (ratio >= 1) return new ParentBasedSampler({ root: new AlwaysOnSampler() });
  return new ParentBasedSampler({ root: new TraceIdRatioBasedSampler(ratio) });
};

function initOtel(): InitResult | null {
  const env = readEnv();
  const global = getGlobal();

  if (!env.ENABLED) {
    // Отключено через флаг — не инициализируем
    return null;
  }

  if (global.initialized && global.provider) {
    // Повторная инициализация не нужна (HMR/повторный маунт)
    const tracer = trace.getTracer(env.SERVICE_NAME, env.SERVICE_VERSION);
    return { tracer, shutdown: global.shutdown ?? (async () => {}) };
  }

  if (env.DEBUG) {
    diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.DEBUG);
  } else {
    diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.ERROR);
  }

  const resource = new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: env.SERVICE_NAME,
    [SemanticResourceAttributes.SERVICE_VERSION]: env.SERVICE_VERSION,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: env.DEPLOY_ENV,
  });

  const provider = new WebTracerProvider({
    resource,
    sampler: selectSampler(env.SAMPLE_RATIO),
  });

  const exporter = new OTLPTraceExporter({
    url: env.OTLP_URL,
    headers: headerKV(env.OTLP_HEADERS),
  });

  provider.addSpanProcessor(
    new BatchSpanProcessor(exporter, {
      maxQueueSize: env.BATCH_MAX_QUEUE_SIZE,
      maxExportBatchSize: env.BATCH_MAX_EXPORT_BATCH_SIZE,
      scheduledDelayMillis: env.BATCH_SCHEDULE_DELAY_MS,
      exportTimeoutMillis: 10000,
    })
  );

  provider.register({
    // В браузере по умолчанию — W3C tracecontext. Доп. пропагаторы при необходимости подключать здесь.
  });

  const instrumentations = [];
  if (env.INSTRUMENT_DOCLOAD) {
    instrumentations.push(new DocumentLoadInstrumentation());
  }
  if (env.INSTRUMENT_UI) {
    instrumentations.push(new UserInteractionInstrumentation());
  }
  if (env.INSTRUMENT_XHR) {
    instrumentations.push(
      new XMLHttpRequestInstrumentation({
        propagateTraceHeaderCorsUrls: /.*/, // осторожно в проде — сузить домены
        clearTimingResources: true,
      })
    );
  }
  if (env.INSTRUMENT_FETCH) {
    instrumentations.push(
      new FetchInstrumentation({
        propagateTraceHeaderCorsUrls: /.*/, // осторожно в проде — сузить домены
        clearTimingResources: true,
      })
    );
  }

  registerInstrumentations({
    instrumentations,
  });

  const tracer = trace.getTracer(env.SERVICE_NAME, env.SERVICE_VERSION);

  const shutdown = async () => {
    try {
      await provider.forceFlush();
    } finally {
      await provider.shutdown();
    }
  };

  // Гарантированный flush перед выгрузкой страницы
  const onUnload = () => {
    // попытаться синхронно зафлашить (ограничено браузером)
    void provider.forceFlush();
  };

  window.addEventListener("pagehide", onUnload, { capture: true });
  window.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") void provider.forceFlush();
  });

  global.initialized = true;
  global.provider = provider;
  global.shutdown = async () => {
    window.removeEventListener("pagehide", onUnload, { capture: true } as any);
    await shutdown();
    global.initialized = false;
    global.provider = undefined;
    global.shutdown = undefined;
  };

  return { tracer, shutdown: global.shutdown };
}

/** ===================== React-контекст ===================== **/

type OtelContextValue = {
  tracer: ReturnType<typeof trace.getTracer> | null;
  shutdown: (() => Promise<void>) | null;
  enabled: boolean;
  serviceName: string;
  serviceVersion: string;
  env: string;
};

const OtelContext = createContext<OtelContextValue>({
  tracer: null,
  shutdown: null,
  enabled: false,
  serviceName: "unknown",
  serviceVersion: "0.0.0",
  env: "local",
});

export const useOtel = () => useContext(OtelContext);

type Props = {
  children: React.ReactNode;
};

export const OtelProvider: React.FC<Props> = ({ children }) => {
  const cfg = useMemo(() => readEnv(), []);
  const initRef = useRef<InitResult | null>(null);

  useEffect(() => {
    initRef.current = initOtel();

    return () => {
      // На размонтировании не шатаем SDK (он глобальный), но форсим flush
      const g = getGlobal();
      if (g.provider) {
        void g.provider.forceFlush();
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value: OtelContextValue = useMemo(
    () => ({
      tracer: initRef.current?.tracer ?? null,
      shutdown: initRef.current?.shutdown ?? null,
      enabled: cfg.ENABLED,
      serviceName: cfg.SERVICE_NAME,
      serviceVersion: cfg.SERVICE_VERSION,
      env: cfg.DEPLOY_ENV,
    }),
    [cfg.DEPLOY_ENV, cfg.ENABLED, cfg.SERVICE_NAME, cfg.SERVICE_VERSION]
  );

  return <OtelContext.Provider value={value}>{children}</OtelContext.Provider>;
};

/** ===================== Утилита для React Profiler (опционально) ===================== **/

/**
 * wrapWithSpan — обёртка для ручного трейсинга блоков/операций.
 * Пример:
 *   const res = await withSpan("load:widgets", async (span) => { ...; return data; });
 */
export async function withSpan<T>(
  name: string,
  fn: (span: import("@opentelemetry/api").Span) => Promise<T>,
  attributes?: Record<string, unknown>
): Promise<T> {
  const tracer = trace.getTracerProvider()?.getTracer(readEnv().SERVICE_NAME) ?? trace.getTracer("default");
  const span = tracer.startSpan(name);
  if (attributes) span.setAttributes(attributes);
  try {
    return await context.with(trace.setSpan(context.active(), span), () => fn(span));
  } catch (e: any) {
    span.recordException?.(e);
    span.setStatus({ code: 2, message: String(e?.message ?? e) }); // 2 = ERROR
    throw e;
  } finally {
    span.end();
  }
}
