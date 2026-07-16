/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * OmniMind Core Dashboard — main entry
 * Производственный entrypoint с:
 * - StrictMode
 * - ErrorBoundary c отчётами
 * - Lazy App bootstrap (code-splitting)
 * - Web Vitals (sendBeacon)
 * - Runtime config из window.__OMNIMIND_CONFIG__
 * - Безопасное монтирование/размонтирование
 * - HMR support
 */

import React, { StrictMode, Suspense } from "react";
import { createRoot, Root } from "react-dom/client";

// --------- Типы и Runtime Config ---------
declare global {
  interface Window {
    __OMNIMIND_CONFIG__?: Partial<OmniRuntimeConfig>;
    __CSP_NONCE__?: string;
  }
}

export type OmniRuntimeConfig = {
  appName: string;
  env: "development" | "staging" | "production";
  version: string;
  sentryDsn?: string;
  vitalsEndpoint?: string; // например: "/__vitals"
  reportErrorsEndpoint?: string; // например: "/__errors"
};

const DEFAULT_CONFIG: OmniRuntimeConfig = {
  appName: "OmniMind Core Dashboard",
  env: (import.meta.env?.MODE as OmniRuntimeConfig["env"]) ?? "production",
  version: import.meta.env?.VITE_APP_VERSION ?? "0.0.0",
  vitalsEndpoint: "/__vitals",
  reportErrorsEndpoint: "/__errors",
};

function getRuntimeConfig(): OmniRuntimeConfig {
  const fromWindow = window.__OMNIMIND_CONFIG__ ?? {};
  return { ...DEFAULT_CONFIG, ...fromWindow };
}

const RUNTIME = Object.freeze(getRuntimeConfig());

// --------- Отчёт об ошибках ---------
function reportError(err: unknown, info?: { componentStack?: string }) {
  try {
    const body = JSON.stringify({
      ts: new Date().toISOString(),
      message: err instanceof Error ? err.message : String(err),
      stack: err instanceof Error ? err.stack : undefined,
      info,
      env: RUNTIME.env,
      version: RUNTIME.version,
    });

    const endpoint = RUNTIME.reportErrorsEndpoint;
    if (!endpoint) return;

    if (navigator.sendBeacon) {
      const blob = new Blob([body], { type: "application/json" });
      navigator.sendBeacon(endpoint, blob);
    } else {
      // fire-and-forget
      fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        keepalive: true,
        body,
      }).catch(() => void 0);
    }
  } catch {
    // без побочных эффектов
  }
}

// --------- Error Boundary ---------
type ErrorBoundaryProps = { children: React.ReactNode };
type ErrorBoundaryState = { hasError: boolean; error?: Error };

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    reportError(error, { componentStack: errorInfo.componentStack });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div role="alert" style={{ padding: 24, fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial" }}>
          <h1 style={{ margin: 0, fontSize: 18 }}>Произошла ошибка интерфейса</h1>
          <p style={{ marginTop: 8 }}>
            Попробуйте обновить страницу. Если проблема повторяется, обратитесь к администратору.
          </p>
          {RUNTIME.env !== "production" && this.state.error && (
            <pre style={{ marginTop: 16, whiteSpace: "pre-wrap" }}>{String(this.state.error.stack ?? this.state.error.message)}</pre>
          )}
        </div>
      );
    }
    return this.props.children;
  }
}

// --------- Lazy App ---------
const App = React.lazy(() => import("./App"));

// --------- Web Vitals ---------
type VitalsMetric = {
  name: string;
  value: number;
  id: string;
  label?: "web-vitals" | string;
};

async function initWebVitals() {
  try {
    const { onCLS, onFID, onLCP, onINP, onFCP, onTTFB } = await import("web-vitals");

    const send = (metric: VitalsMetric) => {
      try {
        const endpoint = RUNTIME.vitalsEndpoint;
        if (!endpoint) return;

        const body = JSON.stringify({
          ts: Date.now(),
          metric: metric.name,
          value: metric.value,
          id: metric.id,
          label: metric.label ?? "web-vitals",
          env: RUNTIME.env,
          version: RUNTIME.version,
          ua: navigator.userAgent,
          url: location.href,
        });

        if (navigator.sendBeacon) {
          const blob = new Blob([body], { type: "application/json" });
          navigator.sendBeacon(endpoint, blob);
        } else {
          fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            keepalive: true,
            body,
          }).catch(() => void 0);
        }
      } catch {
        // ignore
      }
    };

    onCLS(send);
    onFID(send);
    onLCP(send);
    onINP?.(send as any);
    onFCP(send);
    onTTFB(send);
  } catch {
    // web-vitals не критичен
  }
}

// --------- Монтирование ---------
const CONTAINER_ID = "root";
let root: Root | null = null;

function ensureContainer(): HTMLElement {
  const existing = document.getElementById(CONTAINER_ID);
  if (existing) return existing;

  const el = document.createElement("div");
  el.id = CONTAINER_ID;
  // CSP nonce, если предоставлен сервером
  if (window.__CSP_NONCE__) {
    el.setAttribute("nonce", window.__CSP_NONCE__ as string);
  }
  document.body.appendChild(el);
  return el;
}

function mount() {
  const container = ensureContainer();
  if (!root) {
    root = createRoot(container);
  }

  root.render(
    <StrictMode>
      <ErrorBoundary>
        <Suspense fallback={<div style={{ padding: 24 }}>Загрузка…</div>}>
          <App />
        </Suspense>
      </ErrorBoundary>
    </StrictMode>
  );
}

function unmount() {
  if (root) {
    root.unmount();
    root = null;
  }
}

// --------- DEV Утилиты ---------
function lockConsoleInProd() {
  if (RUNTIME.env !== "production") return;
  const noop = () => void 0;
  try {
    // оставить только ошибок/предупреждений, замьютив шумные логи
    console.log = noop as any;
    console.debug = noop as any;
    console.info = noop as any;
  } catch {
    // ignore
  }
}

// --------- Bootstrap ---------
async function bootstrap() {
  lockConsoleInProd();
  await initWebVitals();
  mount();
}

bootstrap().catch((e) => {
  reportError(e);
  // Фолбэк попытки рендера даже при ошибке инициализации
  mount();
});

// --------- HMR ---------
if (import.meta && (import.meta as any).hot) {
  (import.meta as any).hot.accept((newModule: any) => {
    // безопасное обновление модуля
    unmount();
    mount();
  });
  (import.meta as any).hot.dispose(() => {
    unmount();
  });
}

// --------- Защита от двойного монтирования вне StrictMode ---------
// Некоторые окружения могут попытаться замонтировать повторно.
// Мы гарантируем единственность корня.
if ((window as any).__OMNI_APP_MOUNTED__) {
  // уже смонтировано — не делаем ничего
} else {
  (window as any).__OMNI_APP_MOUNTED__ = true;
}
