import React from "react";

/**
 * Пропсы ErrorBoundary:
 * - fallback: статический ReactNode
 * - fallbackRender: функция-рендер с управлением reset
 * - onError: синхронный локальный колбэк
 * - reportError: опциональный async-репорт (Sentry/OTEL и т.п.)
 * - onReset: вызывается при ручном reset
 * - resetKeys: ключи, изменение которых автоматически сбрасывает ошибку
 * - captureConsole: дополнительно логировать в консоль в dev
 * - allowStackInProd: разрешить показывать stack в проде
 */
export type ErrorBoundaryProps = {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  fallbackRender?: (args: { error: Error; reset: () => void; fingerprint?: string }) => React.ReactElement;
  onError?: (error: Error, info: React.ErrorInfo) => void;
  reportError?: (error: Error, context: { info: React.ErrorInfo; fingerprint: string }) => Promise<void> | void;
  onReset?: () => void;
  resetKeys?: Array<unknown>;
  captureConsole?: boolean;
  allowStackInProd?: boolean;
  className?: string;
  style?: React.CSSProperties;
};

type ErrorBoundaryState = {
  error: Error | null;
  fingerprint?: string;
};

/**
 * Компактная деталька ошибки: контролируемый показ стека, копирование в буфер.
 * По умолчанию скрывает stack в production (можно включить allowStackInProd).
 */
export function ErrorDetails({
  error,
  showStack,
  onToggle,
  fingerprint,
}: {
  error: Error;
  showStack: boolean;
  onToggle: () => void;
  fingerprint?: string;
}) {
  const canUseClipboard = typeof navigator !== "undefined" && !!navigator.clipboard?.writeText;

  const copy = async () => {
    if (!canUseClipboard) return;
    const payload = [`message: ${error.message}`, fingerprint ? `fingerprint: ${fingerprint}` : "", showStack && (error.stack ?? "no stack")]
      .filter(Boolean)
      .join("\n");
    try {
      await navigator.clipboard.writeText(payload);
    } catch {
      // ignore
    }
  };

  return (
    <div style={{ marginTop: 8 }}>
      {fingerprint ? (
        <div style={{ fontFamily: "monospace", fontSize: 12, opacity: 0.75 }}>fingerprint: {fingerprint}</div>
      ) : null}
      <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
        <button onClick={onToggle} style={{ padding: "6px 10px", cursor: "pointer" }}>
          {showStack ? "Hide stack" : "Show stack"}
        </button>
        {canUseClipboard ? (
          <button onClick={copy} style={{ padding: "6px 10px", cursor: "pointer" }}>
            Copy
          </button>
        ) : null}
      </div>
      {showStack ? (
        <pre
          style={{
            marginTop: 8,
            background: "rgba(220,53,69,0.08)",
            border: "1px solid rgba(220,53,69,0.35)",
            padding: 12,
            borderRadius: 8,
            whiteSpace: "pre-wrap",
            overflowX: "auto",
          }}
        >
          {error.stack ?? "no stack"}
        </pre>
      ) : null}
    </div>
  );
}

/** Неблокирующий хеш строки для отпечатка ошибки (достаточно для корреляции в логах). */
function fingerprintOf(s: string): string {
  // Простая и быстрая функция (FNV-1a-подобная)
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return ("0000000" + h.toString(16)).slice(-8);
}

/** Сравнение массивов resetKeys с допуском по длине/значениям. */
function changedArray(a?: unknown[], b?: unknown[]) {
  if (a === b) return false;
  if (!a || !b) return true;
  if (a.length !== b.length) return true;
  for (let i = 0; i < a.length; i++) {
    // простое сравнение по ссылке/значению
    if (a[i] !== b[i]) return true;
  }
  return false;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null, fingerprint: undefined };

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    const basis = `${error.name}:${error.message}` + (error.stack ? `\n${error.stack.split("\n")[1] ?? ""}` : "");
    return { error, fingerprint: fingerprintOf(basis) };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    const { onError, reportError, captureConsole } = this.props;

    if (process.env.NODE_ENV !== "production" || captureConsole) {
      // eslint-disable-next-line no-console
      console.error("[ErrorBoundary] Uncaught error:", error, info);
    }

    try {
      onError?.(error, info);
    } catch {
      /* ignore */
    }
    try {
      const fp = this.state.fingerprint ?? fingerprintOf(`${error.name}:${error.message}`);
      void reportError?.(error, { info, fingerprint: fp });
    } catch {
      /* ignore */
    }
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps) {
    const { error } = this.state;
    if (error && changedArray(prevProps.resetKeys, this.props.resetKeys)) {
      this.resetErrorBoundary();
    }
  }

  resetErrorBoundary = () => {
    try {
      this.props.onReset?.();
    } catch {
      /* ignore */
    }
    this.setState({ error: null, fingerprint: undefined });
  };

  render() {
    const { error, fingerprint } = this.state;
    const {
      children,
      fallback,
      fallbackRender,
      allowStackInProd = false,
      className,
      style,
    } = this.props;

    if (error) {
      // Управляемый fallback: приоритет fallbackRender > fallback > дефолтный
      if (typeof fallbackRender === "function") {
        return fallbackRender({ error, reset: this.resetErrorBoundary, fingerprint });
      }
      if (fallback) {
        return (
          <div className={className} style={style}>
            {fallback}
          </div>
        );
      }

      // Дефолтный безопасный fallback
      const showStackDefault = process.env.NODE_ENV !== "production" || allowStackInProd;
      return (
        <div
          role="alert"
          className={className}
          style={{
            border: "1px solid rgba(220,53,69,0.35)",
            background: "rgba(220,53,69,0.06)",
            padding: 16,
            borderRadius: 10,
            ...style,
          }}
        >
          <h2 style={{ margin: 0, fontSize: 18 }}>Something went wrong</h2>
          <div style={{ marginTop: 8 }}>
            <strong>{error.name}:</strong> {error.message}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <button onClick={this.resetErrorBoundary} style={{ padding: "8px 12px", cursor: "pointer" }}>
              Reset
            </button>
          </div>
          <ErrorDetails error={error} showStack={!!showStackDefault} onToggle={() => { /* noop in default */ }} fingerprint={fingerprint} />
        </div>
      );
    }

    return children as React.ReactElement;
  }
}

/**
 * Хелпер для функционального API (обёртка над классом).
 * Удобно для единообразного импорта.
 */
export function AppErrorBoundary(props: ErrorBoundaryProps) {
  return <ErrorBoundary {...props} />;
}

export default ErrorBoundary;
