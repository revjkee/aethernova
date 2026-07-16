import React, { ReactNode, Suspense, useEffect, useMemo } from "react";
import { QueryClient, QueryClientConfig, QueryClientProvider } from "@tanstack/react-query";

/**
 * Минимальный и автономный провайдер темы без внешних зависимостей.
 * Хранит выбор в localStorage, синхронизирует data-theme и prefers-color-scheme.
 */
type ThemeMode = "system" | "light" | "dark";

interface ThemeProviderProps {
  children: ReactNode;
  defaultMode?: ThemeMode;
  storageKey?: string;
}

const ThemeContext = React.createContext<{ mode: ThemeMode; setMode: (m: ThemeMode) => void }>({
  mode: "system",
  setMode: () => undefined,
});

function getSystemTheme(): "light" | "dark" {
  if (typeof window === "undefined" || !window.matchMedia) return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyThemeAttr(mode: ThemeMode) {
  const effective = mode === "system" ? getSystemTheme() : mode;
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", effective);
    document.documentElement.classList.toggle("dark", effective === "dark");
  }
}

export function ThemeProvider({ children, defaultMode = "system", storageKey = "app:theme" }: ThemeProviderProps) {
  const [mode, setModeState] = React.useState<ThemeMode>(() => {
    if (typeof window === "undefined") return defaultMode;
    const saved = window.localStorage.getItem(storageKey) as ThemeMode | null;
    return saved ?? defaultMode;
  });

  const setMode = (m: ThemeMode) => {
    setModeState(m);
    try {
      window.localStorage.setItem(storageKey, m);
    } catch {
      /* ignore quota */
    }
  };

  // Применение темы и подписка на смену системной темы при режиме system
  useEffect(() => {
    applyThemeAttr(mode);
    if (mode !== "system" || typeof window === "undefined") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => applyThemeAttr("system");
    mq.addEventListener?.("change", handler);
    return () => mq.removeEventListener?.("change", handler);
  }, [mode]);

  const value = useMemo(() => ({ mode, setMode }), [mode]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return React.useContext(ThemeContext);
}

/**
 * Безопасный ErrorBoundary с контролируемым выводом.
 */
type ErrorFallbackProps = {
  error: Error;
  reset: () => void;
};

function DefaultErrorFallback({ error, reset }: ErrorFallbackProps) {
  return (
    <div role="alert" style={{ padding: 16 }}>
      <h2 style={{ margin: 0, fontSize: 18 }}>Application error</h2>
      <pre style={{ whiteSpace: "pre-wrap", marginTop: 8, color: "crimson" }}>{error.message}</pre>
      <button onClick={reset} style={{ marginTop: 12, padding: "8px 12px", cursor: "pointer" }}>
        Reload view
      </button>
    </div>
  );
}

type ErrorBoundaryProps = {
  children: ReactNode;
  fallback?: (args: { error: Error; reset: () => void }) => React.ReactElement;
};

class ErrorBoundary extends React.Component<ErrorBoundaryProps, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    // Приватный логгер ошибок: не шумим в проде, но даём хук для интеграции observability
    if (process.env.NODE_ENV !== "production") {
      // eslint-disable-next-line no-console
      console.error("[AppProviders] Uncaught error:", error);
    }
  }

  private reset = () => {
    this.setState({ error: null });
  };

  render() {
    const { error } = this.state;
    if (error) {
      const Fallback = this.props.fallback ?? ((p: ErrorFallbackProps) => <DefaultErrorFallback {...p} />);
      return <Fallback error={error} reset={this.reset} />;
    }
    return this.props.children as React.ReactElement;
  }
}

/**
 * Конфигурация QueryClient с промышленными дефолтами:
 * - не ретраим POST/PUT/DELETE по умолчанию
 * - предсказуемый staleTime для снижения лишних запросов
 * - мягкий логгер в dev, тихий в prod
 */
function createQueryClient(config?: QueryClientConfig) {
  const defaultConfig: QueryClientConfig = {
    defaultOptions: {
      queries: {
        retry: (failureCount, error) => {
          // не ретраим явно отменённые запросы или клиентские 4xx
          const err = error as any;
          const status = err?.status ?? err?.response?.status;
          if (status && status >= 400 && status < 500) return false;
          return failureCount < 2;
        },
        refetchOnWindowFocus: false,
        refetchOnReconnect: true,
        staleTime: 30_000,
      },
      mutations: {
        retry: false,
      },
    },
    logger: {
      log: (...args) => {
        if (process.env.NODE_ENV !== "production") {
          // eslint-disable-next-line no-console
          console.log("[RQ]", ...args);
        }
      },
      warn: (...args) => {
        if (process.env.NODE_ENV !== "production") {
          // eslint-disable-next-line no-console
          console.warn("[RQ]", ...args);
        }
      },
      error: (...args) => {
        if (process.env.NODE_ENV !== "production") {
          // eslint-disable-next-line no-console
          console.error("[RQ]", ...args);
        }
      },
    },
  };
  return new QueryClient({ ...defaultConfig, ...config });
}

/**
 * Унифицированный набор провайдеров приложения.
 * Позволяет подменять QueryClient и дефолт темы в рантайме.
 */
export type AppProvidersProps = {
  children: ReactNode;
  themeMode?: ThemeMode;
  queryClient?: QueryClient;
  queryClientConfig?: QueryClientConfig;
  suspenseFallback?: React.ReactNode;
  errorFallback?: (args: { error: Error; reset: () => void }) => React.ReactElement;
};

export function AppProviders({
  children,
  themeMode = "system",
  queryClient,
  queryClientConfig,
  suspenseFallback = <div style={{ padding: 16 }}>Loading…</div>,
  errorFallback,
}: AppProvidersProps) {
  const qc = React.useMemo(() => queryClient ?? createQueryClient(queryClientConfig), [queryClient, queryClientConfig]);

  return (
    <ThemeProvider defaultMode={themeMode}>
      <QueryClientProvider client={qc}>
        <ErrorBoundary fallback={errorFallback}>
          <Suspense fallback={suspenseFallback}>{children}</Suspense>
        </ErrorBoundary>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

/**
 * Хелпер для SSR/пререндеринга: безопасное отключение Suspense при необходимости.
 * В SPA это не требуется, но может быть полезно в тестах.
 */
export function NoSuspenseProviders(props: Omit<AppProvidersProps, "suspenseFallback">) {
  const { children, ...rest } = props;
  return (
    <ThemeProvider defaultMode={rest.themeMode ?? "system"}>
      <QueryClientProvider client={rest.queryClient ?? createQueryClient(rest.queryClientConfig)}>
        <ErrorBoundary fallback={rest.errorFallback}>{children}</ErrorBoundary>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

/**
 * Экспорт контекста темы для удобного импорта из одного места.
 */
export const Theme = {
  useTheme,
};
