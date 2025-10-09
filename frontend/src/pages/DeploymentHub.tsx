import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from "recharts";

/** =========================
 * Types
 * ======================= */

type Env = "dev" | "staging" | "prod";
type DeployStatus = "Healthy" | "Degraded" | "Progressing" | "Failed" | "Unknown";

type GitMeta = {
  sha: string;
  branch: string;
  author?: string;
  message?: string;
};

type ImageMeta = {
  name: string;
  tag: string;
  digest?: string;
};

type Resources = {
  cpu: string; // e.g., "500m"
  memory: string; // e.g., "512Mi"
};

type Deployment = {
  id: string;
  service: string;
  env: Env;
  version: string;
  image: ImageMeta;
  status: DeployStatus;
  replicasDesired: number;
  replicasReady: number;
  updatedAt: number; // ms
  git?: GitMeta;
  resources?: Resources;
};

type DeployHistoryPoint = {
  timestamp: number;
  successful: number;
  failed: number;
  progressing: number;
};

type DeploymentsResponse = {
  environments: Env[];
  services: string[];
  deployments: Deployment[];
};

type HistoryResponse = {
  points: DeployHistoryPoint[];
};

type ActionKind = "deploy" | "promote" | "rollback" | "restart" | "scale";

type ActionRequest =
  | { kind: "deploy"; service: string; env: Env; version: string }
  | { kind: "promote"; service: string; from: Env; to: Env }
  | { kind: "rollback"; service: string; env: Env; toVersion?: string }
  | { kind: "restart"; service: string; env: Env }
  | { kind: "scale"; service: string; env: Env; replicas: number };

type ActionResponse = {
  ok: boolean;
  message?: string;
  deployment?: Deployment;
};

/** =========================
 * Props
 * ======================= */

type Props = {
  apiBase?: string;      // base REST path, default "/api/deploy"
  streamUrl?: string;    // ws:// or /sse for cluster events/logs
  autoRefreshMs?: number;
  className?: string;
};

const DEFAULT_API_BASE = "/api/deploy";
const DEFAULT_STREAM = "/api/deploy/stream";
const FETCH_TIMEOUT_MS = 15_000;
const MAX_RETRIES = 3;
const POLL_MS = 30_000;

/** =========================
 * Utils
 * ======================= */

function formatDate(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleString(undefined, {
    year: "2-digit",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

function formatInt(n: number) {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(n);
}

function formatPerc(n: number) {
  return `${(n * 100).toFixed(0)}%`;
}

async function fetchWithTimeout(input: RequestInfo, init?: RequestInit, timeout = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(input, { ...init, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

async function getJSONWithRetry<T>(url: string, retries = MAX_RETRIES): Promise<T> {
  let lastErr: unknown;
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetchWithTimeout(url, { headers: { Accept: "application/json" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json()) as T;
    } catch (e) {
      lastErr = e;
      if (i < retries) {
        const backoff = Math.min(1000 * 2 ** i, 8000);
        await new Promise((r) => setTimeout(r, backoff));
        continue;
      }
      throw lastErr;
    }
  }
  throw lastErr;
}

async function postJSONWithRetry<T>(url: string, body: any, retries = MAX_RETRIES): Promise<T> {
  let lastErr: unknown;
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetchWithTimeout(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json()) as T;
    } catch (e) {
      lastErr = e;
      if (i < retries) {
        const backoff = Math.min(1000 * 2 ** i, 8000);
        await new Promise((r) => setTimeout(r, backoff));
        continue;
      }
      throw lastErr;
    }
  }
  throw lastErr;
}

function useSessionCache<T>() {
  const get = useCallback((key: string): T | null => {
    try {
      const raw = sessionStorage.getItem(key);
      if (!raw) return null;
      const parsed = JSON.parse(raw) as { ts: number; data: T };
      // 2 минуты актуальности
      if (Date.now() - parsed.ts > 120_000) return null;
      return parsed.data;
    } catch {
      return null;
    }
  }, []);
  const set = useCallback((key: string, data: T) => {
    try {
      sessionStorage.setItem(key, JSON.stringify({ ts: Date.now(), data }));
    } catch {
      // ignore quota
    }
  }, []);
  return { get, set };
}

/** =========================
 * UI Primitives
 * ======================= */

const Skeleton: React.FC<{ className?: string; "data-testid"?: string }> = ({ className, ...rest }) => (
  <div
    aria-busy="true"
    className={`animate-pulse rounded-xl bg-gray-200/70 dark:bg-gray-700/40 ${className ?? ""}`}
    {...rest}
  />
);

const ErrorBanner: React.FC<{ message: string; onRetry?: () => void }> = ({ message, onRetry }) => (
  <div
    role="alert"
    className="w-full rounded-xl border border-red-300 bg-red-50 p-4 text-red-900 dark:border-red-800 dark:bg-red-950/40"
    data-testid="error-banner"
  >
    <div className="flex items-center justify-between gap-4">
      <p className="font-medium">Ошибка: {message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="rounded-lg border px-3 py-1.5 text-sm hover:bg-red-100 active:scale-[0.98] dark:hover:bg-red-900/30"
        >
          Повторить
        </button>
      )}
    </div>
  </div>
);

const Badge: React.FC<{ tone?: "green" | "yellow" | "red" | "gray"; children: React.ReactNode }> = ({ tone = "gray", children }) => {
  const map: Record<string, string> = {
    green: "bg-green-50 text-green-700 border-green-200 dark:bg-green-900/20 dark:text-green-300 dark:border-green-800",
    yellow: "bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-900/20 dark:text-yellow-300 dark:border-yellow-800",
    red: "bg-red-50 text-red-700 border-red-200 dark:bg-red-900/20 dark:text-red-300 dark:border-red-800",
    gray: "bg-gray-50 text-gray-700 border-gray-200 dark:bg-gray-900/40 dark:text-gray-300 dark:border-gray-800",
  };
  return <span className={`inline-flex items-center gap-1 rounded-xl border px-2 py-0.5 text-xs ${map[tone]}`}>{children}</span>;
};

const Confirm: React.FC<{
  title: string;
  text: string;
  confirmText?: string;
  cancelText?: string;
  onConfirm: () => void;
  onCancel: () => void;
}> = ({ title, text, confirmText = "Подтвердить", cancelText = "Отмена", onConfirm, onCancel }) => (
  <div
    role="dialog"
    aria-modal="true"
    className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
    data-testid="confirm-modal"
  >
    <div className="w-full max-w-lg rounded-2xl border bg-white p-5 shadow-xl dark:border-gray-800 dark:bg-gray-900">
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-2 text-sm text-gray-600 dark:text-gray-300">{text}</p>
      <div className="mt-4 flex justify-end gap-2">
        <button onClick={onCancel} className="rounded-lg border px-3 py-1.5 text-sm dark:border-gray-700">
          {cancelText}
        </button>
        <button
          onClick={onConfirm}
          className="rounded-lg bg-black px-3 py-1.5 text-sm text-white hover:opacity-90 active:scale-[0.98] dark:bg-white dark:text-black"
        >
          {confirmText}
        </button>
      </div>
    </div>
  </div>
);

/** =========================
 * Main Page
 * ======================= */

const DeploymentHub: React.FC<Props> = ({
  apiBase = DEFAULT_API_BASE,
  streamUrl = DEFAULT_STREAM,
  autoRefreshMs = POLL_MS,
  className,
}) => {
  const [env, setEnv] = useState<Env | "all">("all");
  const [service, setService] = useState<string | "all">("all");
  const [query, setQuery] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const [data, setData] = useState<DeploymentsResponse | null>(null);
  const [history, setHistory] = useState<HistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [confirm, setConfirm] = useState<null | {
    request: ActionRequest;
    title: string;
    text: string;
  }>(null);

  const [logs, setLogs] = useState<null | { service: string; env: Env; open: boolean; lines: string[] }>(null);

  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const streamRef = useRef<WebSocket | EventSource | null>(null);
  const { get, set } = useSessionCache<DeploymentsResponse>();
  const { get: getH, set: setH } = useSessionCache<HistoryResponse>();

  const cacheKeyList = useMemo(() => `deploy:list:${apiBase}`, [apiBase]);
  const cacheKeyHist = useMemo(() => `deploy:hist:${apiBase}`, [apiBase]);

  const loadAll = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      const cachedList = get(cacheKeyList);
      if (cachedList) setData(cachedList);
      const cachedHist = getH(cacheKeyHist);
      if (cachedHist) setHistory(cachedHist);

      const listUrl = new URL(`${apiBase}/deployments`, window.location.origin);
      const histUrl = new URL(`${apiBase}/history`, window.location.origin);
      const [list, hist] = await Promise.all([
        getJSONWithRetry<DeploymentsResponse>(listUrl.toString()),
        getJSONWithRetry<HistoryResponse>(histUrl.toString()),
      ]);
      setData(list);
      setHistory(hist);
      set(cacheKeyList, list);
      setH(cacheKeyHist, hist);
    } catch (e: any) {
      setError(e?.message ?? "Неизвестная ошибка");
    } finally {
      setLoading(false);
    }
  }, [apiBase, cacheKeyList, cacheKeyHist, get, getH, set, setH]);

  // initial + refresh
  useEffect(() => {
    loadAll();
  }, [loadAll]);

  // streaming: cluster events (status changes) and logs tail via SSE/WS
  useEffect(() => {
    if (streamRef.current instanceof WebSocket) {
      streamRef.current.close();
    } else if (streamRef.current instanceof EventSource) {
      streamRef.current.close();
    }
    streamRef.current = null;

    const connectStream = () => {
      try {
        const raw = streamUrl.startsWith("ws") || streamUrl.startsWith("http") ? streamUrl : new URL(streamUrl, window.location.origin).toString();
        const isWS = raw.startsWith("ws://") || raw.startsWith("wss://");
        if (isWS) {
          const ws = new WebSocket(raw);
          ws.onmessage = (ev) => {
            try {
              const evt = JSON.parse(ev.data);
              if (evt.type === "DEPLOYMENT_UPDATE") {
                setData((prev) => {
                  if (!prev) return prev;
                  const next = { ...prev };
                  const idx = next.deployments.findIndex((d) => d.id === evt.payload.id);
                  if (idx >= 0) next.deployments[idx] = evt.payload as Deployment;
                  else next.deployments.push(evt.payload as Deployment);
                  set(cacheKeyList, next);
                  return next;
                });
              } else if (evt.type === "LOG" && logs?.open) {
                const { service: s, env: e } = evt.payload;
                if (logs.service === s && logs.env === e) {
                  setLogs((l) => (l ? { ...l, lines: [...l.lines, evt.payload.line] } : l));
                }
              }
            } catch {
              // ignore malformed
            }
          };
          streamRef.current = ws;
          return true;
        }
        if ("EventSource" in window) {
          const es = new EventSource(raw);
          es.onmessage = (ev) => {
            try {
              const evt = JSON.parse(ev.data);
              if (evt.type === "DEPLOYMENT_UPDATE") {
                setData((prev) => {
                  if (!prev) return prev;
                  const next = { ...prev };
                  const idx = next.deployments.findIndex((d) => d.id === evt.payload.id);
                  if (idx >= 0) next.deployments[idx] = evt.payload as Deployment;
                  else next.deployments.push(evt.payload as Deployment);
                  set(cacheKeyList, next);
                  return next;
                });
              } else if (evt.type === "LOG" && logs?.open) {
                const { service: s, env: e } = evt.payload;
                if (logs.service === s && logs.env === e) {
                  setLogs((l) => (l ? { ...l, lines: [...l.lines, evt.payload.line] } : l));
                }
              }
            } catch {
              // ignore
            }
          };
          streamRef.current = es;
          return true;
        }
        return false;
      } catch {
        return false;
      }
    };

    const connected = connectStream();
    if (!connected && autoRefresh) {
      if (timerRef.current) clearInterval(timerRef.current);
      timerRef.current = setInterval(() => loadAll(), autoRefreshMs);
    }

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
      if (streamRef.current instanceof WebSocket) streamRef.current.close();
      else if (streamRef.current instanceof EventSource) streamRef.current.close();
    };
  }, [streamUrl, loadAll, autoRefresh, autoRefreshMs, cacheKeyList, logs]);

  /** Derived data */
  const filtered = useMemo(() => {
    const list = data?.deployments ?? [];
    return list
      .filter((d) => (env === "all" ? true : d.env === env))
      .filter((d) => (service === "all" ? true : d.service === service))
      .filter((d) => {
        if (!query.trim()) return true;
        const q = query.toLowerCase();
        return (
          d.service.toLowerCase().includes(q) ||
          d.version.toLowerCase().includes(q) ||
          d.image.name.toLowerCase().includes(q) ||
          d.image.tag.toLowerCase().includes(q) ||
          d.git?.sha?.toLowerCase().includes(q) ||
          d.git?.branch?.toLowerCase().includes(q)
        );
      })
      .sort((a, b) => b.updatedAt - a.updatedAt);
  }, [data, env, service, query]);

  const kpi = useMemo(() => {
    const list = filtered;
    const total = list.length || 1;
    const healthy = list.filter((d) => d.status === "Healthy").length;
    const progressing = list.filter((d) => d.status === "Progressing").length;
    const degraded = list.filter((d) => d.status === "Degraded").length;
    const failed = list.filter((d) => d.status === "Failed").length;
    return {
      total: formatInt(total),
      healthy: `${healthy} (${formatPerc(healthy / total)})`,
      progressing: `${progressing} (${formatPerc(progressing / total)})`,
      degraded: `${degraded} (${formatPerc(degraded / total)})`,
      failed: `${failed} (${formatPerc(failed / total)})`,
    };
  }, [filtered]);

  /** Actions */
  const ask = useCallback((req: ActionRequest) => {
    const desc = (() => {
      switch (req.kind) {
        case "deploy":
          return { title: "Деплой новой версии", text: `Сервис ${req.service} → ${req.env}, версия ${req.version}. Продолжить?` };
        case "promote":
          return { title: "Промоут в следующее окружение", text: `Сервис ${req.service}: ${req.from} → ${req.to}. Продолжить?` };
        case "rollback":
          return {
            title: "Откат версии",
            text: `Сервис ${req.service} в ${req.env}${req.toVersion ? ` → ${req.toVersion}` : ""}. Продолжить?`,
          };
        case "restart":
          return { title: "Перезапуск сервисов", text: `Сервис ${req.service} в ${req.env}. Продолжить?` };
        case "scale":
          return { title: "Масштабирование", text: `Сервис ${req.service} в ${req.env}: изменить число реплик. Продолжить?` };
      }
    })();
    setConfirm({ request: req, title: desc.title, text: desc.text });
  }, []);

  const runAction = useCallback(
    async (req: ActionRequest) => {
      const url = new URL(`${apiBase}/action`, window.location.origin).toString();
      try {
        const res = await postJSONWithRetry<ActionResponse>(url, req);
        if (!res.ok) throw new Error(res.message ?? "Action failed");
        if (res.deployment) {
          setData((prev) => {
            if (!prev) return prev;
            const next = { ...prev };
            const idx = next.deployments.findIndex((d) => d.id === res.deployment!.id);
            if (idx >= 0) next.deployments[idx] = res.deployment!;
            else next.deployments.push(res.deployment!);
            return next;
          });
        }
      } catch (e: any) {
        setError(e?.message ?? "Неизвестная ошибка во время действия");
      } finally {
        setConfirm(null);
      }
    },
    [apiBase]
  );

  const onExportCSV = useCallback(() => {
    const header = [
      "id",
      "service",
      "env",
      "version",
      "image",
      "tag",
      "status",
      "replicasDesired",
      "replicasReady",
      "updatedAt",
      "gitSha",
      "gitBranch",
    ];
    const rows = filtered.map((d) =>
      [
        d.id,
        d.service,
        d.env,
        d.version,
        d.image.name,
        d.image.tag,
        d.status,
        d.replicasDesired,
        d.replicasReady,
        new Date(d.updatedAt).toISOString(),
        d.git?.sha ?? "",
        d.git?.branch ?? "",
      ].join(",")
    );
    const csvContent = [header.join(","), ...rows].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `deployments_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [filtered]);

  /** Logs drawer via SSE (simple) */
  const openLogs = useCallback((s: string, e: Env) => {
    setLogs({ service: s, env: e, open: true, lines: [] });
  }, []);
  const closeLogs = useCallback(() => setLogs(null), []);
  useEffect(() => {
    if (!logs?.open) return;
    const url = new URL(`${apiBase}/logs`, window.location.origin);
    url.searchParams.set("service", logs.service);
    url.searchParams.set("env", logs.env);
    const es = new EventSource(url.toString());
    es.onmessage = (ev) => {
      setLogs((l) => (l ? { ...l, lines: [...l.lines, ev.data] } : l));
    };
    es.onerror = () => {
      // auto-close on error; user can reopen
      es.close();
    };
    return () => es.close();
  }, [logs?.open, logs?.service, logs?.env, apiBase]);

  /** Render helpers */
  function toneForStatus(s: DeployStatus): "green" | "yellow" | "red" | "gray" {
    switch (s) {
      case "Healthy":
        return "green";
      case "Progressing":
        return "yellow";
      case "Degraded":
      case "Failed":
        return "red";
      default:
        return "gray";
    }
  }

  /** View */
  return (
    <div className={`mx-auto max-w-7xl px-4 pb-10 pt-6 ${className ?? ""}`} data-testid="deployment-hub">
      <div className="mb-6 flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <h1 className="text-2xl font-bold">Deployment Hub</h1>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">Центр управления раскатками и состоянием сервисов</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-sm">
            <span className="text-gray-600 dark:text-gray-300">Окружение</span>
            <select
              className="rounded-lg border bg-white px-2 py-1 text-sm outline-none dark:border-gray-700 dark:bg-gray-900"
              value={env}
              onChange={(e) => setEnv(e.target.value as Env | "all")}
              data-testid="env-select"
            >
              <option value="all">all</option>
              {(data?.environments ?? ["dev", "staging", "prod"]).map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <span className="text-gray-600 dark:text-gray-300">Сервис</span>
            <select
              className="rounded-lg border bg-white px-2 py-1 text-sm outline-none dark:border-gray-700 dark:bg-gray-900"
              value={service}
              onChange={(e) => setService(e.target.value as string | "all")}
              data-testid="service-select"
            >
              <option value="all">all</option>
              {(data?.services ?? []).map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <input
            className="w-52 rounded-lg border bg-white px-3 py-1.5 text-sm outline-none placeholder:text-gray-400 dark:border-gray-700 dark:bg-gray-900"
            placeholder="Поиск (service, version, sha)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            data-testid="search-input"
          />
          <label className="inline-flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="h-4 w-4 accent-black dark:accent-white"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span className="text-gray-600 dark:text-gray-300">Автообновление</span>
          </label>
          <button
            onClick={onExportCSV}
            className="rounded-lg border px-3 py-1.5 text-sm hover:bg-gray-50 active:scale-[0.98] dark:border-gray-700 dark:hover:bg-gray-800"
            data-testid="export-csv"
          >
            Экспорт CSV
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadAll} />}

      {/* KPI */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
        {loading ? (
          <>
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </>
        ) : (
          <>
            <div className="rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
              <div className="text-sm text-gray-500 dark:text-gray-400">Всего деплойментов</div>
              <div className="mt-1 text-2xl font-semibold">{kpi.total}</div>
            </div>
            <div className="rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
              <div className="text-sm text-gray-500 dark:text-gray-400">Healthy</div>
              <div className="mt-1 text-2xl font-semibold">{kpi.healthy}</div>
            </div>
            <div className="rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
              <div className="text-sm text-gray-500 dark:text-gray-400">Progressing</div>
              <div className="mt-1 text-2xl font-semibold">{kpi.progressing}</div>
            </div>
            <div className="rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
              <div className="text-sm text-gray-500 dark:text-gray-400">Degraded</div>
              <div className="mt-1 text-2xl font-semibold">{kpi.degraded}</div>
            </div>
            <div className="rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
              <div className="text-sm text-gray-500 dark:text-gray-400">Failed</div>
              <div className="mt-1 text-2xl font-semibold">{kpi.failed}</div>
            </div>
          </>
        )}
      </div>

      {/* Chart */}
      <div className="mt-6 rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
        <div className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-200">Динамика раскаток</div>
        <div className="h-72">
          {loading ? (
            <Skeleton className="h-full" />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history?.points ?? []} margin={{ left: 10, right: 10, top: 10, bottom: 10 }}>
                <defs>
                  <linearGradient id="succ" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="currentColor" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="currentColor" stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(t) => new Date(t).toLocaleDateString(undefined, { month: "short", day: "2-digit" })}
                />
                <YAxis />
                <Tooltip
                  labelFormatter={(l) => formatDate(Number(l))}
                  formatter={(v: any, name: any) => [formatInt(Number(v)), name === "successful" ? "Успешно" : name === "failed" ? "Провал" : "В процессе"]}
                />
                <Legend />
                <Area type="monotone" dataKey="successful" name="Успешно" stroke="currentColor" fill="url(#succ)" strokeWidth={2} />
                <Area type="monotone" dataKey="failed" name="Провал" stroke="currentColor" fillOpacity={0} strokeDasharray="4 4" />
                <Area type="monotone" dataKey="progressing" name="В процессе" stroke="currentColor" fillOpacity={0} strokeDasharray="2 2" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="mt-6 overflow-x-auto rounded-2xl border bg-white shadow-sm dark:border-gray-800 dark:bg-gray-900">
        <table className="min-w-full text-left text-sm" aria-label="Таблица деплойментов" data-testid="deploy-table">
          <thead className="border-b text-gray-600 dark:border-gray-800 dark:text-gray-300">
            <tr>
              <th className="px-3 py-2">Сервис</th>
              <th className="px-3 py-2">Окружение</th>
              <th className="px-3 py-2">Версия</th>
              <th className="px-3 py-2">Образ</th>
              <th className="px-3 py-2">Статус</th>
              <th className="px-3 py-2">Реплики</th>
              <th className="px-3 py-2">Git</th>
              <th className="px-3 py-2">Обновлено</th>
              <th className="px-3 py-2 text-right">Действия</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={9} className="px-3 py-6">
                  <Skeleton className="h-16" />
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-3 py-6 text-center text-gray-500">
                  Нет данных
                </td>
              </tr>
            ) : (
              filtered.map((d) => (
                <tr key={d.id} className="border-b last:border-0 dark:border-gray-800">
                  <td className="px-3 py-2 font-medium">{d.service}</td>
                  <td className="px-3 py-2">{d.env}</td>
                  <td className="px-3 py-2">{d.version}</td>
                  <td className="px-3 py-2">
                    <div className="max-w-[22rem] truncate" title={`${d.image.name}:${d.image.tag}`}>{d.image.name}:{d.image.tag}</div>
                  </td>
                  <td className="px-3 py-2">
                    <Badge tone={toneForStatus(d.status)}>{d.status}</Badge>
                  </td>
                  <td className="px-3 py-2">
                    {d.replicasReady}/{d.replicasDesired}
                  </td>
                  <td className="px-3 py-2">
                    <div className="max-w-[16rem] truncate" title={`${d.git?.branch ?? ""} ${d.git?.sha ?? ""}`}>
                      {d.git?.branch ?? ""} {d.git?.sha?.slice(0, 8) ?? ""}
                    </div>
                  </td>
                  <td className="px-3 py-2">{formatDate(d.updatedAt)}</td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-2">
                      <button
                        className="rounded border px-2 py-1 text-xs dark:border-gray-700"
                        onClick={() => ask({ kind: "promote", service: d.service, from: d.env, to: d.env === "dev" ? "staging" : "prod" })}
                        disabled={d.env === "prod"}
                        aria-disabled={d.env === "prod"}
                      >
                        Promote
                      </button>
                      <button
                        className="rounded border px-2 py-1 text-xs dark:border-gray-700"
                        onClick={() => ask({ kind: "rollback", service: d.service, env: d.env })}
                      >
                        Rollback
                      </button>
                      <button
                        className="rounded border px-2 py-1 text-xs dark:border-gray-700"
                        onClick={() => ask({ kind: "restart", service: d.service, env: d.env })}
                      >
                        Restart
                      </button>
                      <button
                        className="rounded border px-2 py-1 text-xs dark:border-gray-700"
                        onClick={() => {
                          const replicas = Number(prompt("Новое число реплик:", String(d.replicasDesired)));
                          if (Number.isFinite(replicas)) {
                            ask({ kind: "scale", service: d.service, env: d.env, replicas: clamp(replicas, 0, 1000) });
                          }
                        }}
                      >
                        Scale
                      </button>
                      <button
                        className="rounded border px-2 py-1 text-xs dark:border-gray-700"
                        onClick={() => openLogs(d.service, d.env)}
                      >
                        Logs
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Confirm modal */}
      {confirm && (
        <Confirm
          title={confirm.title}
          text={confirm.text}
          onCancel={() => setConfirm(null)}
          onConfirm={() => runAction(confirm.request)}
        />
      )}

      {/* Logs drawer */}
      {logs?.open && (
        <div
          className="fixed inset-y-0 right-0 z-50 flex w-full max-w-3xl flex-col border-l bg-white shadow-xl dark:border-gray-800 dark:bg-gray-900"
          role="dialog"
          aria-modal="true"
          data-testid="logs-drawer"
        >
          <div className="flex items-center justify-between border-b p-3 dark:border-gray-800">
            <div className="font-semibold">Логи: {logs.service} ({logs.env})</div>
            <button onClick={closeLogs} className="rounded-lg border px-3 py-1.5 text-sm dark:border-gray-700">
              Закрыть
            </button>
          </div>
          <div className="flex-1 overflow-auto p-3 font-mono text-xs leading-relaxed">
            {logs.lines.length === 0 ? (
              <div className="text-gray-500">Стриминг логов…</div>
            ) : (
              logs.lines.slice(-2000).map((l, i) => (
                <pre key={i} className="whitespace-pre-wrap">{l}</pre>
              ))
            )}
          </div>
        </div>
      )}

      <div className="mt-6 text-xs text-gray-500 dark:text-gray-400">Источник данных: {apiBase}</div>
    </div>
  );
};

export default DeploymentHub;
