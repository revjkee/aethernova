import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  BarChart,
  Bar,
  Legend,
} from "recharts";

type TimeRange = "24h" | "7d" | "30d" | "90d" | "1y";
type Fiat = "USD" | "EUR";

type TokenStatsSnapshot = {
  timestamp: number;         // ms since epoch
  price: number;             // baseCurrency
  volume24h: number;         // baseCurrency
  marketCap: number;         // baseCurrency
  holders: number;           // integer
  txCount: number;           // integer in interval
};

type TokenStatsResponse = {
  symbol: string;
  name: string;
  decimals: number;
  circulatingSupply: number;
  baseCurrency: Fiat;
  snapshots: TokenStatsSnapshot[];
  totals?: {
    volume24h?: number;
    marketCap?: number;
    holders?: number;
  };
};

type Props = {
  apiUrl?: string;           // GET endpoint returning TokenStatsResponse
  streamUrl?: string;        // optional ws:// or sse endpoint emitting TokenStatsSnapshot
  initialRange?: TimeRange;
  baseCurrency?: Fiat;       // fallback if API does not specify
  className?: string;
  autoRefreshMs?: number;    // polling fallback interval
};

const DEFAULT_API = "/api/token/stats";
const DEFAULT_STREAM = "/api/token/stream";
const DEFAULT_RANGE: TimeRange = "7d";
const DEFAULT_CURRENCY: Fiat = "USD";
const POLL_MS = 30_000;
const FETCH_TIMEOUT_MS = 15_000;
const MAX_RETRIES = 3;

function formatInt(n: number): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(n);
}

function formatNumber(n: number, maxFraction = 2): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: maxFraction }).format(n);
}

function formatCurrency(n: number, currency: Fiat): string {
  return new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: 2 }).format(n);
}

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

function rangeToMs(range: TimeRange): number {
  const day = 24 * 60 * 60 * 1000;
  switch (range) {
    case "24h": return 1 * day;
    case "7d": return 7 * day;
    case "30d": return 30 * day;
    case "90d": return 90 * day;
    case "1y": return 365 * day;
  }
}

function filterByRange(snapshots: TokenStatsSnapshot[], range: TimeRange): TokenStatsSnapshot[] {
  if (!snapshots.length) return snapshots;
  const cutoff = Date.now() - rangeToMs(range);
  return snapshots.filter(s => s.timestamp >= cutoff);
}

function toCSV(rows: TokenStatsSnapshot[]): string {
  const header = ["timestamp", "datetime", "price", "volume24h", "marketCap", "holders", "txCount"];
  const lines = rows.map(r => [
    r.timestamp,
    new Date(r.timestamp).toISOString(),
    r.price,
    r.volume24h,
    r.marketCap,
    r.holders,
    r.txCount,
  ].join(","));
  return [header.join(","), ...lines].join("\n");
}

async function fetchWithTimeout(input: RequestInfo, init?: RequestInit, timeoutMs = FETCH_TIMEOUT_MS): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(input, { ...init, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

async function getJSONWithRetry<T>(url: string, retries = MAX_RETRIES): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetchWithTimeout(url, { headers: { "Accept": "application/json" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return data as T;
    } catch (err) {
      lastErr = err;
      if (attempt < retries) {
        const backoff = Math.min(1000 * 2 ** attempt, 8000);
        await new Promise(r => setTimeout(r, backoff));
        continue;
      }
      throw lastErr;
    }
  }
  // TS placation, unreachable
  throw lastErr;
}

function useSessionCache<T>() {
  const get = useCallback((key: string): T | null => {
    if (typeof window === "undefined") return null;
    try {
      const raw = sessionStorage.getItem(key);
      if (!raw) return null;
      const parsed = JSON.parse(raw) as { ts: number; data: T };
      // 2 minutes staleness window
      if (Date.now() - parsed.ts > 120_000) return null;
      return parsed.data;
    } catch {
      return null;
    }
  }, []);
  const set = useCallback((key: string, data: T) => {
    if (typeof window === "undefined") return;
    try {
      sessionStorage.setItem(key, JSON.stringify({ ts: Date.now(), data }));
    } catch {
      // ignore quota errors
    }
  }, []);
  return { get, set };
}

const Skeleton: React.FC<{ className?: string; "data-testid"?: string; children?: React.ReactNode }> = ({ className, children, ...rest }) => (
  <div
    aria-busy="true"
    className={`animate-pulse rounded-xl bg-gray-200/70 dark:bg-gray-700/40 ${className ?? ""}`}
    {...rest}
  >
    {children}
  </div>
);

const ErrorBanner: React.FC<{ message: string; onRetry?: () => void }> = ({ message, onRetry }) => (
  <div
    role="alert"
    className="w-full rounded-xl border border-red-300 bg-red-50 p-4 text-red-900 dark:border-red-800 dark:bg-red-950/40"
    data-testid="error-banner"
  >
    <div className="flex items-center justify-between gap-4">
      <p className="font-medium">Ошибка загрузки: {message}</p>
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

const ControlSelect: React.FC<{
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { label: string; value: string }[];
  "data-testid"?: string;
}> = ({ label, value, onChange, options, ...rest }) => (
  <label className="flex items-center gap-2 text-sm">
    <span className="text-gray-600 dark:text-gray-300">{label}</span>
    <select
      className="rounded-lg border bg-white px-2 py-1 text-sm outline-none hover:bg-gray-50 dark:border-gray-700 dark:bg-gray-900 dark:hover:bg-gray-800"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      {...rest}
    >
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  </label>
);

const Toggle: React.FC<{ label: string; checked: boolean; onChange: (v: boolean) => void }> = ({ label, checked, onChange }) => (
  <label className="inline-flex cursor-pointer items-center gap-2 text-sm">
    <input
      type="checkbox"
      className="h-4 w-4 accent-black dark:accent-white"
      checked={checked}
      onChange={(e) => onChange(e.target.checked)}
    />
    <span className="text-gray-600 dark:text-gray-300">{label}</span>
  </label>
);

const KPI: React.FC<{ label: string; value: string; sub?: string; "data-testid"?: string }> = ({ label, value, sub, ...rest }) => (
  <div
    className="rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900"
    {...rest}
  >
    <div className="text-sm text-gray-500 dark:text-gray-400">{label}</div>
    <div className="mt-1 text-2xl font-semibold">{value}</div>
    {sub ? <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">{sub}</div> : null}
  </div>
);

const TokenStatsView: React.FC<Props> = ({
  apiUrl = DEFAULT_API,
  streamUrl = DEFAULT_STREAM,
  initialRange = DEFAULT_RANGE,
  baseCurrency = DEFAULT_CURRENCY,
  className,
  autoRefreshMs = POLL_MS,
}) => {
  const [range, setRange] = useState<TimeRange>(initialRange);
  const [currency, setCurrency] = useState<Fiat>(baseCurrency);
  const [data, setData] = useState<TokenStatsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const wsRef = useRef<WebSocket | EventSource | null>(null);
  const { get, set } = useSessionCache<TokenStatsResponse>();

  const cacheKey = useMemo(() => {
    return `token-stats:${apiUrl}:${range}:${currency}`;
  }, [apiUrl, range, currency]);

  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      const cached = get(cacheKey);
      if (cached) {
        setData(cached);
        setLoading(false);
      }
      const url = new URL(apiUrl, typeof window !== "undefined" ? window.location.origin : "http://localhost");
      url.searchParams.set("range", range);
      url.searchParams.set("currency", currency);
      const fresh = await getJSONWithRetry<TokenStatsResponse>(url.toString());
      // prefer API baseCurrency if present
      if (!fresh.baseCurrency) fresh.baseCurrency = currency;
      setData(fresh);
      set(cacheKey, fresh);
    } catch (e: any) {
      setError(e?.message ?? "Неизвестная ошибка");
    } finally {
      setLoading(false);
    }
  }, [apiUrl, range, currency, cacheKey, get, set]);

  // initial + range/currency changes
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range, currency, apiUrl]);

  // live updates: prefer WebSocket, then EventSource (SSE), fallback to polling
  useEffect(() => {
    // clear previous
    if (wsRef.current instanceof WebSocket) {
      wsRef.current.close();
    } else if (wsRef.current instanceof EventSource) {
      wsRef.current.close();
    }
    wsRef.current = null;

    const connectWS = () => {
      try {
        const url = new URL(streamUrl, typeof window !== "undefined" ? window.location.origin : "http://localhost");
        url.searchParams.set("currency", currency);
        const raw = url.toString();
        // Try WebSocket first if scheme is ws(s) or can be upgraded
        const isWS = raw.startsWith("ws://") || raw.startsWith("wss://");
        if (isWS) {
          const ws = new WebSocket(raw);
          ws.onmessage = (ev) => {
            try {
              const snap = JSON.parse(ev.data) as TokenStatsSnapshot;
              setData(prev => {
                if (!prev) return prev;
                const next = { ...prev, snapshots: [...prev.snapshots, snap] };
                set(cacheKey, next);
                return next;
              });
            } catch { /* ignore */ }
          };
          ws.onerror = () => { /* ignore, fallback below */ };
          wsRef.current = ws;
          return true;
        }
        // Try SSE
        if ("EventSource" in window) {
          const es = new EventSource(raw);
          es.onmessage = (ev) => {
            try {
              const snap = JSON.parse(ev.data) as TokenStatsSnapshot;
              setData(prev => {
                if (!prev) return prev;
                const next = { ...prev, snapshots: [...prev.snapshots, snap] };
                set(cacheKey, next);
                return next;
              });
            } catch { /* ignore */ }
          };
          es.onerror = () => { /* network hiccup */ };
          wsRef.current = es;
          return true;
        }
        return false;
      } catch {
        return false;
      }
    };

    const connected = connectWS();

    if (!connected && autoRefresh) {
      if (pollTimer.current) clearInterval(pollTimer.current);
      pollTimer.current = setInterval(() => load(), autoRefreshMs);
    }

    return () => {
      if (pollTimer.current) {
        clearInterval(pollTimer.current);
        pollTimer.current = null;
      }
      if (wsRef.current instanceof WebSocket) {
        wsRef.current.close();
      } else if (wsRef.current instanceof EventSource) {
        wsRef.current.close();
      }
    };
  }, [streamUrl, currency, autoRefresh, autoRefreshMs, load, cacheKey, set]);

  const filtered = useMemo(() => {
    const snaps = data?.snapshots ?? [];
    const rows = filterByRange(snaps, range).sort((a, b) => a.timestamp - b.timestamp);
    return rows;
  }, [data, range]);

  const latest = filtered.at(-1) ?? data?.snapshots?.at(-1) ?? null;

  const kpis = useMemo(() => {
    const c = (data?.baseCurrency ?? currency) as Fiat;
    return {
      price: latest ? formatCurrency(latest.price, c) : "—",
      mcap: latest ? formatCurrency(latest.marketCap, c) : "—",
      vol24: (data?.totals?.volume24h ?? latest?.volume24h) != null
        ? formatCurrency((data?.totals?.volume24h ?? latest!.volume24h)!, c)
        : "—",
      holders: latest ? formatInt(latest.holders) : "—",
      tx: latest ? formatInt(latest.txCount) : "—",
      supply: data?.circulatingSupply != null ? formatNumber(data.circulatingSupply, 0) : "—",
    };
  }, [data, latest, currency]);

  const onDownloadCSV = useCallback(() => {
    const csv = toCSV(filtered);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const sym = data?.symbol ?? "TOKEN";
    a.download = `${sym}_stats_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [filtered, data]);

  return (
    <div className={`mx-auto max-w-7xl px-4 pb-10 pt-6 ${className ?? ""}`} data-testid="token-stats-view">
      {/* Header */}
      <div className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <h1 className="text-2xl font-bold">
            {data?.name ?? "Token"} {data?.symbol ? `(${data.symbol})` : ""}
          </h1>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">
            Диапазон: {range.toUpperCase()} • Валюта: {(data?.baseCurrency ?? currency)}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <ControlSelect
            label="Диапазон"
            value={range}
            onChange={(v) => setRange(v as TimeRange)}
            options={[
              { label: "24ч", value: "24h" },
              { label: "7д", value: "7d" },
              { label: "30д", value: "30d" },
              { label: "90д", value: "90d" },
              { label: "1г", value: "1y" },
            ]}
            data-testid="range-select"
          />
          <ControlSelect
            label="Валюта"
            value={currency}
            onChange={(v) => setCurrency(v as Fiat)}
            options={[
              { label: "USD", value: "USD" },
              { label: "EUR", value: "EUR" },
            ]}
            data-testid="currency-select"
          />
          <Toggle label="Автообновление" checked={autoRefresh} onChange={setAutoRefresh} />
          <button
            onClick={onDownloadCSV}
            className="rounded-lg border px-3 py-1.5 text-sm hover:bg-gray-50 active:scale-[0.98] dark:border-gray-700 dark:hover:bg-gray-800"
            aria-label="Скачать CSV"
            data-testid="download-csv"
          >
            Экспорт CSV
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && <ErrorBanner message={error} onRetry={load} />}

      {/* KPIs */}
      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-6">
        {loading ? (
          <>
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </>
        ) : (
          <>
            <KPI label="Цена" value={kpis.price} data-testid="kpi-price" />
            <KPI label="Капитализация" value={kpis.mcap} data-testid="kpi-mcap" />
            <KPI label="Объем 24ч" value={kpis.vol24} data-testid="kpi-vol24" />
            <KPI label="Держатели" value={kpis.holders} data-testid="kpi-holders" />
            <KPI label="Транзакций (посл.)" value={kpis.tx} data-testid="kpi-tx" />
            <KPI label="Оборот в обращении" value={kpis.supply} data-testid="kpi-supply" />
          </>
        )}
      </div>

      {/* Charts */}
      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
          <div className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-200">Динамика цены</div>
          <div className="h-72">
            {loading ? (
              <Skeleton className="h-full" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={filtered} margin={{ left: 10, right: 10, top: 10, bottom: 10 }}>
                  <defs>
                    <linearGradient id="priceGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="currentColor" stopOpacity={0.35}/>
                      <stop offset="95%" stopColor="currentColor" stopOpacity={0.05}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.25}/>
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={(t) => new Date(t).toLocaleDateString(undefined, { month: "short", day: "2-digit" })}
                  />
                  <YAxis
                    tickFormatter={(v) => formatNumber(v)}
                    width={70}
                  />
                  <Tooltip
                    formatter={(value: any) => [formatNumber(value), "Цена"]}
                    labelFormatter={(label) => formatDate(Number(label))}
                  />
                  <Area type="monotone" dataKey="price" stroke="currentColor" fill="url(#priceGradient)" strokeWidth={2}/>
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
          <div className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-200">Объем и транзакции</div>
          <div className="h-72">
            {loading ? (
              <Skeleton className="h-full" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={filtered} margin={{ left: 10, right: 10, top: 10, bottom: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.25}/>
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={(t) => new Date(t).toLocaleDateString(undefined, { month: "short", day: "2-digit" })}
                  />
                  <YAxis yAxisId="left" tickFormatter={(v) => formatNumber(v)} width={70}/>
                  <YAxis yAxisId="right" orientation="right" tickFormatter={(v) => formatInt(v)} width={50}/>
                  <Tooltip
                    formatter={(val: any, name, props) => {
                      if (props.dataKey === "volume24h") return [formatNumber(val), "Объем 24ч"];
                      if (props.dataKey === "txCount") return [formatInt(val), "Транзакции"];
                      return [val, name];
                    }}
                    labelFormatter={(label) => formatDate(Number(label))}
                  />
                  <Legend />
                  <Bar yAxisId="left" dataKey="volume24h" name="Объем 24ч" />
                  <Bar yAxisId="right" dataKey="txCount" name="Транзакции" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="mt-6 rounded-2xl border bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
        <div className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-200">Последние точки данных</div>
        <div className="overflow-x-auto">
          {loading ? (
            <Skeleton className="h-40" />
          ) : (
            <table className="min-w-full text-left text-sm" aria-label="Таблица метрик токена">
              <thead className="border-b text-gray-600 dark:border-gray-700 dark:text-gray-300">
                <tr>
                  <th className="px-3 py-2">Время</th>
                  <th className="px-3 py-2">Цена</th>
                  <th className="px-3 py-2">Капитализация</th>
                  <th className="px-3 py-2">Объем 24ч</th>
                  <th className="px-3 py-2">Держатели</th>
                  <th className="px-3 py-2">Транзакции</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(-200).reverse().map((r) => (
                  <tr key={r.timestamp} className="border-b last:border-0 dark:border-gray-800">
                    <td className="px-3 py-2">{formatDate(r.timestamp)}</td>
                    <td className="px-3 py-2">{formatCurrency(r.price, (data?.baseCurrency ?? currency) as Fiat)}</td>
                    <td className="px-3 py-2">{formatCurrency(r.marketCap, (data?.baseCurrency ?? currency) as Fiat)}</td>
                    <td className="px-3 py-2">{formatCurrency(r.volume24h, (data?.baseCurrency ?? currency) as Fiat)}</td>
                    <td className="px-3 py-2">{formatInt(r.holders)}</td>
                    <td className="px-3 py-2">{formatInt(r.txCount)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Footer meta */}
      <div className="mt-6 text-xs text-gray-500 dark:text-gray-400">
        Обновлено: {latest ? formatDate(latest.timestamp) : "—"}
      </div>
    </div>
  );
};

export default TokenStatsView;
