// frontend/src/pages/AnomalyTracker.tsx
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  Fragment,
} from "react";

/**
 * AnomalyTracker — производственная страница мониторинга аномалий.
 *
 * Возможности:
 * - Источник данных: SSE (EventSource) при наличии, fallback на пуллинг fetch + экспоненциальный бэкофф
 * - Безопасная отмена запросов (AbortController), защита от гонок
 * - Авто-реполл, ручной рефреш, офлайн-индикатор
 * - Фильтры (severity/status/source/tags), поиск, сортировка, пагинация
 * - Скелетоны загрузки, мини-графики (SVG sparkline), пустые состояния
 * - Оптимистичные действия (Acknowledge/Close) с откатом при ошибке
 * - Экспорт CSV, сохранение пользовательских настроек в localStorage
 * - Доступность: ARIA-атрибуты, клавиатурная навигация, понятные роли
 *
 * Предполагаемые эндпоинты (адаптируйте под ваш backend):
 *  - GET  /api/anomalies?since=<ISO>&limit=<n>
 *  - POST /api/anomalies/:id/ack
 *  - POST /api/anomalies/:id/close
 *  - SSE  /api/anomalies/stream (event: "anomaly", data: AnomalyDTO)
 */

/* =========================
   Типы домена и утилиты
   ========================= */

type Severity = "low" | "medium" | "high" | "critical";
type AStatus = "open" | "acknowledged" | "closed";

export type AnomalyDTO = {
  id: string;
  occurredAt: string; // ISO
  source: string; // сервис/микросервис
  metric: string; // имя метрики
  value: number;
  baseline: number;
  zScore: number;
  severity: Severity;
  status: AStatus;
  tags: string[];
  // Для мини-графика: последние точки по метрике (необязательно)
  series?: number[];
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function parseAnomaly(raw: unknown): AnomalyDTO | null {
  if (!isRecord(raw)) return null;
  const id = String(raw.id ?? "");
  const occurredAt = String(raw.occurredAt ?? "");
  if (!id || !occurredAt) return null;
  const series =
    Array.isArray(raw.series) && raw.series.every((x) => Number.isFinite(Number(x)))
      ? (raw.series as number[])
      : undefined;

  const sev = ["low", "medium", "high", "critical"].includes(String(raw.severity))
    ? (raw.severity as Severity)
    : ("medium" as Severity);

  const st = ["open", "acknowledged", "closed"].includes(String(raw.status))
    ? (raw.status as AStatus)
    : ("open" as AStatus);

  return {
    id,
    occurredAt,
    source: String(raw.source ?? "unknown"),
    metric: String(raw.metric ?? "unknown"),
    value: Number(raw.value ?? 0),
    baseline: Number(raw.baseline ?? 0),
    zScore: Number(raw.zScore ?? 0),
    severity: sev,
    status: st,
    tags: Array.isArray(raw.tags) ? raw.tags.map(String) : [],
    series,
  };
}

function parseList(raw: unknown): AnomalyDTO[] {
  if (!Array.isArray(raw)) return [];
  const xs = raw.map(parseAnomaly).filter(Boolean) as AnomalyDTO[];
  return xs;
}

function fmtDateTime(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "—";
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "—";
  }
}

function classNames(...xs: Array<string | false | undefined | null>) {
  return xs.filter(Boolean).join(" ");
}

function severityTone(s: Severity) {
  switch (s) {
    case "low":
      return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300 border-emerald-300/50";
    case "medium":
      return "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300 border-amber-300/50";
    case "high":
      return "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300 border-orange-300/50";
    case "critical":
      return "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300 border-red-300/50";
  }
}

function statusTone(s: AStatus) {
  switch (s) {
    case "open":
      return "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300 border-blue-300/50";
    case "acknowledged":
      return "bg-violet-100 text-violet-800 dark:bg-violet-900/30 dark:text-violet-300 border-violet-300/50";
    case "closed":
      return "bg-zinc-200 text-zinc-800 dark:bg-zinc-800/50 dark:text-zinc-200 border-zinc-300/50";
  }
}

function downloadBlob(filename: string, content: string, mime = "text/csv;charset=utf-8") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* =========================
   Настройки пользователя
   ========================= */

type UserPrefs = {
  pageSize: number;
  autoRefreshMs: number; // интервал пуллинга (если нет SSE) и фоновое обновление
  enableSSE: boolean; // попытаться подключить SSE
  showSeries: boolean; // показывать мини-графики
};

const DEFAULT_PREFS: UserPrefs = {
  pageSize: 20,
  autoRefreshMs: 20_000,
  enableSSE: true,
  showSeries: true,
};

function loadPrefs(): UserPrefs {
  try {
    const raw = localStorage.getItem("anomaly:prefs");
    if (!raw) return DEFAULT_PREFS;
    const p = JSON.parse(raw);
    const pageSize = Math.max(5, Math.min(200, Number(p.pageSize ?? DEFAULT_PREFS.pageSize)));
    const autoRefreshMs = Math.max(0, Number(p.autoRefreshMs ?? DEFAULT_PREFS.autoRefreshMs));
    const enableSSE = Boolean(p.enableSSE ?? DEFAULT_PREFS.enableSSE);
    const showSeries = Boolean(p.showSeries ?? DEFAULT_PREFS.showSeries);
    return { pageSize, autoRefreshMs, enableSSE, showSeries };
  } catch {
    return DEFAULT_PREFS;
  }
}

function savePrefs(p: UserPrefs) {
  try {
    localStorage.setItem("anomaly:prefs", JSON.stringify(p));
  } catch {
    /* ignore */
  }
}

/* =========================
   Источник данных (SSE/HTTP)
   ========================= */

type FetchState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ok"; data: AnomalyDTO[]; updatedAt: number }
  | { kind: "error"; error: string; since?: number };

type SortKey = "occurredAt" | "severity" | "zScore" | "value" | "source" | "metric" | "status";
type SortDir = "asc" | "desc";

function useAnomalies(opts: {
  urlList?: string; // GET list
  urlSSE?: string; // SSE stream endpoint
  autoRefreshMs?: number;
  enableSSE?: boolean;
}) {
  const urlList = opts.urlList ?? "/api/anomalies";
  const urlSSE = opts.urlSSE ?? "/api/anomalies/stream";
  const autoRefreshMs = opts.autoRefreshMs ?? 20_000;
  const enableSSE = opts.enableSSE ?? true;

  const [state, setState] = useState<FetchState>({ kind: "idle" });
  const [isOffline, setOffline] = useState<boolean>(!navigator.onLine);
  const abortRef = useRef<AbortController | null>(null);
  const timerRef = useRef<number | null>(null);
  const backoffRef = useRef<number>(1000);
  const sseRef = useRef<EventSource | null>(null);
  const cacheRef = useRef<Map<string, AnomalyDTO>>(new Map());

  const clearTimer = () => {
    if (timerRef.current) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  };

  const applySet = (fn: (m: Map<string, AnomalyDTO>) => void) => {
    const m = new Map(cacheRef.current);
    fn(m);
    cacheRef.current = m;
    setState({ kind: "ok", data: [...m.values()].sort((a, b) => b.occurredAt.localeCompare(a.occurredAt)), updatedAt: Date.now() });
  };

  const handleSSEMessage = useCallback((ev: MessageEvent) => {
    try {
      const payload = JSON.parse(ev.data);
      const dto = parseAnomaly(payload);
      if (!dto) return;
      applySet((m) => m.set(dto.id, dto));
    } catch {
      // ignore malformed
    }
  }, []);

  const startSSE = useCallback(() => {
    if (!enableSSE || typeof EventSource === "undefined") return;
    try {
      const es = new EventSource(urlSSE, { withCredentials: false });
      sseRef.current = es;
      es.addEventListener("anomaly", handleSSEMessage as any);
      es.addEventListener("message", handleSSEMessage as any);
      es.addEventListener("error", () => {
        // При ошибке закроем и позже переподключимся через пуллинг
        es.close();
        sseRef.current = null;
      });
    } catch {
      sseRef.current = null;
    }
  }, [enableSSE, handleSSEMessage, urlSSE]);

  const stopSSE = useCallback(() => {
    sseRef.current?.close();
    sseRef.current = null;
  }, []);

  const loadList = useCallback(async (background = false) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    if (!background && state.kind !== "ok") setState({ kind: "loading" });

    try {
      const url = new URL(urlList, window.location.origin);
      url.searchParams.set("limit", "500"); // подстраивайте
      const res = await fetch(url.toString(), {
        method: "GET",
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      const list = parseList(json);

      applySet((m) => {
        m.clear();
        for (const a of list) m.set(a.id, a);
      });

      backoffRef.current = 1000; // reset backoff
    } catch (e: any) {
      if (e?.name === "AbortError") return;
      const msg = e instanceof Error ? e.message : "Unknown error";
      setState({ kind: "error", error: msg, since: Date.now() });
      backoffRef.current = Math.min(backoffRef.current * 2, 60_000);
      clearTimer();
      timerRef.current = window.setTimeout(() => void loadList(true), backoffRef.current);
    }
  }, [state.kind, urlList]);

  // online/offline
  useEffect(() => {
    const onOnline = () => {
      setOffline(false);
      void loadList(false);
      if (enableSSE) startSSE();
    };
    const onOffline = () => {
      setOffline(true);
      stopSSE();
    };
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, [enableSSE, loadList, startSSE, stopSSE]);

  // init
  useEffect(() => {
    void loadList(false);
    if (enableSSE && navigator.onLine) startSSE();
    return () => {
      abortRef.current?.abort();
      stopSSE();
      clearTimer();
    };
  }, [enableSSE, loadList, startSSE, stopSSE]);

  // авто-пуллинг (фон)
  useEffect(() => {
    if (!autoRefreshMs || autoRefreshMs <= 0) return;
    clearTimer();
    timerRef.current = window.setTimeout(() => void loadList(true), autoRefreshMs);
    return () => clearTimer();
  }, [autoRefreshMs, state.kind === "ok" ? state.updatedAt : 0, loadList]);

  const refresh = useCallback(() => void loadList(false), [loadList]);

  // optimistic actions
  const postAction = useCallback(
    async (id: string, action: "ack" | "close") => {
      const prev = cacheRef.current.get(id);
      if (!prev) return;
      const optimistic: AnomalyDTO = {
        ...prev,
        status: action === "ack" ? "acknowledged" : "closed",
      };
      applySet((m) => m.set(id, optimistic));

      try {
        const res = await fetch(`/api/anomalies/${encodeURIComponent(id)}/${action}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        // optionally merge returned entity
      } catch (e) {
        // rollback
        applySet((m) => {
          if (prev) m.set(id, prev);
        });
      }
    },
    [],
  );

  return { state, isOffline, refresh, actions: { ack: (id: string) => postAction(id, "ack"), close: (id: string) => postAction(id, "close") } };
}

/* =========================
   Компоненты UI
   ========================= */

function Badge({ tone, children }: { tone: "ok" | "warn" | "danger" | "info" | "muted"; children: React.ReactNode }) {
  const tones: Record<string, string> = {
    ok: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300 border-emerald-300/50",
    warn: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300 border-amber-300/50",
    danger: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300 border-red-300/50",
    info: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300 border-blue-300/50",
    muted: "bg-zinc-200 text-zinc-800 dark:bg-zinc-800/40 dark:text-zinc-200 border-zinc-300/50",
  };
  return <span className={classNames("inline-flex items-center px-2 py-0.5 rounded-md text-xs border", tones[tone])}>{children}</span>;
}

function SectionCard(props: { title: string; children: React.ReactNode; className?: string; right?: React.ReactNode }) {
  return (
    <section className={classNames("rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm", "p-5 md:p-6", props.className)}>
      <div className="flex items-start justify-between gap-4">
        <h2 className="text-base md:text-lg font-semibold text-zinc-900 dark:text-zinc-100">{props.title}</h2>
        {props.right}
      </div>
      <div className="mt-3">{props.children}</div>
    </section>
  );
}

function SkeletonRow() {
  return (
    <div className="grid grid-cols-12 gap-3 p-3 border-b border-zinc-200 dark:border-zinc-800">
      <div className="col-span-2 h-4 rounded bg-zinc-200 dark:bg-zinc-800 animate-pulse" />
      <div className="col-span-2 h-4 rounded bg-zinc-200 dark:bg-zinc-800 animate-pulse" />
      <div className="col-span-2 h-4 rounded bg-zinc-200 dark:bg-zinc-800 animate-pulse" />
      <div className="col-span-1 h-4 rounded bg-zinc-200 dark:bg-zinc-800 animate-pulse" />
      <div className="col-span-1 h-4 rounded bg-zinc-200 dark:bg-zinc-800 animate-pulse" />
      <div className="col-span-2 h-4 rounded bg-zinc-200 dark:bg-zinc-800 animate-pulse" />
      <div className="col-span-2 h-4 rounded bg-zinc-200 dark:bg-zinc-800 animate-pulse" />
    </div>
  );
}

function Sparkline({ series }: { series?: number[] }) {
  if (!series || series.length < 2) return <div className="text-xs text-zinc-500">no data</div>;
  const w = 120;
  const h = 28;
  const min = Math.min(...series);
  const max = Math.max(...series);
  const span = max - min || 1;
  const pts = series.map((v, i) => {
    const x = (i / (series.length - 1)) * (w - 2) + 1;
    const y = h - 1 - ((v - min) / span) * (h - 2);
    return `${x},${y}`;
  });
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-label="mini series chart">
      <polyline fill="none" stroke="currentColor" strokeWidth="1.5" points={pts.join(" ")} />
    </svg>
  );
}

/* =========================
   Фильтры, поиск, сорт
   ========================= */

type FilterState = {
  q: string;
  severity: Set<Severity>;
  status: Set<AStatus>;
  source: string; // exact match if provided
  tag: string; // contains
};

function useFilters() {
  const [filters, setFilters] = useState<FilterState>({
    q: "",
    severity: new Set<Severity>(),
    status: new Set<AStatus>(),
    source: "",
    tag: "",
  });

  const toggleSet = <T,>(curr: Set<T>, val: T): Set<T> => {
    const s = new Set(curr);
    s.has(val) ? s.delete(val) : s.add(val);
    return s;
  };

  return {
    filters,
    setQuery: (q: string) => setFilters((f) => ({ ...f, q })),
    toggleSeverity: (s: Severity) => setFilters((f) => ({ ...f, severity: toggleSet(f.severity, s) })),
    toggleStatus: (s: AStatus) => setFilters((f) => ({ ...f, status: toggleSet(f.status, s) })),
    setSource: (source: string) => setFilters((f) => ({ ...f, source })),
    setTag: (tag: string) => setFilters((f) => ({ ...f, tag })),
    reset: () =>
      setFilters({
        q: "",
        severity: new Set<Severity>(),
        status: new Set<AStatus>(),
        source: "",
        tag: "",
      }),
  };
}

/* =========================
   Главная страница
   ========================= */

export default function AnomalyTrackerPage() {
  const [prefs, setPrefs] = useState<UserPrefs>(() => loadPrefs());
  useEffect(() => savePrefs(prefs), [prefs]);

  const { state, isOffline, refresh, actions } = useAnomalies({
    urlList: "/api/anomalies",
    urlSSE: "/api/anomalies/stream",
    autoRefreshMs: prefs.autoRefreshMs,
    enableSSE: prefs.enableSSE,
  });

  const { filters, setQuery, toggleSeverity, toggleStatus, setSource, setTag, reset } = useFilters();

  const [sortKey, setSortKey] = useState<SortKey>("occurredAt");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState<number>(1);

  useEffect(() => {
    document.title = "Anomaly Tracker";
  }, []);

  const severities: Severity[] = ["low", "medium", "high", "critical"];
  const statuses: AStatus[] = ["open", "acknowledged", "closed"];

  const dataFiltered = useMemo(() => {
    if (state.kind !== "ok") return [];
    let xs = state.data;

    // текстовый поиск по нескольким полям
    const q = filters.q.trim().toLowerCase();
    if (q) {
      xs = xs.filter(
        (a) =>
          a.id.toLowerCase().includes(q) ||
          a.source.toLowerCase().includes(q) ||
          a.metric.toLowerCase().includes(q) ||
          a.tags.some((t) => t.toLowerCase().includes(q)),
      );
    }

    if (filters.severity.size > 0) {
      xs = xs.filter((a) => filters.severity.has(a.severity));
    }

    if (filters.status.size > 0) {
      xs = xs.filter((a) => filters.status.has(a.status));
    }

    if (filters.source) {
      xs = xs.filter((a) => a.source === filters.source);
    }

    if (filters.tag) {
      const t = filters.tag.toLowerCase();
      xs = xs.filter((a) => a.tags.some((x) => x.toLowerCase().includes(t)));
    }

    // сортировка
    xs = [...xs].sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      switch (sortKey) {
        case "occurredAt":
          return dir * a.occurredAt.localeCompare(b.occurredAt);
        case "severity":
          const rank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
          return dir * (rank[a.severity] - rank[b.severity]);
        case "zScore":
          return dir * (a.zScore - b.zScore);
        case "value":
          return dir * (a.value - b.value);
        case "source":
          return dir * a.source.localeCompare(b.source);
        case "metric":
          return dir * a.metric.localeCompare(b.metric);
        case "status":
          const sRank: Record<AStatus, number> = { open: 0, acknowledged: 1, closed: 2 };
          return dir * (sRank[a.status] - sRank[b.status]);
      }
    });

    return xs;
  }, [state, filters, sortKey, sortDir]);

  // пагинация
  const total = dataFiltered.length;
  const totalPages = Math.max(1, Math.ceil(total / prefs.pageSize));
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const pageSlice = useMemo(() => {
    const start = (page - 1) * prefs.pageSize;
    return dataFiltered.slice(start, start + prefs.pageSize);
  }, [dataFiltered, page, prefs.pageSize]);

  // собрать список доступных sources для дропа
  const allSources = useMemo(() => {
    if (state.kind !== "ok") return [];
    return Array.from(new Set(state.data.map((x) => x.source))).sort();
  }, [state]);

  // экспорт CSV текущей выборки
  const exportCSV = useCallback(() => {
    const header = [
      "id",
      "occurredAt",
      "source",
      "metric",
      "value",
      "baseline",
      "zScore",
      "severity",
      "status",
      "tags",
    ].join(",");
    const lines = dataFiltered.map((a) =>
      [
        a.id,
        a.occurredAt,
        a.source,
        a.metric,
        a.value,
        a.baseline,
        a.zScore,
        a.severity,
        a.status,
        a.tags.join("|"),
      ]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(","),
    );
    downloadBlob(`anomalies_${new Date().toISOString()}.csv`, [header, ...lines].join("\n"));
  }, [dataFiltered]);

  const sortToggler = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  const stale = state.kind === "ok" ? Date.now() - state.updatedAt > Math.max(5000, prefs.autoRefreshMs) : false;

  return (
    <main className="mx-auto max-w-7xl px-4 py-6 md:py-8">
      <header className="mb-6 md:mb-8 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl md:text-3xl font-bold text-zinc-900 dark:text-zinc-100">Anomaly Tracker</h1>
          {isOffline && <Badge tone="warn">Offline</Badge>}
          {stale && <Badge tone="info">Updating…</Badge>}
          {state.kind === "error" && <Badge tone="danger">Error</Badge>}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-300 dark:border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-50 dark:hover:bg-zinc-800"
            aria-label="Refresh anomalies"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M17.65 6.35A7.95 7.95 0 0 0 12 4a8 8 0 1 0 8 8h-2a6 6 0 1 1-6-6c1.66 0 3.14.67 4.22 1.76L13 11h7V4z"/></svg>
            Refresh
          </button>

          <button
            type="button"
            onClick={exportCSV}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-300 dark:border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-50 dark:hover:bg-zinc-800"
            aria-label="Export CSV"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M5 20h14v-2H5v2zM5 4v6h4v4h6V10h4V4H5z"/></svg>
            Export CSV
          </button>

          <div className="flex items-center gap-2">
            <label htmlFor="sse" className="text-sm text-zinc-600 dark:text-zinc-300 select-none">SSE</label>
            <input
              id="sse"
              type="checkbox"
              className="h-4 w-4 accent-zinc-900"
              checked={prefs.enableSSE}
              onChange={(e) => setPrefs((p) => ({ ...p, enableSSE: e.target.checked }))}
              aria-label="Enable SSE"
            />
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="series" className="text-sm text-zinc-600 dark:text-zinc-300 select-none">Series</label>
            <input
              id="series"
              type="checkbox"
              className="h-4 w-4 accent-zinc-900"
              checked={prefs.showSeries}
              onChange={(e) => setPrefs((p) => ({ ...p, showSeries: e.target.checked }))}
              aria-label="Toggle inline series"
            />
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="interval" className="text-sm text-zinc-600 dark:text-zinc-300 select-none">Auto</label>
            <select
              id="interval"
              className="rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1 text-sm"
              value={String(prefs.autoRefreshMs)}
              onChange={(e) => setPrefs((p) => ({ ...p, autoRefreshMs: Number(e.target.value) }))}
              aria-label="Auto refresh interval"
            >
              <option value="0">Off</option>
              <option value="5000">5s</option>
              <option value="10000">10s</option>
              <option value="20000">20s</option>
              <option value="60000">60s</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="pagesize" className="text-sm text-zinc-600 dark:text-zinc-300 select-none">Page</label>
            <select
              id="pagesize"
              className="rounded-lg border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1 text-sm"
              value={String(prefs.pageSize)}
              onChange={(e) => setPrefs((p) => ({ ...p, pageSize: Number(e.target.value) }))}
              aria-label="Page size"
            >
              <option value="10">10</option>
              <option value="20">20</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>
        </div>
      </header>

      {/* Панель фильтров */}
      <SectionCard
        title="Filters"
        right={
          <button
            type="button"
            onClick={reset}
            className="text-sm text-zinc-600 dark:text-zinc-300 underline underline-offset-2"
            aria-label="Reset filters"
          >
            Reset
          </button>
        }
      >
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-4">
            <label className="block text-xs text-zinc-500 dark:text-zinc-400 mb-1">Search</label>
            <input
              type="text"
              placeholder="id, source, metric, tag…"
              value={filters.q}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-xl border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
              aria-label="Search anomalies"
            />
          </div>

          <div className="md:col-span-4">
            <label className="block text-xs text-zinc-500 dark:text-zinc-400 mb-1">Source</label>
            <select
              value={filters.source}
              onChange={(e) => {
                setSource(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-xl border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
              aria-label="Filter by source"
            >
              <option value="">All</option>
              {allSources.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-4">
            <label className="block text-xs text-zinc-500 dark:text-zinc-400 mb-1">Tag contains</label>
            <input
              type="text"
              placeholder="tag…"
              value={filters.tag}
              onChange={(e) => {
                setTag(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-xl border border-zinc-300 dark:border-zinc-700 bg-transparent px-3 py-2 text-sm"
              aria-label="Filter by tag"
            />
          </div>

          <div className="md:col-span-6">
            <div className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Severity</div>
            <div className="flex flex-wrap gap-2">
              {severities.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => {
                    toggleSeverity(s);
                    setPage(1);
                  }}
                  className={classNames(
                    "px-2 py-1 rounded-md border text-xs",
                    filters.severity.has(s)
                      ? severityTone(s)
                      : "border-zinc-300 dark:border-zinc-700 text-zinc-700 dark:text-zinc-300",
                  )}
                  aria-pressed={filters.severity.has(s)}
                  aria-label={`Toggle severity ${s}`}
                >
                  {s.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div className="md:col-span-6">
            <div className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Status</div>
            <div className="flex flex-wrap gap-2">
              {statuses.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => {
                    toggleStatus(s);
                    setPage(1);
                  }}
                  className={classNames(
                    "px-2 py-1 rounded-md border text-xs",
                    filters.status.has(s)
                      ? statusTone(s)
                      : "border-zinc-300 dark:border-zinc-700 text-zinc-700 dark:text-zinc-300",
                  )}
                  aria-pressed={filters.status.has(s)}
                  aria-label={`Toggle status ${s}`}
                >
                  {s.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        </div>
      </SectionCard>

      {/* Таблица аномалий */}
      <SectionCard title="Anomalies">
        {/* заголовки */}
        <div className="grid grid-cols-12 gap-3 px-3 py-2 text-xs font-semibold text-zinc-600 dark:text-zinc-300">
          <button className="text-left col-span-2" onClick={() => sortToggler("occurredAt")} aria-label="Sort by time">
            Time {sortKey === "occurredAt" ? (sortDir === "asc" ? "↑" : "↓") : ""}
          </button>
          <button className="text-left col-span-2" onClick={() => sortToggler("source")} aria-label="Sort by source">
            Source {sortKey === "source" ? (sortDir === "asc" ? "↑" : "↓") : ""}
          </button>
          <button className="text-left col-span-2" onClick={() => sortToggler("metric")} aria-label="Sort by metric">
            Metric {sortKey === "metric" ? (sortDir === "asc" ? "↑" : "↓") : ""}
          </button>
          <button className="text-left col-span-1" onClick={() => sortToggler("value")} aria-label="Sort by value">
            Value {sortKey === "value" ? (sortDir === "asc" ? "↑" : "↓") : ""}
          </button>
          <button className="text-left col-span-1" onClick={() => sortToggler("zScore")} aria-label="Sort by z-score">
            z {sortKey === "zScore" ? (sortDir === "asc" ? "↑" : "↓") : ""}
          </button>
          <button className="text-left col-span-2" onClick={() => sortToggler("severity")} aria-label="Sort by severity">
            Severity {sortKey === "severity" ? (sortDir === "asc" ? "↑" : "↓") : ""}
          </button>
          <button className="text-left col-span-2" onClick={() => sortToggler("status")} aria-label="Sort by status">
            Status {sortKey === "status" ? (sortDir === "asc" ? "↑" : "↓") : ""}
          </button>
        </div>

        {/* контент */}
        {state.kind === "loading" && (
          <div role="status" aria-live="polite">
            {[...Array(8)].map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {state.kind === "error" && (
          <div className="p-4 text-sm text-red-600 dark:text-red-400" role="alert">
            Failed to load anomalies: {state.error}. Please retry.
          </div>
        )}

        {state.kind === "ok" && total === 0 && (
          <div className="p-6 text-sm text-zinc-600 dark:text-zinc-300">No anomalies match current filters.</div>
        )}

        {state.kind === "ok" && total > 0 && (
          <div role="table" aria-rowcount={pageSlice.length} className="divide-y divide-zinc-200 dark:divide-zinc-800">
            {pageSlice.map((a) => (
              <div
                key={a.id}
                role="row"
                className="grid grid-cols-12 gap-3 p-3 hover:bg-zinc-50 dark:hover:bg-zinc-800/40"
              >
                <div className="col-span-2">
                  <div className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{fmtDateTime(a.occurredAt)}</div>
                  <div className="text-xs text-zinc-500 dark:text-zinc-400 truncate" title={a.id}>
                    {a.id}
                  </div>
                </div>

                <div className="col-span-2">
                  <div className="text-sm text-zinc-900 dark:text-zinc-100">{a.source}</div>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {a.tags.slice(0, 3).map((t) => (
                      <Badge key={t} tone="muted">{t}</Badge>
                    ))}
                    {a.tags.length > 3 && <span className="text-xs text-zinc-500">+{a.tags.length - 3}</span>}
                  </div>
                </div>

                <div className="col-span-2">
                  <div className="text-sm text-zinc-900 dark:text-zinc-100">{a.metric}</div>
                  {prefs.showSeries && (
                    <div className="mt-1 text-zinc-500 dark:text-zinc-400">
                      <Sparkline series={a.series} />
                    </div>
                  )}
                </div>

                <div className="col-span-1">
                  <div className="text-sm font-semibold">{a.value}</div>
                  <div className="text-xs text-zinc-500">base {a.baseline}</div>
                </div>

                <div className="col-span-1">
                  <div className="text-sm">{a.zScore.toFixed(2)}</div>
                  <div className="text-xs text-zinc-500">z-score</div>
                </div>

                <div className="col-span-2">
                  <span className={classNames("inline-flex px-2 py-0.5 rounded-md text-xs border", severityTone(a.severity))}>
                    {a.severity.toUpperCase()}
                  </span>
                </div>

                <div className="col-span-2 flex items-center gap-2">
                  <span className={classNames("inline-flex px-2 py-0.5 rounded-md text-xs border", statusTone(a.status))}>
                    {a.status.toUpperCase()}
                  </span>

                  <div className="flex items-center gap-2 ml-auto">
                    {a.status === "open" && (
                      <button
                        type="button"
                        onClick={() => actions.ack(a.id)}
                        className="text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 px-2 py-1 hover:bg-zinc-50 dark:hover:bg-zinc-800"
                        aria-label={`Acknowledge ${a.id}`}
                      >
                        Ack
                      </button>
                    )}
                    {a.status !== "closed" && (
                      <button
                        type="button"
                        onClick={() => actions.close(a.id)}
                        className="text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 px-2 py-1 hover:bg-zinc-50 dark:hover:bg-zinc-800"
                        aria-label={`Close ${a.id}`}
                      >
                        Close
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* пагинация */}
        {state.kind === "ok" && total > 0 && (
          <div className="mt-4 flex items-center justify-between">
            <div className="text-xs text-zinc-600 dark:text-zinc-300">
              Showing {(page - 1) * prefs.pageSize + 1}–{Math.min(page * prefs.pageSize, total)} of {total}
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-2 py-1 text-sm disabled:opacity-50"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                aria-label="Previous page"
              >
                Prev
              </button>
              <div className="text-sm">{page} / {totalPages}</div>
              <button
                type="button"
                className="rounded-lg border border-zinc-300 dark:border-zinc-700 px-2 py-1 text-sm disabled:opacity-50"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                aria-label="Next page"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </SectionCard>
    </main>
  );
}
