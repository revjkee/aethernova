import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  startTransition,
} from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";

/**
 * Типы домена
 */
export type AgentStatus = "online" | "degraded" | "offline" | "starting" | "unknown";

export interface AgentItem {
  id: string;
  name: string;
  kind: string;               // тип/роль агента (например, "planner", "executor")
  status: AgentStatus;
  version?: string;
  uptimeSec?: number;
  cpuLoad?: number;           // 0..100
  memUsageMb?: number;
  tags?: string[];
  lastSeenAt?: string;        // ISO
}

export interface AgentsResponse {
  items: AgentItem[];
  page: number;               // 1-based
  pageSize: number;
  total: number;
}

/**
 * Утилиты
 */
const clamp = (n: number, min: number, max: number) => Math.max(min, Math.min(max, n));

const formatDuration = (sec?: number) => {
  if (!sec && sec !== 0) return "—";
  const s = Math.floor(sec % 60);
  const m = Math.floor((sec / 60) % 60);
  const h = Math.floor(sec / 3600);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
};

const toPercent = (n?: number) => (typeof n === "number" ? `${clamp(n, 0, 100).toFixed(0)}%` : "—");

/**
 * Конфигурация таблицы и параметры запроса
 */
type SortKey = "name" | "status" | "uptimeSec" | "cpuLoad" | "memUsageMb" | "lastSeenAt";
type SortDir = "asc" | "desc";

interface QueryParams {
  q: string;
  status: AgentStatus | "all";
  kind: string | "all";
  page: number;       // 1-based
  pageSize: number;   // 10/20/50/100
  sortKey: SortKey;
  sortDir: SortDir;
}

/**
 * Значения по умолчанию
 */
const DEFAULT_PARAMS: QueryParams = {
  q: "",
  status: "all",
  kind: "all",
  page: 1,
  pageSize: 20,
  sortKey: "name",
  sortDir: "asc",
};

/**
 * Декодирование/кодирование URL параметров
 */
function useQueryState() {
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const loc = useLocation();

  const value: QueryParams = useMemo(() => {
    const n: QueryParams = { ...DEFAULT_PARAMS };
    n.q = sp.get("q") ?? DEFAULT_PARAMS.q;
    n.status = (sp.get("status") as QueryParams["status"]) ?? DEFAULT_PARAMS.status;
    n.kind = (sp.get("kind") as QueryParams["kind"]) ?? DEFAULT_PARAMS.kind;
    n.page = Number(sp.get("page") ?? DEFAULT_PARAMS.page);
    n.pageSize = Number(sp.get("pageSize") ?? DEFAULT_PARAMS.pageSize);
    n.sortKey = (sp.get("sortKey") as SortKey) ?? DEFAULT_PARAMS.sortKey;
    n.sortDir = (sp.get("sortDir") as SortDir) ?? DEFAULT_PARAMS.sortDir;

    if (!Number.isFinite(n.page) || n.page < 1) n.page = DEFAULT_PARAMS.page;
    if (![10, 20, 50, 100].includes(n.pageSize)) n.pageSize = DEFAULT_PARAMS.pageSize;
    if (!["asc", "desc"].includes(n.sortDir)) n.sortDir = DEFAULT_PARAMS.sortDir;
    return n;
  }, [sp]);

  const setValue = useCallback(
    (patch: Partial<QueryParams>, replace = false) => {
      const next = { ...value, ...patch };
      const params = new URLSearchParams();
      if (next.q) params.set("q", next.q);
      if (next.status !== "all") params.set("status", next.status);
      if (next.kind !== "all") params.set("kind", next.kind);
      params.set("page", String(next.page));
      params.set("pageSize", String(next.pageSize));
      params.set("sortKey", next.sortKey);
      params.set("sortDir", next.sortDir);
      const url = `${loc.pathname}?${params.toString()}`;
      startTransition(() => {
        replace ? nav(url, { replace: true }) : nav(url);
      });
    },
    [value, nav, loc.pathname]
  );

  return [value, setValue] as const;
}

/**
 * API-клиент с отменой запросов и повторной попыткой на фокус/визибилити
 * Предполагается эндпоинт: GET /api/agents?q&status&kind&page&pageSize&sortKey&sortDir
 */
async function fetchAgents(signal: AbortSignal, qp: QueryParams): Promise<AgentsResponse> {
  const qs = new URLSearchParams({
    q: qp.q,
    status: qp.status,
    kind: qp.kind,
    page: String(qp.page),
    pageSize: String(qp.pageSize),
    sortKey: qp.sortKey,
    sortDir: qp.sortDir,
  });
  const res = await fetch(`/api/agents?${qs.toString()}`, { signal, headers: { Accept: "application/json" } });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Failed to load agents (${res.status}): ${text || res.statusText}`);
  }
  return res.json();
}

/**
 * Хук данных: загрузка, отмена, refetch по фокусу/визибилити
 */
function useAgentsData(qp: QueryParams) {
  const [data, setData] = useState<AgentsResponse | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const ctrlRef = useRef<AbortController | null>(null);
  const qpRef = useRef(qp);
  qpRef.current = qp;

  const load = useCallback(async () => {
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    setLoading(true);
    setError(null);
    try {
      const res = await fetchAgents(ctrl.signal, qpRef.current);
      setData(res);
    } catch (e: any) {
      if (e?.name !== "AbortError") {
        setError(e instanceof Error ? e : new Error(String(e)));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qp.q, qp.status, qp.kind, qp.page, qp.pageSize, qp.sortKey, qp.sortDir]);

  // Refetch on window focus / visibility
  useEffect(() => {
    const onFocus = () => {
      if (document.visibilityState === "visible") {
        load();
      }
    };
    const onVis = () => {
      if (document.visibilityState === "visible") {
        load();
      }
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVis);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [load]);

  useEffect(() => () => ctrlRef.current?.abort(), []);

  return { data, error, loading, reload: load };
}

/**
 * Компоненты UI
 */
function StatusBadge({ status }: { status: AgentStatus }) {
  const map = {
    online: "bg-green-100 text-green-800 border-green-300",
    degraded: "bg-yellow-100 text-yellow-800 border-yellow-300",
    offline: "bg-red-100 text-red-800 border-red-300",
    starting: "bg-blue-100 text-blue-800 border-blue-300",
    unknown: "bg-gray-100 text-gray-800 border-gray-300",
  } as const;
  const cls = map[status] ?? map.unknown;
  return (
    <span
      role="status"
      aria-label={`status: ${status}`}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${cls}`}
    >
      <span className="h-2 w-2 rounded-full bg-current opacity-70" />
      {status}
    </span>
  );
}

function SkeletonRow() {
  return (
    <tr className="animate-pulse">
      <td className="py-3 px-3"><div className="h-4 w-40 bg-gray-200 rounded" /></td>
      <td className="py-3 px-3"><div className="h-4 w-24 bg-gray-200 rounded" /></td>
      <td className="py-3 px-3"><div className="h-4 w-20 bg-gray-200 rounded" /></td>
      <td className="py-3 px-3"><div className="h-4 w-16 bg-gray-200 rounded" /></td>
      <td className="py-3 px-3"><div className="h-4 w-16 bg-gray-200 rounded" /></td>
      <td className="py-3 px-3 text-right"><div className="h-8 w-24 bg-gray-200 rounded" /></td>
    </tr>
  );
}

function Toolbar({
  qp,
  onChange,
}: {
  qp: QueryParams;
  onChange: (patch: Partial<QueryParams>) => void;
}) {
  const [search, setSearch] = useState(qp.q);
  // debounce
  useEffect(() => setSearch(qp.q), [qp.q]);
  useEffect(() => {
    const id = window.setTimeout(() => {
      if (search !== qp.q) onChange({ q: search, page: 1 });
    }, 250);
    return () => window.clearTimeout(id);
  }, [search]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="flex flex-wrap items-center gap-3">
      <input
        aria-label="Search agents"
        className="w-64 rounded border px-3 py-2 text-sm"
        placeholder="Search by name, tag, role"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />
      <select
        aria-label="Filter by status"
        className="rounded border px-2 py-2 text-sm"
        value={qp.status}
        onChange={(e) => onChange({ status: e.target.value as QueryParams["status"], page: 1 })}
      >
        <option value="all">All statuses</option>
        <option value="online">online</option>
        <option value="degraded">degraded</option>
        <option value="starting">starting</option>
        <option value="offline">offline</option>
        <option value="unknown">unknown</option>
      </select>
      <select
        aria-label="Filter by kind"
        className="rounded border px-2 py-2 text-sm"
        value={qp.kind}
        onChange={(e) => onChange({ kind: e.target.value as QueryParams["kind"], page: 1 })}
      >
        <option value="all">All kinds</option>
        <option value="planner">planner</option>
        <option value="executor">executor</option>
        <option value="critic">critic</option>
        <option value="memory">memory</option>
      </select>
      <div className="ml-auto flex items-center gap-2">
        <select
          aria-label="Rows per page"
          className="rounded border px-2 py-2 text-sm"
          value={qp.pageSize}
          onChange={(e) => onChange({ pageSize: Number(e.target.value), page: 1 })}
        >
          {[10, 20, 50, 100].map((n) => (
            <option key={n} value={n}>{n} / page</option>
          ))}
        </select>
      </div>
    </div>
  );
}

function SortHeader({
  label,
  col,
  qp,
  onChange,
  className,
}: {
  label: string;
  col: SortKey;
  qp: QueryParams;
  onChange: (patch: Partial<QueryParams>) => void;
  className?: string;
}) {
  const active = qp.sortKey === col;
  const dir = active ? qp.sortDir : undefined;
  const nextDir: SortDir = active ? (qp.sortDir === "asc" ? "desc" : "asc") : "asc";
  return (
    <button
      type="button"
      aria-label={`Sort by ${label}`}
      className={`inline-flex items-center gap-1 text-left ${className ?? ""}`}
      onClick={() => onChange({ sortKey: col, sortDir: nextDir })}
    >
      <span>{label}</span>
      <span className="text-xs opacity-60">{active ? (dir === "asc" ? "▲" : "▼") : ""}</span>
    </button>
  );
}

function Pagination({
  page,
  pageSize,
  total,
  onChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onChange: (patch: Partial<QueryParams>) => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const prev = () => onChange({ page: clamp(page - 1, 1, totalPages) });
  const next = () => onChange({ page: clamp(page + 1, 1, totalPages) });
  return (
    <div className="flex items-center justify-between">
      <div className="text-sm text-gray-600">
        Page {page} of {totalPages} • {total} items
      </div>
      <div className="flex items-center gap-2">
        <button
          aria-label="Previous page"
          className="rounded border px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={prev}
          disabled={page <= 1}
        >
          Prev
        </button>
        <button
          aria-label="Next page"
          className="rounded border px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={next}
          disabled={page >= totalPages}
        >
          Next
        </button>
      </div>
    </div>
  );
}

/**
 * Основная страница
 */
export default function AgentsPage() {
  const [qp, setQp] = useQueryState();
  const { data, error, loading, reload } = useAgentsData(qp);

  const onPatch = useCallback((patch: Partial<QueryParams>) => {
    setQp(patch);
  }, [setQp]);

  const rows = data?.items ?? [];

  return (
    <section className="flex min-h-[60vh] flex-col gap-4 p-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Agents</h1>
          <p className="text-sm text-gray-600">Operational view of AI agents</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            aria-label="Refresh"
            className="rounded border px-3 py-1.5 text-sm"
            onClick={() => reload()}
            disabled={loading}
          >
            Refresh
          </button>
        </div>
      </header>

      <Toolbar qp={qp} onChange={onPatch} />

      <div className="overflow-x-auto rounded border">
        <table className="min-w-full border-separate border-spacing-0 text-sm">
          <thead className="bg-gray-50 text-gray-700">
            <tr>
              <th className="sticky top-0 z-10 border-b px-3 py-2 text-left">
                <SortHeader label="Name" col="name" qp={qp} onChange={onPatch} />
              </th>
              <th className="sticky top-0 z-10 border-b px-3 py-2 text-left">
                Kind
              </th>
              <th className="sticky top-0 z-10 border-b px-3 py-2 text-left">
                <SortHeader label="Status" col="status" qp={qp} onChange={onPatch} />
              </th>
              <th className="sticky top-0 z-10 border-b px-3 py-2 text-left">
                <SortHeader label="Uptime" col="uptimeSec" qp={qp} onChange={onPatch} />
              </th>
              <th className="sticky top-0 z-10 border-b px-3 py-2 text-left">
                <SortHeader label="CPU" col="cpuLoad" qp={qp} onChange={onPatch} />
              </th>
              <th className="sticky top-0 z-10 border-b px-3 py-2 text-left">
                <SortHeader label="Memory" col="memUsageMb" qp={qp} onChange={onPatch} />
              </th>
              <th className="sticky top-0 z-10 border-b px-3 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && !data && Array.from({ length: qp.pageSize }).map((_, i) => <SkeletonRow key={`sk-${i}`} />)}

            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-gray-600">
                  No agents found
                </td>
              </tr>
            )}

            {rows.map((a) => (
              <tr key={a.id} className="even:bg-gray-50/40">
                <td className="px-3 py-3">
                  <div className="flex flex-col">
                    <span className="font-medium">{a.name}</span>
                    <span className="text-xs text-gray-500">
                      v{a.version ?? "—"} • last seen {a.lastSeenAt ? new Date(a.lastSeenAt).toLocaleString() : "—"}
                    </span>
                    {a.tags && a.tags.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {a.tags.map((t) => (
                          <span key={t} className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px] text-gray-700">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </td>
                <td className="px-3 py-3">{a.kind}</td>
                <td className="px-3 py-3"><StatusBadge status={a.status ?? "unknown"} /></td>
                <td className="px-3 py-3">{formatDuration(a.uptimeSec)}</td>
                <td className="px-3 py-3">{toPercent(a.cpuLoad)}</td>
                <td className="px-3 py-3">{typeof a.memUsageMb === "number" ? `${a.memUsageMb.toFixed(0)} MB` : "—"}</td>
                <td className="px-3 py-3 text-right">
                  <div className="inline-flex gap-2">
                    <button
                      className="rounded border px-2 py-1 text-xs"
                      onClick={() => window.dispatchEvent(new CustomEvent("agent:open", { detail: { id: a.id } }))}
                    >
                      Open
                    </button>
                    <button
                      className="rounded border px-2 py-1 text-xs"
                      onClick={() => window.dispatchEvent(new CustomEvent("agent:restart", { detail: { id: a.id } }))}
                      disabled={a.status === "starting"}
                    >
                      Restart
                    </button>
                  </div>
                </td>
              </tr>
            ))}

            {loading && data && rows.length > 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-2 text-center text-gray-500">Updating…</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <footer className="mt-2">
        <Pagination
          page={qp.page}
          pageSize={qp.pageSize}
          total={data?.total ?? 0}
          onChange={onPatch}
        />
      </footer>

      {error && (
        <div
          role="alert"
          className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
        >
          {error.message}
        </div>
      )}
    </section>
  );
}
