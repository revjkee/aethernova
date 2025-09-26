// frontend/src/features/agents/hooks/useAgents.ts
/**
 * Industrial-grade React hook for managing Agents:
 * - Strong TypeScript types
 * - Pagination, filters, sorting
 * - In-memory cache keyed by query + ETag support
 * - Exponential backoff retries (idempotent GET)
 * - Optimistic updates with rollback (POST/PATCH/DELETE)
 * - Safe abort via AbortController and request guards
 * - Narrowed errors with ApiError shape
 * - SSR-safe (guards window/AbortController)
 */

import { useCallback, useEffect, useMemo, useRef, useReducer } from "react";

/* ==============================
   Types
   ============================== */

export type AgentId = string;

export type AgentStatus = "active" | "paused" | "disabled" | "error" | "pending";

export type AgentKind =
  | "planner"
  | "executor"
  | "critic"
  | "governor"
  | "analyst"
  | "retriever"
  | "router"
  | "monitor";

export interface Agent {
  id: AgentId;
  name: string;
  kind: AgentKind;
  status: AgentStatus;
  version: string;
  tags: string[];
  createdAt: string; // ISO-8601
  updatedAt: string; // ISO-8601
  config?: Record<string, unknown>;
  // Optional server-provided ETag/rowVersion for concurrency control
  etag?: string;
}

export type AgentCreateDTO = Omit<Agent, "id" | "createdAt" | "updatedAt" | "etag"> & {
  id?: AgentId;
};

export type AgentUpdateDTO = Partial<
  Omit<Agent, "id" | "createdAt" | "updatedAt" | "etag">
> & {
  id: AgentId;
  // If provided, will be sent as If-Match header
  etag?: string;
};

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export type SortDir = "asc" | "desc";

export interface AgentsQuery {
  page?: number; // 1-based
  pageSize?: number; // default 20
  search?: string;
  status?: AgentStatus[];
  tags?: string[];
  sortBy?: keyof Agent;
  sortDir?: SortDir;
}

export interface ApiError {
  status: number;
  message: string;
  code?: string;
  details?: unknown;
}

type Nullable<T> = T | null;

/* ==============================
   Config
   ============================== */

const DEFAULT_PAGE_SIZE = 20;
const MAX_RETRIES = 3;
const BASE_URL =
  (typeof import.meta !== "undefined" && (import.meta as any).env?.VITE_API_URL) ||
  process.env.VITE_API_URL ||
  "/api";

const AGENTS_ENDPOINT = `${BASE_URL}/agents`;
const TTL_MS = 15_000; // cache TTL for GET list/detail

/* ==============================
   Cache (module-scoped)
   ============================== */

type CacheKey = string;

interface CacheEntry<T> {
  data: T;
  etag?: string;
  ts: number; // timestamp
}

const listCache = new Map<CacheKey, CacheEntry<Paginated<Agent>>>();
const detailCache = new Map<AgentId, CacheEntry<Agent>>();

/* ==============================
   Utils
   ============================== */

function buildQueryString(q: AgentsQuery): string {
  const p = new URLSearchParams();
  if (q.page && q.page > 1) p.set("page", String(q.page));
  p.set("pageSize", String(q.pageSize ?? DEFAULT_PAGE_SIZE));
  if (q.search) p.set("search", q.search);
  if (q.status && q.status.length) q.status.forEach((s) => p.append("status", s));
  if (q.tags && q.tags.length) q.tags.forEach((t) => p.append("tag", t));
  if (q.sortBy) p.set("sortBy", String(q.sortBy));
  if (q.sortDir) p.set("sortDir", q.sortDir);
  const s = p.toString();
  return s ? `?${s}` : "";
}

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

function backoffDelay(attempt: number): number {
  // 200ms, 600ms, 1400ms (jittered)
  const base = Math.pow(2, attempt) * 100;
  const jitter = Math.floor(Math.random() * 100);
  return base + jitter;
}

function safeParseAgent(input: unknown): input is Agent {
  if (!input || typeof input !== "object") return false;
  const o = input as Agent;
  return (
    typeof o.id === "string" &&
    typeof o.name === "string" &&
    typeof o.kind === "string" &&
    typeof o.status === "string" &&
    typeof o.version === "string" &&
    Array.isArray(o.tags) &&
    typeof o.createdAt === "string" &&
    typeof o.updatedAt === "string"
  );
}

function safeParsePaginatedAgents(input: unknown): input is Paginated<Agent> {
  if (!input || typeof input !== "object") return false;
  const o = input as Paginated<Agent>;
  return (
    Array.isArray(o.items) &&
    o.items.every(safeParseAgent) &&
    typeof o.total === "number" &&
    typeof o.page === "number" &&
    typeof o.pageSize === "number"
  );
}

function toApiError(e: unknown, fallbackMessage = "Request failed"): ApiError {
  if (typeof e === "object" && e && "status" in e && "message" in e) {
    const er = e as ApiError;
    return { status: er.status ?? 0, message: String(er.message || fallbackMessage), code: (er as any).code, details: (er as any).details };
  }
  if (e instanceof Error) {
    return { status: 0, message: e.message };
  }
  return { status: 0, message: fallbackMessage };
}

function makeCacheKey(q: AgentsQuery): CacheKey {
  // Stable key independent of property order
  const norm: Required<AgentsQuery> = {
    page: q.page ?? 1,
    pageSize: q.pageSize ?? DEFAULT_PAGE_SIZE,
    search: q.search ?? "",
    status: q.status ?? [],
    tags: q.tags ?? [],
    sortBy: (q.sortBy as keyof Agent) ?? ("updatedAt" as keyof Agent),
    sortDir: q.sortDir ?? "desc",
  };
  return JSON.stringify(norm);
}

/* ==============================
   Networking
   ============================== */

interface RequestOptions {
  signal?: AbortSignal;
  etag?: string; // If-None-Match (GET) or If-Match (mutations)
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
}

async function httpJSON<T>(url: string, options: RequestOptions = {}, retryable = false): Promise<{ data: T; etag?: string }> {
  const { signal, etag, method = "GET", body, headers = {} } = options;

  const h: Record<string, string> = {
    "Accept": "application/json",
    ...(body ? { "Content-Type": "application/json" } : {}),
    ...headers,
  };

  // For GET we use If-None-Match; for mutations we use If-Match (if provided)
  if (method === "GET" && etag) h["If-None-Match"] = etag;
  if (method !== "GET" && etag) h["If-Match"] = etag;

  let attempt = 0;
  // Only GET is retried; others fail fast to avoid duplicating side effects
  const maxAttempts = retryable ? MAX_RETRIES : 1;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const res = await fetch(url, {
      method,
      headers: h,
      body: body ? JSON.stringify(body) : undefined,
      signal,
      credentials: "include",
    }).catch((err) => {
      // Network errors
      throw toApiError(err);
    });

    // Not Modified: return a typed signal to caller (no new data)
    const respEtag = res.headers.get("ETag") || undefined;
    if (method === "GET" && res.status === 304) {
      // @ts-expect-error Using undefined to signal cache use
      return { data: undefined as T, etag: respEtag };
    }

    if (res.ok) {
      if (res.status === 204) {
        // @ts-expect-error empty body
        return { data: undefined as T, etag: respEtag };
      }
      const json = await res.json().catch(() => {
        throw <ApiError>{ status: res.status, message: "Invalid JSON response" };
      });
      return { data: json as T, etag: respEtag };
    }

    // Retry only for 5xx on GET
    if (retryable && res.status >= 500 && res.status < 600 && attempt < maxAttempts - 1) {
      attempt += 1;
      await sleep(backoffDelay(attempt));
      continue;
    }

    // Surface server error payload if present
    let msg = `${res.status} ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson?.message) msg = errJson.message;
      throw <ApiError>{ status: res.status, message: msg, code: errJson?.code, details: errJson?.details };
    } catch {
      throw <ApiError>{ status: res.status, message: msg };
    }
  }
}

/* ==============================
   Reducer & State
   ============================== */

interface State {
  loading: boolean;
  error: Nullable<ApiError>;
  page: number;
  pageSize: number;
  data: Agent[];
  total: number;
  isStale: boolean;
  lastUpdated: Nullable<number>;
}

type Action =
  | { type: "REQUEST"; page: number; pageSize: number }
  | { type: "SUCCESS"; items: Agent[]; total: number; isStale: boolean; ts: number }
  | { type: "FAIL"; error: ApiError }
  | { type: "LOCAL_MUTATION"; items: Agent[] } // optimistic update
  | { type: "ROLLBACK"; items: Agent[] };

const initialState: State = {
  loading: false,
  error: null,
  page: 1,
  pageSize: DEFAULT_PAGE_SIZE,
  data: [],
  total: 0,
  isStale: false,
  lastUpdated: null,
};

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "REQUEST":
      return { ...state, loading: true, error: null, page: action.page, pageSize: action.pageSize };
    case "SUCCESS":
      return {
        ...state,
        loading: false,
        error: null,
        data: action.items,
        total: action.total,
        isStale: action.isStale,
        lastUpdated: action.ts,
      };
    case "FAIL":
      return { ...state, loading: false, error: action.error };
    case "LOCAL_MUTATION":
      return { ...state, data: action.items };
    case "ROLLBACK":
      return { ...state, data: action.items };
    default:
      return state;
  }
}

/* ==============================
   Hook
   ============================== */

export interface UseAgentsOptions extends AgentsQuery {
  enabled?: boolean; // default true
  ttlMs?: number; // override cache TTL
}

export interface UseAgentsResult {
  loading: boolean;
  error: Nullable<ApiError>;
  agents: Agent[];
  total: number;
  page: number;
  pageSize: number;
  isStale: boolean;
  lastUpdated: Nullable<number>;
  refetch: () => Promise<void>;
  // Mutations (all return latest server state)
  createAgent: (dto: AgentCreateDTO) => Promise<Agent>;
  updateAgent: (dto: AgentUpdateDTO) => Promise<Agent>;
  deleteAgent: (id: AgentId, etag?: string) => Promise<void>;
  setStatus: (id: AgentId, status: AgentStatus, etag?: string) => Promise<Agent>;
  // Bulk helpers
  bulkUpsert: (items: AgentCreateDTO[]) => Promise<Agent[]>;
  // Cache controls
  invalidate: () => void;
  getByIdCached: (id: AgentId) => Agent | undefined;
}

export function useAgents(opts: UseAgentsOptions = {}): UseAgentsResult {
  const {
    page = 1,
    pageSize = DEFAULT_PAGE_SIZE,
    search,
    status,
    tags,
    sortBy = "updatedAt",
    sortDir = "desc",
    enabled = true,
    ttlMs = TTL_MS,
  } = opts;

  const [state, dispatch] = useReducer(reducer, { ...initialState, page, pageSize });

  const query = useMemo<AgentsQuery>(
    () => ({ page, pageSize, search, status, tags, sortBy, sortDir }),
    [page, pageSize, search, status, tags, sortBy, sortDir]
  );

  const cacheKey = useMemo(() => makeCacheKey(query), [query]);

  const etagRef = useRef<string | undefined>(listCache.get(cacheKey)?.etag);
  const abortRef = useRef<AbortController | null>(null);
  const reqGuard = useRef<number>(0); // incrementing request id to avoid races

  const getCachedList = useCallback((): Paginated<Agent> | undefined => {
    const c = listCache.get(cacheKey);
    if (!c) return undefined;
    const fresh = Date.now() - c.ts < ttlMs;
    if (fresh && safeParsePaginatedAgents(c.data)) return c.data;
    return undefined;
  }, [cacheKey, ttlMs]);

  const getByIdCached = useCallback((id: AgentId): Agent | undefined => {
    const c = detailCache.get(id);
    if (!c) return undefined;
    if (Date.now() - c.ts < ttlMs && safeParseAgent(c.data)) return c.data;
    return undefined;
  }, [ttlMs]);

  const load = useCallback(async () => {
    if (!enabled) return;
    // Cancel previous
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    const requestId = ++reqGuard.current;

    dispatch({ type: "REQUEST", page, pageSize });

    // Serve from cache immediately if fresh
    const cached = getCachedList();
    if (cached) {
      dispatch({
        type: "SUCCESS",
        items: cached.items,
        total: cached.total,
        isStale: false,
        ts: listCache.get(cacheKey)!.ts,
      });
    }

    try {
      const url = `${AGENTS_ENDPOINT}${buildQueryString(query)}`;

      const { data, etag } = await httpJSON<Paginated<Agent>>(
        url,
        { signal: ac.signal, etag: etagRef.current, method: "GET" },
        true // retryable GET
      );

      // If server returned 304 -> use existing cache and mark as fresh
      if (data === (undefined as unknown)) {
        const c = listCache.get(cacheKey);
        if (c && requestId === reqGuard.current) {
          dispatch({ type: "SUCCESS", items: c.data.items, total: c.data.total, isStale: false, ts: c.ts });
        }
        return;
      }

      if (!safeParsePaginatedAgents(data)) {
        throw <ApiError>{ status: 0, message: "Invalid agents payload" };
      }

      // Update caches
      listCache.set(cacheKey, { data, etag, ts: Date.now() });
      data.items.forEach((a) => detailCache.set(a.id, { data: a, etag: a.etag, ts: Date.now() }));
      etagRef.current = etag;

      if (requestId === reqGuard.current) {
        dispatch({ type: "SUCCESS", items: data.items, total: data.total, isStale: false, ts: Date.now() });
      }
    } catch (e) {
      const err = toApiError(e);
      // Mark stale when we had cached data but failed refresh
      const hasCached = !!cached;
      if (hasCached) {
        dispatch({ type: "SUCCESS", items: cached!.items, total: cached!.total, isStale: true, ts: listCache.get(cacheKey)!.ts });
      } else {
        dispatch({ type: "FAIL", error: err });
      }
    }
  }, [enabled, page, pageSize, query, cacheKey, getCachedList]);

  // Initial and param-change effect
  useEffect(() => {
    let mounted = true;
    if (mounted) void load();
    return () => {
      mounted = false;
      abortRef.current?.abort();
    };
  }, [load]);

  const refetch = useCallback(async () => {
    // Clear ETag to force full fetch
    etagRef.current = undefined;
    await load();
  }, [load]);

  const invalidate = useCallback(() => {
    listCache.delete(cacheKey);
    // Do not clear detail cache globally; keep per-item longevity
  }, [cacheKey]);

  /* ==============================
     Optimistic mutation helpers
     ============================== */

  const optimisticApply = useCallback(
    (apply: (prev: Agent[]) => Agent[]) => {
      const prev = state.data;
      const next = apply(prev);
      dispatch({ type: "LOCAL_MUTATION", items: next });
      return prev; // return snapshot for rollback
    },
    [state.data]
  );

  const rollback = useCallback((snapshot: Agent[]) => {
    dispatch({ type: "ROLLBACK", items: snapshot });
  }, []);

  /* ==============================
     Mutations
     ============================== */

  const createAgent = useCallback(
    async (dto: AgentCreateDTO): Promise<Agent> => {
      const url = `${AGENTS_ENDPOINT}`;
      const snapshot = optimisticApply((prev) => {
        const temp: Agent = {
          id: dto.id ?? `temp-${Math.random().toString(36).slice(2)}`,
          name: dto.name,
          kind: dto.kind,
          status: dto.status ?? "pending",
          version: dto.version ?? "0.0.0",
          tags: dto.tags ?? [],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          config: dto.config ?? {},
          etag: undefined,
        };
        return [temp, ...prev];
      });

      try {
        const { data } = await httpJSON<Agent>(url, { method: "POST", body: dto });
        if (!safeParseAgent(data)) throw <ApiError>{ status: 0, message: "Invalid agent response" };
        // Update caches
        detailCache.set(data.id, { data, etag: data.etag, ts: Date.now() });
        // Replace temp with real
        dispatch({
          type: "LOCAL_MUTATION",
          items: state.data.map((a) => (a.id.startsWith("temp-") ? data : a)),
        });
        // Invalidate list cache snapshot
        invalidate();
        return data;
      } catch (e) {
        rollback(snapshot);
        throw toApiError(e, "Create agent failed");
      }
    },
    [invalidate, optimisticApply, rollback, state.data]
  );

  const updateAgent = useCallback(
    async (dto: AgentUpdateDTO): Promise<Agent> => {
      const url = `${AGENTS_ENDPOINT}/${encodeURIComponent(dto.id)}`;

      // Optimistic local merge
      const snapshot = optimisticApply((prev) =>
        prev.map((a) => (a.id === dto.id ? { ...a, ...dto, updatedAt: new Date().toISOString() } : a))
      );

      try {
        const { data } = await httpJSON<Agent>(
          url,
          { method: "PATCH", body: dto, etag: dto.etag },
          false
        );
        if (!safeParseAgent(data)) throw <ApiError>{ status: 0, message: "Invalid agent response" };
        detailCache.set(data.id, { data, etag: data.etag, ts: Date.now() });
        dispatch({
          type: "LOCAL_MUTATION",
          items: state.data.map((a) => (a.id === data.id ? data : a)),
        });
        invalidate();
        return data;
      } catch (e) {
        rollback(snapshot);
        throw toApiError(e, "Update agent failed");
      }
    },
    [invalidate, optimisticApply, rollback, state.data]
  );

  const deleteAgent = useCallback(
    async (id: AgentId, etag?: string): Promise<void> => {
      const url = `${AGENTS_ENDPOINT}/${encodeURIComponent(id)}`;

      const snapshot = optimisticApply((prev) => prev.filter((a) => a.id !== id));

      try {
        await httpJSON<void>(url, { method: "DELETE", etag }, false);
        detailCache.delete(id);
        invalidate();
      } catch (e) {
        rollback(snapshot);
        throw toApiError(e, "Delete agent failed");
      }
    },
    [invalidate, optimisticApply, rollback]
  );

  const setStatus = useCallback(
    async (id: AgentId, status: AgentStatus, etag?: string): Promise<Agent> => {
      const url = `${AGENTS_ENDPOINT}/${encodeURIComponent(id)}/status`;

      const snapshot = optimisticApply((prev) =>
        prev.map((a) => (a.id === id ? { ...a, status, updatedAt: new Date().toISOString() } : a))
      );

      try {
        const { data } = await httpJSON<Agent>(url, { method: "PATCH", body: { status }, etag }, false);
        if (!safeParseAgent(data)) throw <ApiError>{ status: 0, message: "Invalid agent response" };
        detailCache.set(data.id, { data, etag: data.etag, ts: Date.now() });
        dispatch({
          type: "LOCAL_MUTATION",
          items: state.data.map((a) => (a.id === data.id ? data : a)),
        });
        invalidate();
        return data;
      } catch (e) {
        rollback(snapshot);
        throw toApiError(e, "Set status failed");
      }
    },
    [invalidate, optimisticApply, rollback, state.data]
  );

  const bulkUpsert = useCallback(
    async (items: AgentCreateDTO[]): Promise<Agent[]> => {
      const url = `${AGENTS_ENDPOINT}/bulk`;
      // Optimistic prepend of new/updated entries
      const snapshot = optimisticApply((prev) => {
        const map = new Map(prev.map((a) => [a.id, a]));
        items.forEach((it) => {
          const id = it.id ?? `temp-${Math.random().toString(36).slice(2)}`;
          const existing = map.get(id);
          const up: Agent = existing
            ? { ...existing, ...it, updatedAt: new Date().toISOString() }
            : {
                id,
                name: it.name,
                kind: it.kind,
                status: it.status ?? "pending",
                version: it.version ?? "0.0.0",
                tags: it.tags ?? [],
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                config: it.config ?? {},
              };
          map.set(id, up);
        });
        return Array.from(map.values());
      });

      try {
        const { data } = await httpJSON<Agent[]>(url, { method: "POST", body: { items } }, false);
        if (!Array.isArray(data) || !data.every(safeParseAgent)) {
          throw <ApiError>{ status: 0, message: "Invalid bulk response" };
        }
        // Update caches
        const now = Date.now();
        data.forEach((a) => detailCache.set(a.id, { data: a, etag: a.etag, ts: now }));
        invalidate();
        // Ensure list reflects server items (merge by id)
        const byId = new Map(state.data.map((a) => [a.id, a]));
        data.forEach((a) => byId.set(a.id, a));
        dispatch({ type: "LOCAL_MUTATION", items: Array.from(byId.values()) });
        return data;
      } catch (e) {
        rollback(snapshot);
        throw toApiError(e, "Bulk upsert failed");
      }
    },
    [invalidate, optimisticApply, rollback, state.data]
  );

  return {
    loading: state.loading,
    error: state.error,
    agents: state.data,
    total: state.total,
    page: state.page,
    pageSize: state.pageSize,
    isStale: state.isStale,
    lastUpdated: state.lastUpdated,
    refetch,
    createAgent,
    updateAgent,
    deleteAgent,
    setStatus,
    bulkUpsert,
    invalidate,
    getByIdCached,
  };
}
