// neuroforge-core/sdks/typescript/src/client.ts

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * NeuroForge TypeScript SDK - Industrial Client
 * - Zero-deps, Node 18+ and modern browsers
 * - Timeouts, retries with jitter, rate-limit handling
 * - Simple circuit breaker
 * - AbortController for cancellation
 * - Optional HMAC request signing
 * - Idempotency keys for unsafe methods
 * - Pagination helpers (async iterators)
 * - Streaming (SSE and NDJSON)
 * - Optional in-memory GET cache with TTL
 * - Telemetry hooks and pluggable logger
 */

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface Logger {
  debug(...args: any[]): void;
  info(...args: any[]): void;
  warn(...args: any[]): void;
  error(...args: any[]): void;
}

export interface TelemetryHooks {
  onRequestStart?(ctx: RequestContext): void;
  onRequestFinish?(ctx: RequestContext & { durationMs: number }): void;
  onRetry?(info: RetryInfo): void;
  onCircuitOpen?(info: CircuitInfo): void;
}

export interface RequestContext {
  method: HttpMethod;
  url: string;
  headers: Record<string, string>;
  bodySize?: number;
  requestId?: string;
}

export interface RetryInfo {
  attempt: number;
  maxRetries: number;
  delayMs: number;
  reason: string;
  method: HttpMethod;
  url: string;
  status?: number;
}

export interface CircuitInfo {
  state: "open" | "half_open" | "closed";
  failures: number;
  openedAt?: number;
  cooldownMs: number;
}

export interface CircuitBreakerOptions {
  failureThreshold: number; // consecutive failures before open
  cooldownMs: number;       // how long stay open
  halfOpenMaxRequests: number; // allowed trial requests in half-open
}

export interface RetryPolicy {
  maxRetries: number;
  baseDelayMs: number;
  backoffFactor: number;
  maxDelayMs: number;
  retryOnStatuses: number[];
  retryOnNetworkError: boolean;
}

export interface CacheOptions {
  enabled: boolean;
  defaultTtlMs: number;
  respectETag: boolean;
  maxEntries: number;
}

export interface ClientOptions {
  baseUrl: string;                 // e.g., https://api.neuroforge.local
  apiKey?: string;                 // X-API-Key
  oauthToken?: string;             // Bearer token
  hmacSecret?: string;             // for X-NF-Signature
  userAgent?: string;              // extra UA
  timeoutMs?: number;              // request timeout
  retry?: Partial<RetryPolicy>;
  circuit?: Partial<CircuitBreakerOptions>;
  telemetry?: TelemetryHooks;
  logger?: Logger;
  defaultHeaders?: Record<string, string>;
  cache?: Partial<CacheOptions>;
}

/** Default policies */
const DEFAULT_TIMEOUT_MS = 30_000;

const DEFAULT_RETRY: RetryPolicy = {
  maxRetries: 3,
  baseDelayMs: 250,
  backoffFactor: 2,
  maxDelayMs: 5_000,
  retryOnStatuses: [408, 409, 425, 429, 500, 502, 503, 504],
  retryOnNetworkError: true,
};

const DEFAULT_CIRCUIT: CircuitBreakerOptions = {
  failureThreshold: 5,
  cooldownMs: 15_000,
  halfOpenMaxRequests: 2,
};

const DEFAULT_CACHE: CacheOptions = {
  enabled: false,
  defaultTtlMs: 10_000,
  respectETag: true,
  maxEntries: 1000,
};

function nowMs(): number {
  return Date.now();
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException("Aborted", "AbortError"));
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new DOMException("Aborted", "AbortError"));
      },
      { once: true }
    );
  });
}

function jitter(delay: number): number {
  const r = Math.random() + 0.5; // 0.5..1.5
  return Math.round(delay * r);
}

function encodeQuery(q?: Record<string, unknown>): string {
  if (!q) return "";
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      for (const item of v) usp.append(k, String(item));
    } else {
      usp.append(k, String(v));
    }
  }
  const s = usp.toString();
  return s ? `?${s}` : "";
}

function isJson(contentType?: string | null): boolean {
  if (!contentType) return false;
  return /application\/json|application\/\w+\+json/i.test(contentType);
}

function isNdJson(contentType?: string | null): boolean {
  if (!contentType) return false;
  return /application\/x-ndjson/i.test(contentType);
}

function isSse(contentType?: string | null): boolean {
  if (!contentType) return false;
  return /text\/event-stream/i.test(contentType);
}

/** Error types */
export class ApiError extends Error {
  public readonly status: number;
  public readonly code?: string;
  public readonly requestId?: string;
  public readonly details?: any;
  constructor(message: string, status: number, code?: string, requestId?: string, details?: any) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}

export class TimeoutError extends Error {
  constructor(public readonly timeoutMs: number) {
    super(`Request timed out after ${timeoutMs} ms`);
    this.name = "TimeoutError";
  }
}

export class NetworkError extends Error {
  constructor(public readonly cause?: any) {
    super(`Network error${cause ? `: ${String(cause)}` : ""}`);
    this.name = "NetworkError";
  }
}

export class RateLimitError extends ApiError {
  public readonly retryAfterMs?: number;
  constructor(message: string, status: number, requestId?: string, retryAfterMs?: number) {
    super(message, status, "rate_limit", requestId);
    this.name = "RateLimitError";
    this.retryAfterMs = retryAfterMs;
  }
}

/** Simple in-memory cache for GET */
type CacheEntry = {
  expiresAt: number;
  etag?: string;
  data: any;
};
class SimpleCache {
  private map = new Map<string, CacheEntry>();
  constructor(private readonly maxEntries: number) {}

  get(key: string): CacheEntry | undefined {
    const e = this.map.get(key);
    if (!e) return;
    if (nowMs() >= e.expiresAt) {
      this.map.delete(key);
      return;
    }
    return e;
  }
  set(key: string, value: CacheEntry): void {
    if (this.map.size >= this.maxEntries) {
      // drop oldest
      const first = this.map.keys().next().value as string | undefined;
      if (first) this.map.delete(first);
    }
    this.map.set(key, value);
  }
  delete(key: string): void {
    this.map.delete(key);
  }
  clear(): void {
    this.map.clear();
  }
}

/** Circuit breaker state */
class CircuitBreaker {
  private failures = 0;
  private state: "closed" | "open" | "half_open" = "closed";
  private openedAt = 0;
  private halfOpenInFlight = 0;

  constructor(private readonly opts: CircuitBreakerOptions, private readonly telemetry?: TelemetryHooks, private readonly logger?: Logger) {}

  canRequest(): boolean {
    if (this.state === "closed") return true;
    const now = nowMs();
    if (this.state === "open") {
      if (now - this.openedAt >= this.opts.cooldownMs) {
        // transition to half-open
        this.state = "half_open";
        this.halfOpenInFlight = 0;
        this.emitState();
        return this.halfOpenInFlight < this.opts.halfOpenMaxRequests;
      }
      return false;
    }
    if (this.state === "half_open") {
      return this.halfOpenInFlight < this.opts.halfOpenMaxRequests;
    }
    return true;
  }

  onRequestStart(): void {
    if (this.state === "half_open") {
      this.halfOpenInFlight += 1;
    }
  }

  onSuccess(): void {
    if (this.state === "half_open") {
      this.state = "closed";
      this.failures = 0;
      this.halfOpenInFlight = 0;
      this.emitState();
      return;
    }
    this.failures = 0;
  }

  onFailure(): void {
    if (this.state === "half_open") {
      this.state = "open";
      this.openedAt = nowMs();
      this.halfOpenInFlight = 0;
      this.emitState();
      return;
    }
    this.failures += 1;
    if (this.failures >= this.opts.failureThreshold) {
      this.state = "open";
      this.openedAt = nowMs();
      this.emitState();
    }
  }

  private emitState(): void {
    this.logger?.warn("Circuit state:", { state: this.state, failures: this.failures });
    this.telemetry?.onCircuitOpen?.({
      state: this.state,
      failures: this.failures,
      openedAt: this.openedAt,
      cooldownMs: this.opts.cooldownMs,
    });
  }
}

/** Signing: X-NF-Signature = HMAC-SHA256(base64) of `${ts}.${method}.${path}.${sha256(body)}` */
async function computeSignature(hmacSecret: string, method: HttpMethod, path: string, body?: ArrayBuffer | null): Promise<string> {
  const ts = Math.floor(Date.now() / 1000);
  const enc = new TextEncoder();
  const algo = { name: "HMAC", hash: "SHA-256" } as const;

  // hash body
  const bodyBytes = body ?? new ArrayBuffer(0);
  const bodyHash = await crypto.subtle.digest("SHA-256", bodyBytes);
  const msg = `${ts}.${method}.${path}.${toHex(bodyHash)}`;
  const key = await crypto.subtle.importKey("raw", enc.encode(hmacSecret), algo, false, ["sign"]);
  const sig = await crypto.subtle.sign(algo, key, enc.encode(msg));
  const sigB64 = toBase64(sig);
  return `${ts}.${sigB64}`;
}

function toHex(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf);
  const hex = Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
  return hex;
}

function toBase64(buf: ArrayBuffer): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(buf as any).toString("base64");
  }
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  // btoa is available in browsers
  // eslint-disable-next-line no-undef
  return btoa(binary);
}

export class NeuroForgeClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly oauthToken?: string;
  private readonly hmacSecret?: string;
  private readonly userAgent?: string;
  private readonly timeoutMs: number;
  private readonly retry: RetryPolicy;
  private readonly telemetry?: TelemetryHooks;
  private readonly logger?: Logger;
  private readonly defaultHeaders: Record<string, string>;
  private readonly cacheCfg: CacheOptions;
  private readonly cache?: SimpleCache;

  private readonly circuit: CircuitBreaker;

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new Error("baseUrl is required");
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.oauthToken = opts.oauthToken;
    this.hmacSecret = opts.hmacSecret;
    this.userAgent = opts.userAgent;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retry = { ...DEFAULT_RETRY, ...(opts.retry ?? {}) };
    const circuitOpts = { ...DEFAULT_CIRCUIT, ...(opts.circuit ?? {}) };
    this.telemetry = opts.telemetry;
    this.logger = opts.logger;
    this.defaultHeaders = { ...(opts.defaultHeaders ?? {}) };
    this.cacheCfg = { ...DEFAULT_CACHE, ...(opts.cache ?? {}) };
    this.cache = this.cacheCfg.enabled ? new SimpleCache(this.cacheCfg.maxEntries) : undefined;
    this.circuit = new CircuitBreaker(circuitOpts, this.telemetry, this.logger);
  }

  // -------------- Public high-level domain methods (examples) --------------

  /** Datasets: list with pagination */
  public listDatasets = this.paginated<{ id: string; name: string; version: string }>(
    (cursor?: string) =>
      this.request("GET", "/v1/datasets", { query: cursor ? { cursor } : undefined }),
    (resp) => ({
      items: (resp?.data ?? []) as { id: string; name: string; version: string }[],
      nextCursor: resp?.next_cursor as string | undefined,
    })
  );

  /** Get dataset by id */
  public async getDataset(datasetId: string, signal?: AbortSignal) {
    if (!datasetId) throw new Error("datasetId is required");
    return this.request("GET", `/v1/datasets/${encodeURIComponent(datasetId)}`, { signal, cacheTtlMs: 15_000 });
  }

  /** Create dataset (idempotent via key) */
  public async createDataset(body: unknown, idempotencyKey?: string, signal?: AbortSignal) {
    return this.request("POST", "/v1/datasets", { body, idempotencyKey, signal });
  }

  /** Stream events from job (SSE or NDJSON) */
  public async *streamJob(jobId: string, signal?: AbortSignal): AsyncGenerator<any> {
    const path = `/v1/jobs/${encodeURIComponent(jobId)}/stream`;
    const { response } = await this.raw("GET", path, { signal, streaming: true });
    const ct = response.headers.get("content-type");
    if (isSse(ct)) {
      yield* this.readSSE(response);
    } else if (isNdJson(ct)) {
      yield* this.readNDJSON(response);
    } else {
      throw new ApiError("Unsupported stream content-type", 415);
    }
  }

  // -------------- Core request methods --------------

  public async request(
    method: HttpMethod,
    path: string,
    opts?: {
      body?: unknown;
      query?: Record<string, unknown>;
      headers?: Record<string, string>;
      signal?: AbortSignal;
      idempotencyKey?: string;
      cacheTtlMs?: number; // only for GET
    }
  ): Promise<any> {
    const url = this.baseUrl + path + encodeQuery(opts?.query);
    const cacheKey = method === "GET" && this.cache ? url : undefined;
    let etag: string | undefined;

    if (method === "GET" && this.cache && this.cacheCfg.enabled) {
      const hit = this.cache.get(url);
      if (hit) {
        // Soft revalidate if ETag supported
        if (this.cacheCfg.respectETag && hit.etag) {
          etag = hit.etag;
        } else {
          return hit.data;
        }
      }
    }

    const { response, body } = await this.raw(method, path, {
      body: opts?.body,
      query: opts?.query,
      headers: { ...opts?.headers, ...(etag ? { "If-None-Match": etag } : {}) },
      signal: opts?.signal,
      idempotencyKey: opts?.idempotencyKey,
    });

    const contentType = response.headers.get("content-type");
    if (response.status === 304 && cacheKey && this.cache) {
      // Not modified
      const cached = this.cache.get(cacheKey);
      if (cached) return cached.data;
    }

    let data: any = null;
    if (body && isJson(contentType)) {
      try {
        data = JSON.parse(new TextDecoder().decode(body));
      } catch {
        // fallback: treat as text
        data = new TextDecoder().decode(body);
      }
    } else if (body) {
      data = new TextDecoder().decode(body);
    }

    if (!response.ok) {
      this.throwApiError(response, data);
    }

    if (cacheKey && this.cache && method === "GET") {
      const newEtag = response.headers.get("etag") ?? undefined;
      const ttl = opts?.cacheTtlMs ?? this.cacheCfg.defaultTtlMs;
      this.cache.set(cacheKey, { data, etag: newEtag, expiresAt: nowMs() + ttl });
    }

    return data;
  }

  /** Low-level fetch with retries/timeouts/circuit/signing */
  public async raw(
    method: HttpMethod,
    path: string,
    opts?: {
      body?: unknown;
      query?: Record<string, unknown>;
      headers?: Record<string, string>;
      signal?: AbortSignal;
      idempotencyKey?: string;
      streaming?: boolean;
    }
  ): Promise<{ response: Response; body: ArrayBuffer | null }> {
    const url = this.baseUrl + path + encodeQuery(opts?.query);
    const headers: Record<string, string> = {
      Accept: "application/json",
      ...this.defaultHeaders,
      ...(opts?.headers ?? {}),
    };

    if (this.apiKey) headers["X-API-Key"] = this.apiKey;
    if (this.oauthToken) headers["Authorization"] = `Bearer ${this.oauthToken}`;
    if (this.userAgent) headers["User-Agent"] = this.userAgent;

    let bodyBytes: ArrayBuffer | null = null;
    if (opts?.body !== undefined) {
      headers["Content-Type"] = "application/json";
      bodyBytes = new TextEncoder().encode(JSON.stringify(opts.body));
    }

    if (this.hmacSecret) {
      const sig = await computeSignature(this.hmacSecret, method, path, bodyBytes);
      headers["X-NF-Signature"] = sig;
    }
    if (opts?.idempotencyKey) {
      headers["Idempotency-Key"] = opts.idempotencyKey;
    }

    // Circuit breaker check
    if (!this.circuit.canRequest()) {
      throw new ApiError("Circuit open: refusing request", 503, "circuit_open");
    }
    this.circuit.onRequestStart();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const combined = mergeSignals(controller.signal, opts?.signal);

    const ctx: RequestContext = {
      method,
      url,
      headers,
      bodySize: bodyBytes?.byteLength,
    };

    this.telemetry?.onRequestStart?.(ctx);
    const start = nowMs();

    let attempt = 0;
    let lastErr: any;

    try {
      // retry loop
      while (attempt <= this.retry.maxRetries) {
        attempt += 1;
        try {
          const response = await fetch(url, {
            method,
            headers,
            body: bodyBytes ? new Blob([bodyBytes]) : undefined,
            signal: combined,
          });

          // Handle rate limit
          if (response.status === 429) {
            const retryAfterMs = parseRetryAfter(response.headers.get("retry-after"));
            if (attempt <= this.retry.maxRetries) {
              await this.delayWithTelemetry(attempt, `429`, retryAfterMs ?? this.backoffDelay(attempt), combined);
              continue;
            }
            clearTimeout(timeout);
            this.circuit.onFailure();
            const end = nowMs();
            this.telemetry?.onRequestFinish?.({ ...ctx, durationMs: end - start });
            const reqId = response.headers.get("x-request-id") ?? undefined;
            throw new RateLimitError("Rate limited", 429, reqId, retryAfterMs ?? undefined);
          }

          // Retry on selected 4xx/5xx
          if (!response.ok && this.retry.retryOnStatuses.includes(response.status)) {
            if (attempt <= this.retry.maxRetries) {
              await this.delayWithTelemetry(attempt, `status_${response.status}`, this.backoffDelay(attempt), combined);
              continue;
            }
          }

          // Success or non-retriable error
          if (!response.ok) {
            const buf = opts?.streaming ? null : await response.arrayBuffer().catch(() => null);
            clearTimeout(timeout);
            if (response.ok) this.circuit.onSuccess(); else this.circuit.onFailure();
            const end = nowMs();
            this.telemetry?.onRequestFinish?.({ ...ctx, durationMs: end - start });
            return { response, body: buf };
          }

          // OK
          const buf = opts?.streaming ? null : await response.arrayBuffer().catch(() => null);
          clearTimeout(timeout);
          this.circuit.onSuccess();
          const end = nowMs();
          this.telemetry?.onRequestFinish?.({ ...ctx, durationMs: end - start });
          return { response, body: buf };
        } catch (err: any) {
          // Abort/timeout handling
          if (err?.name === "AbortError") {
            // Distinguish our timeout vs external abort if possible
            clearTimeout(timeout);
            this.circuit.onFailure();
            const end = nowMs();
            this.telemetry?.onRequestFinish?.({ ...ctx, durationMs: end - start });
            // If external signal aborted, surface as AbortError
            if (opts?.signal?.aborted) throw err;
            throw new TimeoutError(this.timeoutMs);
          }

          // Network error
          lastErr = err;
          if (!this.retry.retryOnNetworkError || attempt > this.retry.maxRetries) {
            clearTimeout(timeout);
            this.circuit.onFailure();
            const end = nowMs();
            this.telemetry?.onRequestFinish?.({ ...ctx, durationMs: end - start });
            throw new NetworkError(err);
          }
          await this.delayWithTelemetry(attempt, "network_error", this.backoffDelay(attempt), combined);
          continue;
        }
      }
    } catch (e) {
      clearTimeout(timeout);
      throw e;
    }

    clearTimeout(timeout);
    this.circuit.onFailure();
    const end = nowMs();
    this.telemetry?.onRequestFinish?.({ ...ctx, durationMs: end - start });
    throw new NetworkError(lastErr);
  }

  private throwApiError(response: Response, data: any): never {
    const status = response.status;
    const reqId = response.headers.get("x-request-id") ?? undefined;
    if (status === 429) {
      const retryAfterMs = parseRetryAfter(response.headers.get("retry-after"));
      throw new RateLimitError("Rate limited", status, reqId, retryAfterMs ?? undefined);
    }
    const msg = toErrorMessage(data) || `HTTP ${status}`;
    const code = typeof data?.code === "string" ? data.code : undefined;
    throw new ApiError(msg, status, code, reqId, data);
  }

  private backoffDelay(attempt: number): number {
    const exp = this.retry.baseDelayMs * Math.pow(this.retry.backoffFactor, attempt - 1);
    return Math.min(this.retry.maxDelayMs, jitter(exp));
    }

  private async delayWithTelemetry(attempt: number, reason: string, delayMs: number, signal?: AbortSignal): Promise<void> {
    this.telemetry?.onRetry?.({
      attempt,
      maxRetries: this.retry.maxRetries,
      delayMs,
      reason,
      method: "GET", // not strictly known here
      url: "",
    });
    await sleep(delayMs, signal);
  }

  // -------------- Streaming readers --------------

  private async *readNDJSON(response: Response): AsyncGenerator<any> {
    const reader = response.body?.getReader();
    if (!reader) return;
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      // split by newline
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try {
          yield JSON.parse(line);
        } catch {
          // skip malformed line
        }
      }
    }
    if (buf.trim()) {
      try {
        yield JSON.parse(buf.trim());
      } catch {
        // ignore
      }
    }
  }

  private async *readSSE(response: Response): AsyncGenerator<any> {
    const reader = response.body?.getReader();
    if (!reader) return;
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let sep: number;
      // SSE events are separated by double newline
      while ((sep = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, sep);
        buf = buf.slice(sep + 2);
        const evt = parseSSE(chunk);
        if (evt !== undefined) yield evt;
      }
    }
    // flush remaining
    if (buf) {
      const evt = parseSSE(buf);
      if (evt !== undefined) yield evt;
    }
  }

  // -------------- Pagination helper --------------

  /**
   * Returns an async iterator over items.
   * fetchPage: (cursor?) => Promise<{ data: T[]; next_cursor?: string }>
   * select: map server response into { items, nextCursor }
   */
  private paginated<T>(
    fetchPage: (cursor?: string) => Promise<any>,
    select: (resp: any) => { items: T[]; nextCursor?: string }
  ): (params?: { cursor?: string; limit?: number }) => AsyncIterable<T> {
    return (params?: { cursor?: string; limit?: number }) => {
      const self = this;
      async function* gen() {
        let cursor = params?.cursor;
        let yielded = 0;
        for (;;) {
          const resp = await fetchPage(cursor);
          const { items, nextCursor } = select(resp);
          for (const it of items) {
            yield it;
            yielded++;
            if (params?.limit !== undefined && yielded >= params.limit) return;
          }
          if (!nextCursor) return;
          cursor = nextCursor;
        }
      }
      return {
        [Symbol.asyncIterator]() {
          return gen();
        },
      };
    };
  }
}

// ---------------------- Utilities ----------------------

function parseRetryAfter(h: string | null): number | undefined {
  if (!h) return;
  // Could be seconds or HTTP date
  const secs = Number(h);
  if (!Number.isNaN(secs)) return secs * 1000;
  const t = Date.parse(h);
  if (!Number.isNaN(t)) return Math.max(0, t - Date.now());
  return;
}

function toErrorMessage(data: any): string | undefined {
  if (!data) return;
  if (typeof data === "string") return data;
  if (typeof data.message === "string") return data.message;
  if (typeof data.error === "string") return data.error;
  return;
}

/** Merge our timeout controller with external signal */
function mergeSignals(a: AbortSignal, b?: AbortSignal): AbortSignal {
  if (!b) return a;
  const ctrl = new AbortController();
  const onAbort = () => ctrl.abort();
  a.addEventListener("abort", onAbort);
  b.addEventListener("abort", onAbort);
  // Propagate state
  if (a.aborted || b.aborted) ctrl.abort();
  return ctrl.signal;
}

function parseSSE(chunk: string): any | undefined {
  // Basic SSE: lines "event: name" and "data: json"
  const lines = chunk.split("\n");
  let data: string | undefined;
  for (const ln of lines) {
    const s = ln.trim();
    if (s.startsWith("data:")) {
      data = s.slice(5).trim();
    }
  }
  if (!data) return;
  try {
    return JSON.parse(data);
  } catch {
    return { data };
  }
}

// ---------------------- Example Type Declarations ----------------------
// You can extend with your API surfaces as needed:

export interface Dataset {
  id: string;
  name: string;
  version: string;
  description?: string;
}
