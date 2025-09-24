// cybersecurity-core/sdks/typescript/src/client.ts

/* eslint-disable no-console */

/**
 * Industrial-grade Cybersecurity SDK HTTP client
 * - Auth: API Key / OAuth2 Bearer / HMAC (SHA-256)
 * - Reliability: retries (exp backoff + jitter), timeouts, circuit breaker
 * - Control: token-bucket rate limiter, Idempotency-Key for unsafe methods
 * - Convenience: JSON helpers, pagination iterator, SSE subscribe
 * - Compatibility: Browser & Node >= 18 without external deps
 */

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface Logger {
  debug(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

export interface CircuitBreakerOptions {
  failureThreshold: number; // failures to open
  cooldownMs: number;       // open -> half-open after cooldown
}

export interface RateLimitOptions {
  ratePerSec: number;     // tokens per second
  burst?: number;         // bucket capacity (default: 2 * ratePerSec)
}

export interface RetryOptions {
  maxRetries: number;       // total retry attempts
  baseDelayMs: number;      // base backoff
  maxDelayMs?: number;      // clamp backoff
  jitter?: boolean;         // add jitter
  retryOn?: (status: number | null, err: Error | null) => boolean;
}

export interface ClientOptions {
  baseUrl: string;
  apiKey?: string;
  oauthToken?: string;
  hmacSecret?: string | ArrayBuffer; // enables HMAC signing if provided
  organizationId?: string;

  defaultHeaders?: Record<string, string>;
  userAgent?: string;

  timeoutMs?: number;          // per request timeout
  retry?: Partial<RetryOptions>;
  circuitBreaker?: Partial<CircuitBreakerOptions>;
  rateLimit?: Partial<RateLimitOptions>;

  fetchImpl?: typeof fetch;    // custom fetch (tests, polyfills)
  logger?: Logger;             // custom logger
}

export interface RequestOptions {
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  timeoutMs?: number;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

export interface ApiErrorPayload {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
  [k: string]: unknown;
}

export class ApiError extends Error {
  public status: number | null;
  public code?: string;
  public details?: unknown;
  public requestId?: string;

  constructor(message: string, status: number | null, code?: string, details?: unknown, requestId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
  }
}

export class TimeoutError extends Error {
  constructor(ms: number) {
    super(`Request timed out after ${ms} ms`);
    this.name = "TimeoutError";
  }
}

export class RateLimitError extends Error {
  constructor() {
    super("Rate limit exceeded (token bucket depleted)");
    this.name = "RateLimitError";
  }
}

export class CircuitOpenError extends Error {
  constructor() {
    super("Circuit breaker is open");
    this.name = "CircuitOpenError";
  }
}

export class AuthError extends Error {
  constructor(msg = "Authentication is not configured") {
    super(msg);
    this.name = "AuthError";
  }
}

/** Utilities */

const isBrowser = typeof window !== "undefined" && typeof window.document !== "undefined";
const HAS_WEB_CRYPTO = typeof crypto !== "undefined" && !!(crypto as any).subtle;

function textEncoder(): TextEncoder {
  return new TextEncoder();
}

function toArrayBuffer(input: string | ArrayBuffer): ArrayBuffer {
  if (typeof input === "string") {
    return textEncoder().encode(input).buffer;
  }
  return input;
}

function hex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function withJitter(ms: number): number {
  // Full jitter
  return Math.random() * ms;
}

function isUnsafeMethod(method: HttpMethod): boolean {
  return method !== "GET";
}

function buildQuery(query?: Record<string, string | number | boolean | undefined>): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined) continue;
    params.append(k, String(v));
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}

function parseRetryAfter(h: string | null): number | null {
  if (!h) return null;
  const secs = Number(h);
  if (!Number.isNaN(secs)) return Math.max(0, secs * 1000);
  const date = Date.parse(h);
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now());
  return null;
}

function generateUUIDv4(): string {
  // RFC 4122 v4
  const b = new Uint8Array(16);
  (typeof crypto !== "undefined" && crypto.getRandomValues) ? crypto.getRandomValues(b) : (() => {
    for (let i = 0; i < 16; i++) b[i] = (Math.random() * 256) | 0;
  })();
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const toHex = (n: number) => n.toString(16).padStart(2, "0");
  return (
    `${toHex(b[0])}${toHex(b[1])}${toHex(b[2])}${toHex(b[3])}-` +
    `${toHex(b[4])}${toHex(b[5])}-` +
    `${toHex(b[6])}${toHex(b[7])}-` +
    `${toHex(b[8])}${toHex(b[9])}-` +
    `${toHex(b[10])}${toHex(b[11])}${toHex(b[12])}${toHex(b[13])}${toHex(b[14])}${toHex(b[15])}`
  );
}

async function hmacSHA256(secret: string | ArrayBuffer, data: string): Promise<string> {
  const raw = toArrayBuffer(secret);
  const msg = textEncoder().encode(data);
  if (HAS_WEB_CRYPTO) {
    const key = await (crypto as any).subtle.importKey(
      "raw",
      raw,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await (crypto as any).subtle.sign("HMAC", key, msg);
    return hex(sig);
  } else {
    // Node fallback via dynamic import to avoid bundler complaints in browser
    const nodeCrypto = await import("node:crypto");
    const buf = Buffer.isBuffer(secret) ? secret : Buffer.from(new Uint8Array(raw));
    return nodeCrypto.createHmac("sha256", buf).update(msg).digest("hex");
  }
}

/** Simple Token Bucket Rate Limiter */
class TokenBucket {
  private capacity: number;
  private tokens: number;
  private refillRate: number; // tokens per ms
  private lastRefill: number;

  constructor(opts: RateLimitOptions) {
    const rate = Math.max(1, Math.floor(opts.ratePerSec));
    this.capacity = Math.max(rate, opts.burst ?? rate * 2);
    this.tokens = this.capacity;
    this.refillRate = rate / 1000; // tokens/ms
    this.lastRefill = Date.now();
  }

  private refill() {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    if (elapsed <= 0) return;
    this.tokens = clamp(this.tokens + elapsed * this.refillRate, 0, this.capacity);
    this.lastRefill = now;
  }

  public tryRemoveToken(): boolean {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  public async removeTokenOrWait(timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!this.tryRemoveToken()) {
      if (Date.now() > deadline) throw new RateLimitError();
      // Sleep roughly until next token is expected
      await sleep(10);
    }
  }
}

/** Minimal Circuit Breaker */
class CircuitBreaker {
  private state: "closed" | "open" | "half-open" = "closed";
  private failures = 0;
  private openedAt = 0;
  private readonly failureThreshold: number;
  private readonly cooldownMs: number;

  constructor(opts: CircuitBreakerOptions) {
    this.failureThreshold = Math.max(1, opts.failureThreshold);
    this.cooldownMs = Math.max(100, opts.cooldownMs);
  }

  public allowRequest(): boolean {
    if (this.state === "closed") return true;
    if (this.state === "open") {
      const now = Date.now();
      if (now - this.openedAt > this.cooldownMs) {
        this.state = "half-open";
        return true;
      }
      return false;
    }
    // half-open allows a single trial (enforced by caller)
    return true;
  }

  public onSuccess() {
    this.failures = 0;
    this.state = "closed";
  }

  public onFailure() {
    this.failures += 1;
    if (this.failures >= this.failureThreshold) {
      this.state = "open";
      this.openedAt = Date.now();
    }
  }
}

/** Core Client */
export class CybersecurityClient {
  private baseUrl: string;
  private apiKey?: string;
  private oauthToken?: string;
  private hmacSecret?: string | ArrayBuffer;
  private organizationId?: string;

  private defaultHeaders: Record<string, string>;
  private userAgent: string;
  private timeoutMs: number;
  private retry: RetryOptions;
  private fetchImpl: typeof fetch;
  private logger: Logger;

  private bucket?: TokenBucket;
  private breaker: CircuitBreaker;

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new Error("baseUrl is required");

    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.oauthToken = opts.oauthToken;
    this.hmacSecret = opts.hmacSecret;
    this.organizationId = opts.organizationId;

    this.defaultHeaders = Object.assign({}, opts.defaultHeaders);
    this.userAgent = opts.userAgent ?? "cybersecurity-core-ts-sdk/1.0";
    this.timeoutMs = opts.timeoutMs ?? 30_000;

    const retryDefaults: RetryOptions = {
      maxRetries: 3,
      baseDelayMs: 300,
      maxDelayMs: 10_000,
      jitter: true,
      retryOn: (status, err) => {
        if (err) return true; // network/timeout
        if (status === null) return true;
        return status >= 500 || status === 429;
      },
    };
    this.retry = { ...retryDefaults, ...(opts.retry ?? {}) };

    const cbDefaults: CircuitBreakerOptions = { failureThreshold: 5, cooldownMs: 15_000 };
    this.breaker = new CircuitBreaker({ ...cbDefaults, ...(opts.circuitBreaker ?? {}) });

    if (opts.rateLimit?.ratePerSec) {
      const rlDefaults: RateLimitOptions = { ratePerSec: opts.rateLimit.ratePerSec, burst: opts.rateLimit.burst ?? (opts.rateLimit.ratePerSec * 2) };
      this.bucket = new TokenBucket(rlDefaults);
    }

    this.fetchImpl = opts.fetchImpl ?? fetch.bind(globalThis);
    this.logger = opts.logger ?? console;
  }

  /** Public shorthand methods */
  public get<T = unknown>(path: string, options?: RequestOptions) {
    return this.request<T>("GET", path, options);
  }
  public post<T = unknown>(path: string, options?: RequestOptions) {
    return this.request<T>("POST", path, options);
  }
  public put<T = unknown>(path: string, options?: RequestOptions) {
    return this.request<T>("PUT", path, options);
  }
  public patch<T = unknown>(path: string, options?: RequestOptions) {
    return this.request<T>("PATCH", path, options);
  }
  public delete<T = unknown>(path: string, options?: RequestOptions) {
    return this.request<T>("DELETE", path, options);
  }

  /** Core request with retries, timeout, circuit breaker, HMAC, rate limit */
  public async request<T = unknown>(method: HttpMethod, path: string, options?: RequestOptions): Promise<T> {
    const queryString = buildQuery(options?.query);
    const url = `${this.baseUrl}${path.startsWith("/") ? "" : "/"}${path}${queryString}`;
    const headers: Record<string, string> = Object.assign({}, this.defaultHeaders, options?.headers);

    headers["Accept"] = headers["Accept"] ?? "application/json";
    headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
    headers["User-Agent"] = headers["User-Agent"] ?? this.userAgent;
    headers["x-request-id"] = headers["x-request-id"] ?? generateUUIDv4();
    if (this.organizationId) headers["X-Org-Id"] = this.organizationId;

    // Auth headers
    if (this.oauthToken) {
      headers["Authorization"] = `Bearer ${this.oauthToken}`;
    } else if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    } else if (!this.hmacSecret) {
      // Allow unsigned public endpoints; otherwise warn
      this.logger.debug("[client] proceeding without explicit auth headers");
    }

    // Idempotency for unsafe methods (unless provided)
    if (isUnsafeMethod(method) && !headers["Idempotency-Key"]) {
      headers["Idempotency-Key"] = options?.idempotencyKey ?? generateUUIDv4();
    }

    // Encode body once for signature and fetch
    let bodyString: string | undefined;
    if (options?.body !== undefined && options?.body !== null) {
      bodyString = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
    }

    // HMAC signature if configured
    const timestamp = Date.now().toString();
    if (this.hmacSecret) {
      const parsed = new URL(url);
      const signingPath = parsed.pathname + (parsed.search || "");
      const payload = `${method}\n${signingPath}\n${bodyString ?? ""}\n${timestamp}`;
      const signature = await hmacSHA256(this.hmacSecret, payload);
      headers["x-timestamp"] = timestamp;
      headers["x-signature"] = signature;
      headers["x-signature-alg"] = "HMAC-SHA256";
    }

    const timeoutMs = options?.timeoutMs ?? this.timeoutMs;

    // Rate limiting
    if (this.bucket) {
      await this.bucket.removeTokenOrWait(timeoutMs);
    }

    // Circuit breaker gate
    if (!this.breaker.allowRequest()) {
      throw new CircuitOpenError();
    }

    const ctl = new AbortController();
    const userSignal = options?.signal;
    const timeout = setTimeout(() => ctl.abort(), timeoutMs);
    const abortCleanup = () => clearTimeout(timeout);

    const doFetch = async (): Promise<Response> => {
      try {
        return await this.fetchImpl(url, {
          method,
          headers,
          body: bodyString,
          signal: userSignal ? anySignal([ctl.signal, userSignal]) : ctl.signal,
        });
      } catch (err: any) {
        // Network-level error
        throw err;
      } finally {
        abortCleanup();
      }
    };

    let attempt = 0;
    let lastErr: Error | null = null;
    while (true) {
      try {
        const res = await doFetch();

        // Handle retryable statuses
        if (this.retry.retryOn?.(res.status, null)) {
          const retryAfterMs = parseRetryAfter(res.headers.get("Retry-After"));
          if (attempt < this.retry.maxRetries) {
            attempt++;
            await this.delayForAttempt(attempt, retryAfterMs ?? undefined);
            continue;
          }
        }

        // Parse response body
        const requestId = res.headers.get("x-request-id") ?? headers["x-request-id"];
        if (!res.ok) {
          const payload = await safeParseJson<ApiErrorPayload>(res);
          const msg =
            payload?.error?.message ||
            `Request failed with status ${res.status}`;
          const code = payload?.error?.code;
          this.breaker.onFailure();
          throw new ApiError(msg, res.status, code, payload?.error?.details ?? payload, requestId ?? undefined);
        }

        // Success
        this.breaker.onSuccess();
        const contentType = res.headers.get("Content-Type") || "";
        if (contentType.includes("application/json")) {
          return (await res.json()) as T;
        } else if (contentType.startsWith("text/")) {
          return (await res.text()) as unknown as T;
        } else {
          // Return raw Response for binary or unknown content-types
          return (await res.arrayBuffer()) as unknown as T;
        }
      } catch (err: any) {
        lastErr = normalizeError(err, timeoutMs);
        // Retry on network/timeout if policy says so
        const status: number | null = err instanceof ApiError ? err.status : null;
        if (this.retry.retryOn?.(status, lastErr) && attempt < this.retry.maxRetries) {
          attempt++;
          await this.delayForAttempt(attempt);
          continue;
        }
        this.breaker.onFailure();
        throw lastErr;
      }
    }
  }

  /** Async iterator over paginated endpoints */
  public async *paginate<T = unknown>(
    path: string,
    initQuery: Record<string, string | number | boolean | undefined>,
    options: {
      pageParam?: string;
      pageSizeParam?: string;
      pageSize?: number;
      extractItems?: (page: any) => T[];
      extractNext?: (page: any) => string | number | null | undefined;
      requestOptions?: Omit<RequestOptions, "query">;
    } = {}
  ): AsyncGenerator<T[], void, unknown> {
    const pageParam = options.pageParam ?? "page";
    const pageSizeParam = options.pageSizeParam ?? "page_size";
    const pageSize = options.pageSize ?? 100;

    let cursor: string | number | null | undefined = initQuery[pageParam] as any;
    let page = 1;
    while (true) {
      const q = {
        ...initQuery,
        [pageParam]: cursor ?? page,
        [pageSizeParam]: pageSize,
      };
      const resp = await this.get<any>(path, { ...(options.requestOptions ?? {}), query: q });
      const extractItems = options.extractItems ?? ((r: any) => r.items ?? r.data ?? []);
      const items = extractItems(resp);
      if (!Array.isArray(items)) {
        throw new Error("Paginator: extractItems did not return an array");
      }
      yield items as T[];
      const extractNext = options.extractNext ?? ((r: any) => r.next ?? r.nextPage ?? (r.page < r.totalPages ? r.page + 1 : null));
      cursor = extractNext(resp);
      if (!cursor) break;
      page = typeof cursor === "number" ? cursor : page + 1;
    }
  }

  /** Server-Sent Events (SSE) subscribe helper */
  public async subscribeSSE(
    path: string,
    opts: {
      query?: Record<string, string | number | boolean | undefined>;
      headers?: Record<string, string>;
      onMessage: (event: { event: string; id?: string; data: string; retry?: number }) => void;
      signal?: AbortSignal;
      lastEventId?: string;
      timeoutMs?: number; // stream open timeout
    }
  ): Promise<{ close: () => void }> {
    const url = `${this.baseUrl}${path.startsWith("/") ? "" : "/"}${path}${buildQuery(opts.query)}`;
    const headers: Record<string, string> = Object.assign({}, this.defaultHeaders, opts.headers);
    headers["Accept"] = "text/event-stream";
    headers["Cache-Control"] = "no-cache";
    headers["User-Agent"] = headers["User-Agent"] ?? this.userAgent;
    if (this.organizationId) headers["X-Org-Id"] = this.organizationId;

    if (this.oauthToken) headers["Authorization"] = `Bearer ${this.oauthToken}`;
    else if (this.apiKey) headers["X-API-Key"] = this.apiKey;

    if (opts.lastEventId) headers["Last-Event-ID"] = opts.lastEventId;

    const controller = new AbortController();
    const signal = opts.signal ? anySignal([controller.signal, opts.signal]) : controller.signal;

    const res = await this.fetchImpl(url, { headers, method: "GET", signal });
    if (!res.ok || !res.body) {
      throw new ApiError(`SSE connection failed with status ${res.status}`, res.status);
    }

    // Read stream line-by-line
    const reader = (res.body as any).getReader?.();
    if (!reader) throw new Error("SSE: ReadableStream reader is not available in this environment");

    const decoder = new TextDecoder();
    let buffer = "";
    (async () => {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let idx: number;
          while ((idx = buffer.indexOf("\n\n")) !== -1) {
            const chunk = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            const evt = parseSSEEvent(chunk);
            if (evt) opts.onMessage(evt);
          }
        }
      } catch (e) {
        this.logger.debug("SSE stream closed", e);
      }
    })();

    return { close: () => controller.abort() };
  }

  /** Internal helpers */

  private async delayForAttempt(attempt: number, overrideMs?: number) {
    const base = overrideMs ?? (this.retry.baseDelayMs * Math.pow(2, attempt - 1));
    const capped = clamp(base, this.retry.baseDelayMs, this.retry.maxDelayMs ?? base);
    const ms = this.retry.jitter ? withJitter(capped) : capped;
    await sleep(ms);
  }
}

/** Helpers */

function normalizeError(err: any, timeoutMs: number): Error {
  if (err?.name === "AbortError") {
    return new TimeoutError(timeoutMs);
  }
  if (err instanceof Error) return err;
  return new Error(String(err));
}

async function safeParseJson<T>(res: Response): Promise<T | null> {
  const ct = res.headers.get("Content-Type") || "";
  if (!ct.includes("application/json")) return null;
  try {
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

function anySignal(signals: AbortSignal[]): AbortSignal {
  // Combine multiple AbortSignals
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  for (const s of signals) {
    if (s.aborted) return s;
    s.addEventListener("abort", onAbort, { once: true });
  }
  return controller.signal;
}

function parseSSEEvent(block: string): { event: string; id?: string; data: string; retry?: number } | null {
  let event = "message";
  let id: string | undefined;
  let data: string[] = [];
  let retry: number | undefined;

  const lines = block.split("\n");
  for (const line of lines) {
    if (!line.trim() || line.startsWith(":")) continue; // comment or empty
    const idx = line.indexOf(":");
    const field = idx === -1 ? line : line.slice(0, idx);
    const value = idx === -1 ? "" : line.slice(idx + 1).trimStart();
    switch (field) {
      case "event":
        event = value || "message";
        break;
      case "id":
        id = value;
        break;
      case "data":
        data.push(value);
        break;
      case "retry":
        {
          const n = Number(value);
          if (!Number.isNaN(n)) retry = n;
        }
        break;
      default:
        // ignore unknown
        break;
    }
  }

  if (data.length === 0 && !id) return null;
  return { event, id, data: data.join("\n"), retry };
}

export default CybersecurityClient;
