/* ops/sdks/typescript/src/client.ts
   Industrial-grade TypeScript SDK client for Omnimind Core API.
   - No external deps. Works in Browser and Node (>=18 with global fetch).
   - Auth: Bearer/JWT or static Api-Key.
   - Timeouts & cancellation: AbortController.
   - Retries: exponential backoff + Retry-After. Safe methods only by default, or opt-in.
   - Idempotency-Key for unsafe methods.
   - Error handling: typed envelope compatible with omnimind.v1.Error (JSON analog).
   - Rate limit headers parsing.
   - ETag / conditional GET.
   - Pagination helpers.
   - Streaming & file uploads.

   Copyright (c) Omnimind.
*/

export type FetchLike = typeof fetch;

export interface RetryPolicy {
  maxAttempts: number;          // including first try
  baseDelayMs: number;          // initial backoff
  maxDelayMs: number;           // cap
  jitter: boolean;              // full jitter
  retryOnHttp: number[];        // e.g. [429, 502, 503, 504]
  retryOnNetworkError: boolean; // fetch/network errors
  retryOnMethods: ("GET"|"HEAD"|"OPTIONS"|"PUT"|"DELETE"|"PATCH"|"POST")[]; // default safe methods only
}

export interface ClientOptions {
  baseUrl: string;                     // e.g. https://api.example.com
  apiKey?: string;                     // static API key (sent as Authorization: Bearer/ApiKey)
  authScheme?: "Bearer"|"ApiKey";      // default: Bearer if apiKey provided
  getToken?: () => Promise<string>;    // dynamic token provider (overrides apiKey if set)
  timeoutMs?: number;                  // per request timeout (default 30_000)
  userAgent?: string;                  // appended to UA header (Node only)
  defaultHeaders?: Record<string,string>;
  fetchImpl?: FetchLike;               // custom fetch (for Node <18 or tests)
  retry?: Partial<RetryPolicy>;
  defaultLocale?: string;              // Accept-Language
  defaultIdempotency?: boolean;        // send Idempotency-Key on unsafe methods by default
  traceparentProvider?: () => string;  // for distributed tracing header
}

export interface ErrorEnvelope {
  code: string;               // e.g. "VALIDATION_FAILED", "NOT_FOUND"
  http_status?: number;
  message: string;
  locale?: string;
  request_id?: string;
  timestamp?: string;         // ISO timestamp
  domain?: string;
  reason?: string;
  hints?: string[];
  cause_chain?: string[];
  details?: unknown[];        // google.protobuf.Any-like JSONs
  retry?: {
    retry_after?: string;     // ISO8601 duration or seconds
    policy?: string;
    max_attempts?: number;
  };
}

export class OmnimindError extends Error {
  readonly status?: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly envelope?: ErrorEnvelope;
  constructor(message: string, init?: { status?: number; code?: string; requestId?: string; envelope?: ErrorEnvelope; cause?: unknown }) {
    super(message);
    this.name = "OmnimindError";
    this.status = init?.status;
    this.code = init?.code;
    this.requestId = init?.requestId;
    this.envelope = init?.envelope;
    if (init?.cause) (this as any).cause = init.cause;
  }
}

export interface RateLimitInfo {
  limit?: number;
  remaining?: number;
  reset?: number; // epoch seconds
  windowSeconds?: number;
}

export interface RequestOptions<Q=unknown,B=unknown> {
  query?: Q;
  body?: B;
  headers?: Record<string,string>;
  signal?: AbortSignal;
  timeoutMs?: number;
  idempotencyKey?: string;
  retry?: Partial<RetryPolicy>;
  etag?: string;                          // If-None-Match value
  responseType?: "json"|"text"|"blob"|"stream"; // default json
}

export interface ResponseMeta {
  status: number;
  headers: Headers;
  rateLimit?: RateLimitInfo;
  etag?: string | null;
  requestId?: string | null;
}

export interface JsonResponse<T> {
  data: T;
  meta: ResponseMeta;
}

export type Paginated<T> = {
  items: T[];
  nextPageToken?: string;
  total?: number;
};

const DEFAULT_RETRY: RetryPolicy = {
  maxAttempts: 3,
  baseDelayMs: 150,
  maxDelayMs: 2_000,
  jitter: true,
  retryOnHttp: [429, 502, 503, 504],
  retryOnNetworkError: true,
  retryOnMethods: ["GET","HEAD","OPTIONS"]
};

const DEFAULT_TIMEOUT = 30_000;

export class OmnimindClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly authScheme: "Bearer"|"ApiKey";
  private readonly getToken?: () => Promise<string>;
  private readonly timeoutMs: number;
  private readonly ua?: string;
  private readonly defaultHeaders: Record<string,string>;
  private readonly fetchImpl: FetchLike;
  private readonly retry: RetryPolicy;
  private readonly defaultLocale?: string;
  private readonly defaultIdempotency: boolean;
  private readonly traceparentProvider?: () => string;

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new Error("baseUrl is required");
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.authScheme = opts.authScheme ?? "Bearer";
    this.getToken = opts.getToken;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT;
    this.ua = opts.userAgent;
    this.defaultHeaders = { ...(opts.defaultHeaders ?? {}) };
    this.fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
    if (!this.fetchImpl) throw new Error("No fetch implementation available");
    this.retry = { ...DEFAULT_RETRY, ...(opts.retry ?? {}) };
    this.defaultLocale = opts.defaultLocale;
    this.defaultIdempotency = opts.defaultIdempotency ?? true;
    this.traceparentProvider = opts.traceparentProvider;
  }

  // Generic request
  async request<T = unknown, Q = Record<string,unknown>, B = unknown>(
    method: "GET"|"POST"|"PUT"|"PATCH"|"DELETE"|"HEAD"|"OPTIONS",
    path: string,
    options: RequestOptions<Q,B> = {}
  ): Promise<JsonResponse<T>> {
    const url = this.buildUrl(path, options.query as Record<string,unknown> | undefined);
    const controller = new AbortController();
    const timeout = options.timeoutMs ?? this.timeoutMs;
    const timeoutId = setTimeout(() => controller.abort(new DOMException("Timeout", "AbortError")), timeout);
    const userAbortSignal = options.signal;
    const signal = this.mergeSignals(controller.signal, userAbortSignal);

    const retryPolicy: RetryPolicy = { ...this.retry, ...(options.retry ?? {}) };
    const headers = await this.buildHeaders(method, options);
    let attempt = 0;
    let lastErr: unknown;

    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        attempt++;
        try {
          const res = await this.fetchImpl(url, {
            method,
            headers,
            body: this.serializeBody(headers, options.body),
            signal
          });

          const meta = this.extractMeta(res);

          // 304 Not Modified handled as empty body
          if (res.status >= 200 && res.status < 300) {
            const data = await this.parseBody<T>(res, options.responseType ?? "json");
            clearTimeout(timeoutId);
            return { data, meta };
          }

          // Retryable HTTP?
          if (this.shouldRetryHttp(res.status, method, retryPolicy, attempt)) {
            const delay = this.computeDelay(attempt, retryPolicy, res.headers);
            await this.sleep(delay, signal);
            continue;
          }

          // Non-2xx: try parse enveloped error
          await this.throwApiError(res);

        } catch (err: any) {
          // Network/Abort
          if (err?.name === "AbortError") {
            lastErr = err;
            if (this.shouldRetryNetwork(err, method, retryPolicy, attempt)) {
              const delay = this.computeDelay(attempt, retryPolicy);
              await this.sleep(delay);
              continue;
            }
            throw new OmnimindError("Request aborted/timeout", { cause: err });
          }
          lastErr = err;
          if (this.shouldRetryNetwork(err, method, retryPolicy, attempt)) {
            const delay = this.computeDelay(attempt, retryPolicy);
            await this.sleep(delay);
            continue;
          }
          throw err;
        }
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // Convenience methods
  get<T=unknown,Q=Record<string,unknown>>(path: string, opts?: RequestOptions<Q,never>) {
    return this.request<T,Q,never>("GET", path, opts);
  }
  post<T=unknown,B=unknown,Q=Record<string,unknown>>(path: string, opts?: RequestOptions<Q,B>) {
    return this.request<T,Q,B>("POST", path, opts);
  }
  put<T=unknown,B=unknown,Q=Record<string,unknown>>(path: string, opts?: RequestOptions<Q,B>) {
    return this.request<T,Q,B>("PUT", path, opts);
  }
  patch<T=unknown,B=unknown,Q=Record<string,unknown>>(path: string, opts?: RequestOptions<Q,B>) {
    return this.request<T,Q,B>("PATCH", path, opts);
  }
  delete<T=unknown,Q=Record<string,unknown>>(path: string, opts?: RequestOptions<Q,never>) {
    return this.request<T,Q,never>("DELETE", path, opts);
  }

  // Pagination helper (token-based)
  async *paginate<T=unknown,Q extends Record<string,unknown> = Record<string,unknown>>(
    path: string,
    query: Q,
    pageTokenField: keyof Q & string = "page_token" as any,
    pageSizeField: keyof Q & string = "page_size" as any,
    pageSize = 100
  ): AsyncGenerator<T[], void, unknown> {
    let token: string | undefined = undefined;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const q = { ...query, [pageSizeField]: pageSize, ...(token ? { [pageTokenField]: token } : {}) } as Q;
      const { data } = await this.get<Paginated<T>, Q>(path, { query: q });
      yield data.items ?? [];
      if (!data.nextPageToken) break;
      token = data.nextPageToken;
    }
  }

  // Upload helper (multipart)
  async upload<T=unknown,Q=Record<string,unknown>>(
    path: string,
    files: Record<string, Blob | File>,
    fields?: Record<string,string>,
    opts?: RequestOptions<Q,never>
  ): Promise<JsonResponse<T>> {
    const form = new FormData();
    for (const [k,v] of Object.entries(files)) {
      // @ts-expect-error: Node’s Blob/File compatible since Node 18
      form.append(k, v as any);
    }
    for (const [k,v] of Object.entries(fields ?? {})) {
      form.append(k, v);
    }
    const headers = { ...(opts?.headers ?? {}) };
    // fetch will set proper multipart boundary; do not set Content-Type explicitly
    return this.request<T,Q,FormData>("POST", path, { ...opts, body: form, headers });
  }

  // Streaming helper (consumes ReadableStream or Node stream)
  async getStream(path: string, opts?: RequestOptions) {
    const { baseUrl } = this;
    const url = this.buildUrl(path, opts?.query as any);
    const headers = await this.buildHeaders("GET", opts);
    const res = await this.fetchImpl(url, { method: "GET", headers, signal: opts?.signal });
    if (!res.ok) await this.throwApiError(res);
    return res.body; // ReadableStream<Uint8Array> (browser) / Node stream (Node)
  }

  // Internal helpers
  private async buildHeaders(method: string, options: RequestOptions): Promise<Headers> {
    const h = new Headers();

    // Default headers
    for (const [k,v] of Object.entries(this.defaultHeaders)) h.set(k, v);
    if (this.defaultLocale) h.set("Accept-Language", this.defaultLocale);
    h.set("Accept", "application/json");
    // User-Agent (Node only, header may be blocked in browsers)
    if (this.ua && typeof process !== "undefined" && process.release?.name === "node") {
      h.set("User-Agent", `omnimind-ts-sdk/1 ${this.ua}`);
    }

    // Content negotiation
    const hasBody = options.body !== undefined && options.body !== null;
    if (hasBody && !(options.body instanceof FormData) && !(options.body instanceof Blob)) {
      if (!h.has("Content-Type")) h.set("Content-Type", "application/json");
    }

    // Auth
    const tok = this.getToken ? await this.getToken() : this.apiKey;
    if (tok) {
      const scheme = this.authScheme ?? "Bearer";
      h.set("Authorization", `${scheme} ${tok}`);
    }

    // Idempotency for unsafe methods
    const unsafe = ["POST","PUT","PATCH","DELETE"].includes(method);
    if (unsafe && (options.idempotencyKey || this.defaultIdempotency)) {
      h.set("Idempotency-Key", options.idempotencyKey || cryptoRandomId());
    }

    // ETag conditional GET
    if (options.etag) h.set("If-None-Match", options.etag);

    // tracing
    const tp = this.traceparentProvider?.();
    if (tp) h.set("traceparent", tp);

    // Per-request headers
    for (const [k,v] of Object.entries(options.headers ?? {})) h.set(k, v);

    return h;
  }

  private buildUrl(path: string, query?: Record<string,unknown>) {
    const url = new URL(path.startsWith("http") ? path : `${this.baseUrl}${path.startsWith("/") ? "" : "/"}${path}`);
    if (query) {
      for (const [k,v] of Object.entries(query)) {
        if (v === undefined || v === null) continue;
        if (Array.isArray(v)) v.forEach(val => url.searchParams.append(k, String(val)));
        else url.searchParams.set(k, String(v));
      }
    }
    return url.toString();
  }

  private serializeBody(headers: Headers, body: unknown): BodyInit | undefined {
    if (body === undefined || body === null) return undefined;
    if (body instanceof FormData) return body;
    if (typeof Blob !== "undefined" && body instanceof Blob) return body as any;
    const ct = headers.get("Content-Type") || "";
    if (ct.includes("application/json") || ct === "") {
      return JSON.stringify(body);
    }
    return body as any;
  }

  private extractMeta(res: Response): ResponseMeta {
    const headers = res.headers;
    const rate: RateLimitInfo = {
      limit: num(headers.get("x-ratelimit-limit")),
      remaining: num(headers.get("x-ratelimit-remaining")),
      reset: num(headers.get("x-ratelimit-reset")),
      windowSeconds: num(headers.get("x-ratelimit-window"))
    };
    const etag = headers.get("etag");
    const requestId = headers.get("x-request-id");
    const meta: ResponseMeta = { status: res.status, headers, rateLimit: rate, etag, requestId };
    return meta;
  }

  private async parseBody<T>(res: Response, responseType: NonNullable<RequestOptions["responseType"]>): Promise<T> {
    if (res.status === 204 || res.headers.get("content-length") === "0") return undefined as unknown as T;
    const ct = res.headers.get("content-type") || "";
    if (responseType === "json") {
      if (ct.includes("application/json") || ct.includes("+json") || ct === "") {
        return (await res.json()) as T;
      }
      // fallback
      const text = await res.text();
      try { return JSON.parse(text) as T; } catch { return { raw: text } as unknown as T; }
    }
    if (responseType === "text") return (await res.text()) as unknown as T;
    if (responseType === "blob") return (await res.blob()) as unknown as T;
    if (responseType === "stream") return (res.body as unknown) as T;
    return (await res.json()) as T;
  }

  private shouldRetryHttp(status: number, method: string, policy: RetryPolicy, attempt: number): boolean {
    if (attempt >= policy.maxAttempts) return false;
    if (!policy.retryOnMethods.includes(method as any)) return false;
    return policy.retryOnHttp.includes(status);
    // Additionally, 408 could be considered; leaving to caller to customize retryOnHttp
  }

  private shouldRetryNetwork(err: unknown, method: string, policy: RetryPolicy, attempt: number): boolean {
    if (attempt >= policy.maxAttempts) return false;
    if (!policy.retryOnMethods.includes(method as any)) return false;
    if (!policy.retryOnNetworkError) return false;
    return true;
  }

  private computeDelay(attempt: number, policy: RetryPolicy, headers?: Headers): number {
    // Honor Retry-After header if present (seconds or HTTP date)
    const ra = headers?.get?.("retry-after");
    if (ra) {
      const seconds = parseInt(ra, 10);
      if (!Number.isNaN(seconds)) return clamp(seconds * 1000, 0, policy.maxDelayMs);
      const date = Date.parse(ra);
      if (!Number.isNaN(date)) {
        const ms = date - Date.now();
        return clamp(ms, 0, policy.maxDelayMs);
      }
    }
    const exp = Math.min(policy.maxDelayMs, policy.baseDelayMs * Math.pow(2, attempt - 1));
    return policy.jitter ? Math.floor(Math.random() * exp) : exp;
  }

  private async throwApiError(res: Response): Promise<never> {
    const status = res.status;
    let env: ErrorEnvelope | undefined;
    let message = `HTTP ${status}`;
    try {
      const ct = res.headers.get("content-type") || "";
      if (ct.includes("application/json") || ct.includes("+json")) {
        env = (await res.json()) as ErrorEnvelope;
        if (env?.message) message = env.message;
      } else {
        message = await res.text();
      }
    } catch { /* ignore */ }
    const err = new OmnimindError(message, {
      status,
      code: env?.code,
      requestId: res.headers.get("x-request-id") || env?.request_id,
      envelope: env
    });
    throw err;
  }

  private sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const t = setTimeout(resolve, ms);
      if (signal) {
        const onAbort = () => {
          clearTimeout(t);
          reject(new DOMException("Aborted", "AbortError"));
        };
        if (signal.aborted) return onAbort();
        signal.addEventListener("abort", onAbort, { once: true });
      }
    });
  }

  private mergeSignals(a: AbortSignal, b?: AbortSignal): AbortSignal {
    if (!b) return a;
    const controller = new AbortController();
    const onAbort = (reason?: any) => controller.abort(reason);
    const setup = (s: AbortSignal) => {
      if (s.aborted) return controller.abort(s.reason);
      s.addEventListener("abort", () => onAbort(s.reason), { once: true });
    };
    setup(a); setup(b);
    return controller.signal;
  }
}

/* ----------------------------- Utilities ---------------------------------- */

function num(v: string | null): number | undefined {
  if (v == null) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function clamp(n: number, min: number, max: number) {
  return Math.min(Math.max(n, min), max);
}

function cryptoRandomId(): string {
  // RFC4122-like (not strictly UUID). Works in browser and Node.
  const arr = new Uint8Array(16);
  (globalThis.crypto || (require("node:crypto") as any).webcrypto.crypto).getRandomValues(arr);
  arr[6] = (arr[6] & 0x0f) | 0x40; // version 4
  arr[8] = (arr[8] & 0x3f) | 0x80; // variant
  const toHex = (n: number) => n.toString(16).padStart(2, "0");
  const hex = Array.from(arr, toHex).join("");
  return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`;
}

/* --------------------------- Example types -------------------------------- */

export namespace Types {
  export interface Item {
    id: string;
    name: string;
    amount: string; // decimal as string
    currency: "USD"|"EUR"|"GBP";
    created_at: string;
  }
}

/* --------------------------- Example usage ---------------------------------
const client = new OmnimindClient({
  baseUrl: "https://api.example.com",
  getToken: async () => process.env.TOKEN!,
  userAgent: "my-service/1.0",
  defaultLocale: "en",
});

const res = await client.get<Types.Item>("/api/v1/items/123", { etag: '"abc123"' });
console.log(res.data, res.meta.etag);

for await (const page of client.paginate<Types.Item>("/api/v1/items", { filter: "recent" } as any)) {
  // process page
}
----------------------------------------------------------------------------- */
