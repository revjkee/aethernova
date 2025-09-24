// physical-integration-core/sdks/typescript/src/client.ts
/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Industrial-grade TypeScript SDK client for physical-integration-core.
 * Zero external dependencies. Works in Node (>=18) and modern browsers.
 *
 * Features:
 * - Resilient networking: retries with exponential backoff + jitter, circuit breaker, token-bucket rate limiter
 * - Auth: static Bearer or async TokenProvider; Idempotency-Key for POST
 * - Observability: before/after hooks, timings, breaker state events
 * - SSE subscriptions (EventSource in browser, injectable in Node)
 * - Domain methods: policy evaluateCommand, sendCommand, ingest segment/chunk, twins/events/metrics queries
 * - Pagination helpers, typed results, safe JSON parsing
 */

//////////////////////////
// Public type contracts
//////////////////////////

export interface TokenProvider {
  (): Promise<string | null> | string | null;
}

export interface Logger {
  debug?(msg: string, meta?: any): void;
  info?(msg: string, meta?: any): void;
  warn?(msg: string, meta?: any): void;
  error?(msg: string, meta?: any): void;
}

export interface RetryPolicy {
  maxAttempts: number;       // total tries including the first
  baseDelayMs: number;       // initial backoff
  maxDelayMs: number;        // cap
  multiplier: number;        // exponential factor
  jitter: number;            // 0..1
  retryOnHttp: number[];     // e.g. [408, 429, 500, 502, 503, 504]
  retryOnNetworkErrors: boolean; // DNS reset, timeouts, aborted, etc.
  methods: Array<"GET"|"HEAD"|"PUT"|"DELETE"|"OPTIONS"|"TRACE"|"POST"|"PATCH">; // which methods are retryable
}

export interface CircuitBreakerOptions {
  failureThreshold: number;          // % failures to open
  minimumThroughput: number;         // min samples to evaluate
  rollingWindowMs: number;           // window size
  halfOpenAfterMs: number;           // cooldown
  halfOpenMaxCalls: number;          // trial calls
}

export interface RateLimitOptions {
  tokensPerSecond: number;
  burst: number;
}

export interface ObservabilityHooks {
  beforeRequest?(ctx: RequestContext): void | Promise<void>;
  afterResponse?(ctx: ResponseContext): void | Promise<void>;
  onError?(ctx: ErrorContext): void | Promise<void>;
  onCircuitStateChange?(state: "closed"|"open"|"half-open"): void;
}

export interface ClientOptions {
  baseUrl: string;                       // e.g. https://pic.api.company/v1
  timeoutMs?: number;                    // per-request timeout
  token?: string;                        // static Bearer
  tokenProvider?: TokenProvider;         // dynamic Bearer
  defaultHeaders?: Record<string,string>;
  retry?: Partial<RetryPolicy>;
  breaker?: Partial<CircuitBreakerOptions>;
  rateLimit?: Partial<RateLimitOptions>;
  idempotencyForPost?: boolean;          // attach Idempotency-Key for POST automatically
  fetchImpl?: typeof fetch;              // optional custom fetch (Node: undici fetch by default)
  eventSourceImpl?: any;                 // optional EventSource constructor (Node)
  logger?: Logger;
  // Advanced: custom decision whether a response is retryable
  isRetryableResponse?(res: Response): boolean;
}

export interface RequestContext {
  url: string;
  method: string;
  headers: Record<string,string>;
  body?: any;
  startTime: number;
  attempt: number;
  idempotencyKey?: string;
}

export interface ResponseContext extends RequestContext {
  status: number;
  ok: boolean;
  durationMs: number;
  responseHeaders: Headers;
}

export interface ErrorContext extends RequestContext {
  error: any;
  durationMs: number;
}

export interface Page<T> {
  items: T[];
  nextPageToken?: string;
}

//////////////////////////
// Policy / Command types
//////////////////////////

export interface PolicyDecision {
  policy_id: string;
  version: string;
  allow: boolean;
  breakglass_used?: boolean;
  required_approvals?: number;
  impact_level?: string;
  deny_hard?: string[] | Record<string,unknown>;
  deny_soft?: string[] | Record<string,unknown>;
  deny_reasons?: string[] | Record<string,unknown>;
}

export interface EvaluateCommandInput {
  // Mirrors the Rego input shape; kept generic to avoid tight coupling.
  authn: Record<string, any>;
  authz: Record<string, any>;
  env: Record<string, any>;
  request: Record<string, any>;
  context?: Record<string, any>;
}

export interface CommandRequest {
  twinId: string;
  command: string;
  args?: Record<string, any>;
  impactLevel?: "low"|"medium"|"high"|"critical";
  ticket?: { id: string; };
}

export interface CommandResponse {
  accepted: boolean;
  decision: PolicyDecision;
  commandId?: string;
  reasons?: string[];
}

//////////////////////////
// Ingest types
//////////////////////////

export interface UploadSegmentOptions {
  contentType?: string;      // e.g. video/mp4 or application/octet-stream
  idempotencyKey?: string;   // if omitted and idempotencyForPost=true, auto-generated
  metadata?: Record<string, any>;
  timeoutMs?: number;
}

//////////////////////////
// Utilities
//////////////////////////

const DEFAULT_RETRY: RetryPolicy = {
  maxAttempts: 6,
  baseDelayMs: 200,
  maxDelayMs: 20_000,
  multiplier: 2,
  jitter: 0.2,
  retryOnHttp: [408, 409, 425, 429, 500, 502, 503, 504],
  retryOnNetworkErrors: true,
  methods: ["GET","HEAD","PUT","DELETE","OPTIONS","TRACE","POST","PATCH"]
};

const DEFAULT_BREAKER: CircuitBreakerOptions = {
  failureThreshold: 50,         // 50%
  minimumThroughput: 20,
  rollingWindowMs: 30_000,
  halfOpenAfterMs: 30_000,
  halfOpenMaxCalls: 5
};

const DEFAULT_RATELIMIT: RateLimitOptions = {
  tokensPerSecond: 20,
  burst: 40
};

function nowMs() { return Date.now(); }

function sleep(ms: number) {
  return new Promise(res => setTimeout(res, ms));
}

function backoffDelay(policy: RetryPolicy, attempt: number): number {
  const expo = policy.baseDelayMs * Math.pow(policy.multiplier, attempt - 1);
  const capped = Math.min(expo, policy.maxDelayMs);
  const jitter = capped * policy.jitter * (Math.random() * 2 - 1);
  return Math.max(0, Math.floor(capped + jitter));
}

function randomUUID(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    // @ts-ignore
    return crypto.randomUUID();
  }
  // RFC4122 v4 fallback
  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i=0;i<16;i++) bytes[i] = Math.floor(Math.random()*256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex: string[] = [];
  for (let b of bytes) hex.push((b + 0x100).toString(16).slice(1));
  return `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-${hex[6]}${hex[7]}-${hex[8]}${hex[9]}-${hex[10]}${hex[11]}${hex[12]}${hex[13]}${hex[14]}${hex[15]}`;
}

//////////////////////////
// Circuit Breaker
//////////////////////////

class CircuitBreaker {
  private failures = 0;
  private successes = 0;
  private state: "closed"|"open"|"half-open" = "closed";
  private openedAt = 0;
  private halfOpenCalls = 0;

  constructor(private opts: CircuitBreakerOptions, private hooks?: ObservabilityHooks) {}

  onSuccess() {
    if (this.state === "half-open") {
      this.state = "closed";
      this.failures = 0; this.successes = 1; this.halfOpenCalls = 0;
      this.hooks?.onCircuitStateChange?.("closed");
      return;
    }
    this.successes++;
  }

  onFailure() {
    if (this.state === "half-open") {
      this.state = "open";
      this.openedAt = nowMs();
      this.halfOpenCalls = 0;
      this.hooks?.onCircuitStateChange?.("open");
      return;
    }
    this.failures++;
    const total = this.failures + this.successes;
    if (total >= this.opts.minimumThroughput) {
      const failureRate = (this.failures / total) * 100;
      if (failureRate >= this.opts.failureThreshold) {
        this.state = "open";
        this.openedAt = nowMs();
        this.hooks?.onCircuitStateChange?.("open");
      }
    }
  }

  canRequest(): boolean {
    if (this.state === "open") {
      if (nowMs() - this.openedAt >= this.opts.halfOpenAfterMs) {
        this.state = "half-open";
        this.halfOpenCalls = 0;
        this.hooks?.onCircuitStateChange?.("half-open");
        return true;
      }
      return false;
    }
    if (this.state === "half-open") {
      if (this.halfOpenCalls < this.opts.halfOpenMaxCalls) {
        this.halfOpenCalls++;
        return true;
      }
      return false;
    }
    return true;
  }
}

//////////////////////////
// Token Bucket limiter
//////////////////////////

class TokenBucket {
  private tokens: number;
  private lastRefill: number;

  constructor(private opts: RateLimitOptions) {
    this.tokens = opts.burst;
    this.lastRefill = nowMs();
  }

  async take(count = 1) {
    while (true) {
      this.refill();
      if (this.tokens >= count) {
        this.tokens -= count;
        return;
      }
      const need = count - this.tokens;
      // time to wait until enough tokens
      const perTokenMs = 1000 / this.opts.tokensPerSecond;
      const waitMs = Math.max(perTokenMs * need, 5);
      await sleep(waitMs);
    }
  }

  private refill() {
    const now = nowMs();
    const delta = now - this.lastRefill;
    if (delta <= 0) return;
    const add = (delta / 1000) * this.opts.tokensPerSecond;
    this.tokens = Math.min(this.opts.burst, this.tokens + add);
    this.lastRefill = now;
  }
}

//////////////////////////
// ApiError with helpers
//////////////////////////

export class ApiError extends Error {
  constructor(
    message: string,
    public status?: number,
    public response?: any
  ) {
    super(message);
    this.name = "ApiError";
  }

  isRetryable(policy: RetryPolicy): boolean {
    if (this.status) {
      return policy.retryOnHttp.includes(this.status);
    }
    // network or unknown error
    return policy.retryOnNetworkErrors;
  }
}

//////////////////////////
// HttpClient
//////////////////////////

class HttpClient {
  private fetch: typeof fetch;
  private retry: RetryPolicy;
  private breaker: CircuitBreaker;
  private limiter: TokenBucket;
  private idempotencyForPost: boolean;
  private isRetryableResponse?: (res: Response) => boolean;

  constructor(private opts: ClientOptions, private hooks?: ObservabilityHooks) {
    this.fetch = opts.fetchImpl ?? fetch;
    this.retry = { ...DEFAULT_RETRY, ...(opts.retry ?? {}) };
    this.breaker = new CircuitBreaker({ ...DEFAULT_BREAKER, ...(opts.breaker ?? {}) }, hooks);
    this.limiter = new TokenBucket({ ...DEFAULT_RATELIMIT, ...(opts.rateLimit ?? {}) });
    this.idempotencyForPost = opts.idempotencyForPost ?? true;
    this.isRetryableResponse = opts.isRetryableResponse;
  }

  private async authHeader(): Promise<Record<string,string>> {
    const h: Record<string,string> = {};
    const token = this.opts.token ?? (await this.opts.tokenProvider?.());
    if (token) h["Authorization"] = `Bearer ${token}`;
    return h;
  }

  async request<T>(method: string, path: string, body?: any, init?: RequestInit & { timeoutMs?: number; idempotencyKey?: string; }): Promise<T> {
    const url = this.joinUrl(path);
    const policy = this.retry;
    const canRetryMethod = policy.methods.includes(method as any);

    let lastError: any = null;

    for (let attempt = 1; attempt <= policy.maxAttempts; attempt++) {
      if (!this.breaker.canRequest()) {
        lastError = new ApiError("Circuit breaker is OPEN", 503);
        this.hooks?.onError?.({
          url, method, headers: {}, startTime: 0, attempt, error: lastError, durationMs: 0
        });
        throw lastError;
      }

      await this.limiter.take(1);

      const idempotencyKey =
        init?.idempotencyKey ??
        (method === "POST" && this.idempotencyForPost ? randomUUID() : undefined);

      const headers: Record<string,string> = {
        "Accept": "application/json",
        ...(body && !(body instanceof Blob) && !(body instanceof ArrayBuffer) && !(body instanceof Uint8Array) ? { "Content-Type": "application/json" } : {}),
        ...(await this.authHeader()),
        ...(this.opts.defaultHeaders ?? {}),
        ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {})
      };

      const controller = new AbortController();
      const timeout = init?.timeoutMs ?? this.opts.timeoutMs ?? 30_000;
      const t = setTimeout(() => controller.abort(), timeout);

      const start = nowMs();
      const ctx: RequestContext = { url, method, headers, body, startTime: start, attempt, idempotencyKey };
      try {
        await this.hooks?.beforeRequest?.(ctx);

        const res = await this.fetch(url, {
          method,
          headers,
          body: body == null ? undefined : (headers["Content-Type"] === "application/json" ? JSON.stringify(body) : body),
          signal: controller.signal,
          keepalive: method === "GET", // hint for browsers
          ...init
        });

        const duration = nowMs() - start;

        const respCtx: ResponseContext = {
          ...ctx,
          status: res.status,
          ok: res.ok,
          durationMs: duration,
          responseHeaders: res.headers
        };
        await this.hooks?.afterResponse?.(respCtx);

        if (!res.ok) {
          // decide if retryable by policy or user function
          const errPayload = await safeParseJson(res).catch(() => undefined);
          const apiErr = new ApiError(`HTTP ${res.status} ${res.statusText}`, res.status, errPayload);
          const retryable = canRetryMethod && (this.isRetryableResponse?.(res) ?? apiErr.isRetryable(policy));
          if (retryable && attempt < policy.maxAttempts) {
            this.breaker.onFailure();
            clearTimeout(t);
            await sleep(backoffDelay(policy, attempt));
            continue;
          }
          this.breaker.onFailure();
          clearTimeout(t);
          throw apiErr;
        }

        // success
        this.breaker.onSuccess();
        clearTimeout(t);

        // parse JSON if any
        const ct = res.headers.get("content-type") || "";
        if (ct.includes("application/json")) {
          return (await res.json()) as T;
        }
        // return text or empty as-is
        const text = await res.text();
        return (text ? (JSON.parse(text) as T) : (undefined as unknown as T));

      } catch (err: any) {
        clearTimeout(t);
        lastError = wrapNetworkError(err);

        const duration = nowMs() - start;
        await this.hooks?.onError?.({ ...ctx, error: lastError, durationMs: duration });

        const retryable = canRetryMethod && policy.retryOnNetworkErrors;
        if (retryable && attempt < policy.maxAttempts) {
          this.breaker.onFailure();
          await sleep(backoffDelay(policy, attempt));
          continue;
        }
        this.breaker.onFailure();
        throw lastError;
      }
    }

    throw lastError ?? new ApiError("Unknown error");
  }

  private joinUrl(path: string): string {
    const base = this.opts.baseUrl.replace(/\/+$/,"");
    const p = path.startsWith("/") ? path : `/${path}`;
    return base + p;
  }
}

function wrapNetworkError(err: any): ApiError {
  if (err?.name === "AbortError") return new ApiError("Request timed out");
  if (err instanceof ApiError) return err;
  return new ApiError(err?.message ?? "Network error");
}

async function safeParseJson(res: Response): Promise<any> {
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return undefined;
  try { return await res.json(); } catch { return undefined; }
}

//////////////////////////
// PhysicalIntegrationClient
//////////////////////////

export class PhysicalIntegrationClient {
  private http: HttpClient;
  private hooks?: ObservabilityHooks;
  private eventSourceCtor?: any;
  private log: Logger;

  constructor(private opts: ClientOptions, hooks?: ObservabilityHooks) {
    this.hooks = hooks;
    this.http = new HttpClient(opts, hooks);
    this.eventSourceCtor = opts.eventSourceImpl ?? (typeof EventSource !== "undefined" ? EventSource : undefined);
    this.log = opts.logger ?? {};
  }

  /** Healthcheck */
  async health(): Promise<{ status: "ok"|"degraded"|"down"; version?: string; }> {
    return this.http.request("GET", "/health");
  }

  /** Get StreamDescriptor (matches video.proto service) */
  async getStreamDescriptor(streamId: string): Promise<any> {
    return this.http.request("GET", `/streams/${encodeURIComponent(streamId)}/descriptor`);
  }

  /** Upload a video segment (HTTP fallback path for gRPC ingest); supports idempotency */
  async uploadSegment(streamId: string, payload: ArrayBuffer | Uint8Array | Blob, opts: UploadSegmentOptions = {}): Promise<{ accepted: boolean; segmentIndex?: number; }> {
    const body = payload instanceof Blob ? payload : (payload instanceof Uint8Array ? payload : new Uint8Array(payload));
    const headers: Record<string,string> = {};
    if (opts.contentType) headers["Content-Type"] = opts.contentType;

    return this.http.request("POST", `/ingest/streams/${encodeURIComponent(streamId)}/segments`, body, {
      headers,
      idempotencyKey: opts.idempotencyKey,
      timeoutMs: opts.timeoutMs
    });
  }

  /** Upload chunk (smaller part) */
  async uploadChunk(streamId: string, chunkIndex: number, data: ArrayBuffer | Uint8Array | Blob, opts: UploadSegmentOptions = {}): Promise<{ accepted: boolean; lastCommittedIndex?: number; }> {
    const body = data instanceof Blob ? data : (data instanceof Uint8Array ? data : new Uint8Array(data));
    const headers: Record<string,string> = {};
    if (opts.contentType) headers["Content-Type"] = opts.contentType;

    return this.http.request("POST", `/ingest/streams/${encodeURIComponent(streamId)}/chunks/${chunkIndex}`, body, {
      headers,
      idempotencyKey: opts.idempotencyKey,
      timeoutMs: opts.timeoutMs
    });
  }

  /** Commit segment/chunks (aligns with CommitSegment in proto) */
  async commit(streamId: string, upToIndex: number, aggregateChecksum?: { type: string; value: string }, retention?: any): Promise<{ status: string; lastCommittedIndex?: number; }> {
    return this.http.request("POST", `/ingest/streams/${encodeURIComponent(streamId)}/commit`, {
      stream_id: streamId,
      up_to_index: upToIndex,
      aggregate_checksum: aggregateChecksum,
      retention
    });
  }

  /** Evaluate a command via OPA/Policy adapter (command_guard.rego) */
  async evaluateCommand(input: EvaluateCommandInput): Promise<PolicyDecision> {
    const decision = await this.http.request<PolicyDecision>("POST", "/policy/command/decide", input);
    // Minimal structural validation
    if (typeof decision?.allow !== "boolean") {
      throw new ApiError("Malformed PolicyDecision: 'allow' is missing or not boolean");
    }
    return decision;
  }

  /** Send command after policy evaluation; will deny if policy says no */
  async sendCommand(req: CommandRequest, policyInput: EvaluateCommandInput): Promise<CommandResponse> {
    const decision = await this.evaluateCommand(policyInput);
    if (!decision.allow) {
      return { accepted: false, decision, reasons: normalizeReasons(decision) };
    }
    const res = await this.http.request<{ commandId: string }>("POST", `/twins/${encodeURIComponent(req.twinId)}/commands`, {
      command: req.command,
      args: req.args ?? {},
      impact_level: req.impactLevel ?? "low",
      ticket: req.ticket ?? null
    });
    return { accepted: true, decision, commandId: res.commandId };
  }

  /** Get latest twin state */
  async getTwinLatestState(twinId: string): Promise<any> {
    return this.http.request("GET", `/twins/${encodeURIComponent(twinId)}/state:latest`);
  }

  /** Query events with time range and pagination */
  async queryEvents(params: { twinId?: string; type?: string; severity?: string; from?: string; to?: string; pageToken?: string; pageSize?: number; }): Promise<Page<any>> {
    const q = new URLSearchParams();
    if (params.twinId) q.set("twinId", params.twinId);
    if (params.type) q.set("type", params.type);
    if (params.severity) q.set("severity", params.severity);
    if (params.from) q.set("from", params.from);
    if (params.to) q.set("to", params.to);
    if (params.pageToken) q.set("pageToken", params.pageToken);
    if (params.pageSize) q.set("pageSize", String(params.pageSize));
    return this.http.request("GET", `/events?${q.toString()}`);
  }

  /** Query metrics in a time window */
  async getMetrics(twinId: string, metric: string, fromIso: string, toIso: string, agg?: "raw"|"min"|"max"|"avg"|"p50"|"p90"|"p99"): Promise<Page<any>> {
    const q = new URLSearchParams({ metric, from: fromIso, to: toIso });
    if (agg) q.set("agg", agg);
    return this.http.request("GET", `/twins/${encodeURIComponent(twinId)}/metrics?${q.toString()}`);
  }

  /** SSE subscribe to a topic (e.g., command updates, telemetry) */
  subscribe(path: string, onMessage: (data: any) => void, onError?: (e: any) => void): { close: () => void } {
    if (!this.eventSourceCtor) {
      throw new Error("No EventSource implementation available. Provide ClientOptions.eventSourceImpl in Node.");
    }
    const url = this.joinUrl(path);
    const headers: Record<string, string> = {};
    // inject bearer into query when EventSource cannot set headers (browser)
    const token = this.opts.token ?? null;
    const qs = new URLSearchParams();
    if (token) qs.set("access_token", token);
    const full = token ? `${url}${url.includes("?") ? "&" : "?"}${qs.toString()}` : url;

    const es = new this.eventSourceCtor(full);
    es.onmessage = (ev: MessageEvent<any>) => {
      try {
        const data = typeof ev.data === "string" ? JSON.parse(ev.data) : ev.data;
        onMessage(data);
      } catch (e) {
        this.log.warn?.("SSE parse error", { error: e });
      }
    };
    es.onerror = (e: any) => {
      onError?.(e);
    };
    return { close: () => es.close() };
  }

  /////////////////////////
  // Helpers
  /////////////////////////

  private joinUrl(path: string): string {
    const base = this.opts.baseUrl.replace(/\/+$/,"");
    const p = path.startsWith("/") ? path : `/${path}`;
    return base + p;
  }

  /** Static factory with optional hooks */
  static create(opts: ClientOptions, hooks?: ObservabilityHooks): PhysicalIntegrationClient {
    return new PhysicalIntegrationClient(opts, hooks);
  }
}

function normalizeReasons(decision: PolicyDecision): string[] {
  const acc: string[] = [];
  const push = (r: any) => {
    if (typeof r === "string") acc.push(r);
    else if (r && typeof r === "object") acc.push(JSON.stringify(r));
  };
  if (Array.isArray(decision.deny_reasons)) decision.deny_reasons.forEach(push);
  if (Array.isArray(decision.deny_hard)) decision.deny_hard.forEach(push);
  if (Array.isArray(decision.deny_soft)) decision.deny_soft.forEach(push);
  return Array.from(new Set(acc));
}

//////////////////////////
// Example default hooks
//////////////////////////

export const DefaultHooks: ObservabilityHooks = {
  onCircuitStateChange: (s) => {
    // eslint-disable-next-line no-console
    console.warn(`[PIC SDK] Circuit state -> ${s}`);
  },
  beforeRequest: (ctx) => {
    (globalLogger.info ?? noop)(`HTTP ${ctx.method} ${ctx.url}`, { attempt: ctx.attempt });
  },
  afterResponse: (ctx) => {
    (globalLogger.debug ?? noop)(`HTTP ${ctx.method} ${ctx.url} -> ${ctx.status} in ${ctx.durationMs}ms`);
  },
  onError: (ctx) => {
    (globalLogger.error ?? noop)(`HTTP ${ctx.method} ${ctx.url} failed in ${ctx.durationMs}ms: ${ctx.error?.message}`, { attempt: ctx.attempt });
  }
};

const globalLogger: Logger = {
  info: (...args: any[]) => { if (typeof console !== "undefined") (console as any).info?.(...args); },
  debug: (...args: any[]) => { if (typeof console !== "undefined") (console as any).debug?.(...args); },
  warn:  (...args: any[]) => { if (typeof console !== "undefined") (console as any).warn?.(...args); },
  error: (...args: any[]) => { if (typeof console !== "undefined") (console as any).error?.(...args); }
};

function noop() { /* no-op */ }
