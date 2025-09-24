// oblivionvault-core/sdks/typescript/src/client.ts
// Industrial-grade TypeScript SDK for OblivionVault-Core
// Requirements: global fetch & AbortController (browser, Node 18+ or polyfilled)

export type HTTPMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface Logger {
  debug: (...args: any[]) => void;
  info: (...args: any[]) => void;
  warn: (...args: any[]) => void;
  error: (...args: any[]) => void;
}

export interface CircuitBreakerOptions {
  failureThreshold: number;   // consecutive failures to open
  successThreshold: number;   // consecutive successes to close
  cooldownMs: number;         // time in OPEN before HALF_OPEN
}

export interface RateLimitOptions {
  maxRequests: number;
  perMs: number;
}

export interface ClientOptions {
  baseUrl: string;                         // e.g. https://api.oblivionvault.example
  getAccessToken?: () => Promise<string> | string;
  staticToken?: string;                    // alternative to getAccessToken
  timeoutMs?: number;                      // request timeout
  retries?: number;                        // max retries (default 2)
  retryBackoffMs?: number;                 // initial backoff (default 150ms)
  retryOn?: number[] | "idempotent";       // HTTP codes or "idempotent" preset
  circuitBreaker?: CircuitBreakerOptions;
  rateLimit?: RateLimitOptions;
  fetchFn?: typeof fetch;                  // custom fetch (if not global)
  defaultHeaders?: Record<string, string>;
  userAgent?: string;
  telemetry?: {
    traceparent?: string;                  // custom traceparent
    getTraceparent?: () => string;         // generator for traceparent
  };
  logger?: Logger;
}

export interface RequestOptions {
  query?: Record<string, any>;
  headers?: Record<string, string>;
  body?: any;                              // JSON body (object) or string
  form?: Record<string, string | Blob | File | undefined>; // multipart fields
  files?: Array<{ field: string; filename?: string; content: Blob | File }>;
  idempotencyKey?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  stream?: "sse" | "ndjson";               // streaming mode
  responseType?: "json" | "text" | "blob"; // default json
}

export class APIError<T = any> extends Error {
  public status: number;
  public code?: string;
  public requestId?: string;
  public details?: T;

  constructor(message: string, status: number, requestId?: string, code?: string, details?: T) {
    super(message);
    this.name = "APIError";
    this.status = status;
    this.requestId = requestId;
    this.code = code;
    this.details = details;
  }
}

/** Internal: Simple token bucket rate limiter */
class TokenBucket {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillPerMs: number;
  private lastRefill: number;

  constructor(opts: RateLimitOptions) {
    this.capacity = opts.maxRequests;
    this.tokens = opts.maxRequests;
    this.refillPerMs = opts.maxRequests / opts.perMs;
    this.lastRefill = Date.now();
  }

  async take(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.max(1, Math.ceil(1 / this.refillPerMs));
      await sleep(waitMs);
    }
  }

  private refill() {
    const now = Date.now();
    const delta = now - this.lastRefill;
    if (delta <= 0) return;
    const refill = delta * this.refillPerMs;
    this.tokens = Math.min(this.capacity, this.tokens + refill);
    this.lastRefill = now;
  }
}

/** Internal: Basic circuit breaker */
class CircuitBreaker {
  private state: "CLOSED" | "OPEN" | "HALF_OPEN" = "CLOSED";
  private failures = 0;
  private successes = 0;
  private nextTry = 0;

  constructor(private opts: CircuitBreakerOptions) {}

  canRequest(): boolean {
    if (this.state === "OPEN" && Date.now() >= this.nextTry) {
      this.state = "HALF_OPEN";
      this.failures = 0;
      this.successes = 0;
    }
    return this.state === "CLOSED" || this.state === "HALF_OPEN";
  }

  onSuccess() {
    if (this.state === "HALF_OPEN") {
      this.successes++;
      if (this.successes >= this.opts.successThreshold) {
        this.state = "CLOSED";
        this.failures = 0;
        this.successes = 0;
      }
    } else {
      this.failures = 0;
    }
  }

  onFailure() {
    this.failures++;
    if (this.state === "HALF_OPEN" || (this.state === "CLOSED" && this.failures >= this.opts.failureThreshold)) {
      this.state = "OPEN";
      this.nextTry = Date.now() + this.opts.cooldownMs;
      this.failures = 0;
      this.successes = 0;
    }
  }
}

/** Domain types (aligned with earlier schemas/protos, simplified) */
export namespace Domain {
  export type DataClass = "public" | "internal" | "confidential" | "restricted";

  export interface EvidenceDigest {
    alg: "sha256" | "sha512" | "blake2b-256";
    value: string;
  }

  export interface Attachment {
    name: string;
    mediaType: string;
    size_bytes: number;
    location: string; // s3://... or https://...
    digest: EvidenceDigest;
    encryption?: { type: "kms" | "age" | "pgp" | "none"; key_id?: string };
  }

  export interface Party {
    name: string;
    email?: string;
    org?: string;
    key_id?: string;
  }

  export interface Signature {
    type: "jws" | "pgp" | "x509";
    alg?: string;
    value?: string;
    detached?: boolean;
    canonicalization?: "jcs" | "rfc8785" | "sha256-tree" | "none";
    key_id?: string;
    public_key?: string;
    cert_chain?: string[];
    signer: Party;
    created_at: string; // RFC3339
    covers?: string[];
  }

  export interface CustodyEvent {
    event_id: string;
    time: string;
    action: "created" | "transferred" | "validated" | "sealed" | "unsealed" | "accessed" | "exported" | "destroyed";
    actor: Party;
    from?: Party;
    to?: Party;
    signature?: Signature;
    notes?: string;
  }

  export interface EvidencePackage {
    schema_version: string;
    id: string;
    created_at: string;
    updated_at?: string;
    environment?: "dev" | "stage" | "prod";
    producer: { system: string; component: string; version: string; build_id: string; runner?: string; contact?: string };
    subject: { type: string; id: string; data_class?: DataClass; jurisdictions?: string[]; annotations?: Record<string, string> };
    content?: { mediaType: string; encoding: "none" | "base64" | "utf8"; data?: string; size_bytes: number; digest?: EvidenceDigest };
    attachments?: Attachment[];
    sources: Array<{ type: string; endpoint?: string; method?: string; query?: string; actor?: Party; ip?: string; accessed_at: string }>;
    integrity: { digest: EvidenceDigest; algorithms?: EvidenceDigest["alg"][]; merkle_root?: string; canonicalization?: string };
    signatures: Signature[];
    attestations?: Array<{ type: "in-toto" | "slsa" | "sbom" | "other"; predicate_type: string; statement_uri?: string; digest?: EvidenceDigest }>;
    custody: { sealed?: boolean; current_custodian?: Party; events: CustodyEvent[] };
    retention?: { policy_id?: string; legal_hold?: boolean; due_time?: string; delete_method?: "soft" | "hard" };
    compliance?: { frameworks?: Array<{ name: string; version?: string }>; controls?: string[] };
    redaction?: { applied?: boolean; fields?: string[]; reason?: string; approved_by?: Party };
    references?: Array<{ type: string; id: string; uri?: string }>;
    labels?: Record<string, string>;
    notes?: string;
  }

  // Retention related (subset)
  export interface RecordContext {
    record_id: string;
    resource_type: string;
    data_class?: DataClass;
    labels?: Record<string, string>;
    pii_types?: string[];
    jurisdictions?: string[];
    environment?: "dev" | "stage" | "prod";
    created_at: string;
    last_modified_at?: string;
    last_accessed_at?: string;
    size_bytes?: number;
    legal_hold_active?: boolean;
  }

  export type RetentionAction = "DELETE" | "ANONYMIZE" | "QUARANTINE" | "ARCHIVE" | "RETAIN";
  export type DeleteMethod = "SOFT" | "HARD";

  export interface EvaluationDecision {
    decision_id: string;
    applicable: boolean;
    final_action: RetentionAction;
    delete_method?: DeleteMethod;
    anonymization_profile?: string;
    target_storage_class?: string;
    target_location?: string;
    due_time?: string;
    grace_period?: string;
    matched_rule_ids?: string[];
    matched_policy_id?: string;
    rationale?: string;
  }

  export interface EnforcementRequest {
    decision_id?: string;
    record_id?: string;
    override_action?: RetentionAction;
    actor?: string;
    request_time?: string;
  }

  export interface EnforcementResult {
    status: "APPLIED" | "SKIPPED" | "FAILED";
    applied_action?: RetentionAction;
    delete_method?: DeleteMethod;
    location?: string;
    action_time?: string;
    error_message?: string;
  }

  export interface RetentionPolicy {
    id: string;
    name: string;
    description?: string;
    version?: string;
    enabled: boolean;
    priority?: number;
    owner?: string;
    create_time?: string;
    update_time?: string;
    etag?: string;
    // rules omitted for brevity
  }

  export interface ListResponse<T> {
    items?: T[];
    data?: T[];
    results?: T[];
    next_page_token?: string;
    next?: string;
  }
}

// Utilities
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function toQuery(params?: Record<string, any>): string {
  if (!params) return "";
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null) return;
    if (Array.isArray(v)) v.forEach((x) => q.append(k, String(x)));
    else q.append(k, String(v));
  });
  const s = q.toString();
  return s ? `?${s}` : "";
}

function makeUlidLike(): string {
  // Lightweight ULID-like (not spec-perfect, but sortable and unique enough)
  const t = Date.now().toString(36).toUpperCase();
  const r = [...cryptoRandom(16)].map((n) => "0123456789ABCDEFGHJKMNPQRSTVWXYZ"[n % 32]).join("");
  return (t + r).slice(0, 26);
}

function cryptoRandom(len: number): Uint8Array {
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    const a = new Uint8Array(len);
    globalThis.crypto.getRandomValues(a);
    return a;
  }
  // Fallback: not cryptographically strong
  const a = new Uint8Array(len);
  for (let i = 0; i < len; i++) a[i] = Math.floor(Math.random() * 256);
  return a;
}

function makeTraceparent(): string {
  // W3C traceparent: version 00, 16-byte trace-id, 8-byte parent-id, flags 01
  const bytes = cryptoRandom(24);
  const hex = (u: Uint8Array) => Array.from(u).map((b) => b.toString(16).padStart(2, "0")).join("");
  const traceId = hex(bytes.slice(0, 16));
  const parentId = hex(bytes.slice(16, 24));
  return `00-${traceId}-${parentId}-01`;
}

function parseRetryAfter(h: string | null): number | null {
  if (!h) return null;
  const s = Number(h);
  if (!Number.isNaN(s)) return Math.max(0, s * 1000);
  const t = Date.parse(h);
  if (!Number.isNaN(t)) return Math.max(0, t - Date.now());
  return null;
}

/** The main SDK client */
export class OblivionVaultClient {
  private readonly baseUrl: string;
  private readonly getAccessToken?: () => Promise<string> | string;
  private readonly staticToken?: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly retryBackoffMs: number;
  private readonly retryOn: number[] | "idempotent";
  private readonly fetchFn: typeof fetch;
  private readonly defaultHeaders: Record<string, string>;
  private readonly userAgent?: string;
  private readonly telemetry?: ClientOptions["telemetry"];
  private readonly logger: Logger;
  private readonly breaker?: CircuitBreaker;
  private readonly limiter?: TokenBucket;

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new Error("baseUrl is required");
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.getAccessToken = opts.getAccessToken;
    this.staticToken = opts.staticToken;
    this.timeoutMs = opts.timeoutMs ?? 15000;
    this.retries = Math.max(0, opts.retries ?? 2);
    this.retryBackoffMs = opts.retryBackoffMs ?? 150;
    this.retryOn = opts.retryOn ?? "idempotent";
    this.fetchFn = opts.fetchFn ?? globalThis.fetch?.bind(globalThis);
    if (!this.fetchFn) throw new Error("fetch is not available; provide fetchFn");
    this.defaultHeaders = opts.defaultHeaders ?? {};
    this.userAgent = opts.userAgent;
    this.telemetry = opts.telemetry;
    this.logger = opts.logger ?? console;

    if (opts.circuitBreaker) this.breaker = new CircuitBreaker(opts.circuitBreaker);
    if (opts.rateLimit) this.limiter = new TokenBucket(opts.rateLimit);
  }

  // ===== Low-level request =====
  async request<T = any>(method: HTTPMethod, path: string, options: RequestOptions = {}): Promise<T> {
    const url = this.baseUrl + path + toQuery(options.query);
    const headers: Record<string, string> = {
      Accept: "application/json",
      "X-Request-ID": makeUlidLike(),
      ...this.defaultHeaders,
      ...(options.headers ?? {}),
    };

    if (this.userAgent) headers["User-Agent"] = this.userAgent;

    // Auth
    const token = await this.resolveToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    // Trace
    headers["traceparent"] =
      this.telemetry?.traceparent ??
      (typeof this.telemetry?.getTraceparent === "function" ? this.telemetry.getTraceparent() : makeTraceparent());

    // Idempotency for mutating safe operations
    if ((method === "POST" || method === "PUT" || method === "PATCH") && !headers["Idempotency-Key"]) {
      const key = options.idempotencyKey ?? makeUlidLike();
      headers["Idempotency-Key"] = key;
    }

    // Body / Multipart
    let body: BodyInit | undefined;
    if (options.form || options.files?.length) {
      const fd = new FormData();
      if (options.form) {
        for (const [k, v] of Object.entries(options.form)) {
          if (v === undefined) continue;
          fd.append(k, v as any);
        }
      }
      if (options.files) {
        for (const f of options.files) {
          fd.append(f.field, f.content as any, f.filename);
        }
      }
      body = fd as any;
    } else if (options.body != null) {
      if (typeof options.body === "string") {
        headers["Content-Type"] ||= "application/json; charset=utf-8";
        body = options.body;
      } else {
        headers["Content-Type"] ||= "application/json; charset=utf-8";
        body = JSON.stringify(options.body);
      }
    }

    // Timeouts & signals
    const controller = new AbortController();
    const timeout = options.timeoutMs ?? this.timeoutMs;
    const timer = setTimeout(() => controller.abort(new DOMException("Timeout","AbortError")), timeout);
    const signal = anySignal([controller.signal, options.signal]);

    // Rate limit
    if (this.limiter) await this.limiter.take();

    // Retry loop with backoff
    let attempt = 0;
    let lastErr: any;
    const startTs = Date.now();

    while (attempt <= this.retries) {
      attempt++;
      if (this.breaker && !this.breaker.canRequest()) {
        clearTimeout(timer);
        throw new APIError("Circuit breaker is OPEN", 503);
      }

      try {
        const res = await this.fetchFn(url, { method, headers, body, signal });
        const reqId = res.headers.get("x-request-id") ?? headers["X-Request-ID"] ?? undefined;

        // Streaming
        if (options.stream) {
          if (!res.ok) {
            const errBody = await safeParseJson(res);
            throw new APIError(errMessage(res, errBody), res.status, reqId, (errBody as any)?.code, errBody);
          }
          clearTimeout(timer);
          // Return as any: for SSE/NDJSON caller should pass through stream()
          return (res as unknown) as T;
        }

        // Normal response
        const respType = options.responseType ?? "json";
        let payload: any = undefined;
        if (respType === "json") payload = await safeParseJson(res);
        else if (respType === "text") payload = await res.text();
        else if (respType === "blob") payload = await res.blob();

        if (!res.ok) {
          // Decide on retry
          if (this.shouldRetry(method, res.status)) {
            const ra = parseRetryAfter(res.headers.get("retry-after"));
            const backoff = ra ?? backoffMs(this.retryBackoffMs, attempt);
            this.logger.warn(`[SDK] retry ${attempt}/${this.retries} after status ${res.status} in ${backoff}ms`);
            await sleep(backoff);
            continue;
          }
          throw new APIError(errMessage(res, payload), res.status, reqId, (payload as any)?.code, payload);
        }

        this.breaker?.onSuccess();
        clearTimeout(timer);
        return payload as T;
      } catch (err: any) {
        lastErr = err;
        const isAbort = err?.name === "AbortError";
        const maybeNetwork = err instanceof TypeError || isAbort;

        if (!maybeNetwork) {
          // Treat as non-retryable application error
          this.breaker?.onFailure();
          clearTimeout(timer);
          if (err instanceof APIError) throw err;
          throw new APIError(String(err?.message ?? "Unknown error"), 500, undefined, undefined, err);
        }

        // network/abort: retry only if allowed
        if (attempt <= this.retries) {
          this.breaker?.onFailure();
          const wait = backoffMs(this.retryBackoffMs, attempt);
          this.logger.warn(`[SDK] network error, retry ${attempt}/${this.retries} in ${wait}ms: ${err?.message}`);
          await sleep(wait);
          continue;
        } else {
          this.breaker?.onFailure();
          clearTimeout(timer);
          throw new APIError(`Network error after ${attempt} attempts: ${err?.message}`, 503);
        }
      } finally {
        // guard: ensure timeout cleared on any return path (except streaming path handled above)
        if (Date.now() - startTs >= timeout) {
          try { clearTimeout(timer); } catch {}
        }
      }
    }

    clearTimeout(timer);
    if (lastErr) throw lastErr;
    throw new APIError("Unknown failure", 500);
  }

  // ===== High-level helpers =====
  get<T = any>(path: string, opts?: RequestOptions) { return this.request<T>("GET", path, opts); }
  post<T = any>(path: string, opts?: RequestOptions) { return this.request<T>("POST", path, opts); }
  put<T = any>(path: string, opts?: RequestOptions) { return this.request<T>("PUT", path, opts); }
  patch<T = any>(path: string, opts?: RequestOptions) { return this.request<T>("PATCH", path, opts); }
  delete<T = any>(path: string, opts?: RequestOptions) { return this.request<T>("DELETE", path, opts); }

  /** Async iterator for paginated endpoints. It tries several common shapes. */
  async *paginate<T = any>(path: string, query: Record<string, any> = {}, pageSize = 100): AsyncGenerator<T, void, unknown> {
    let q = { ...query, page_size: query.page_size ?? pageSize };
    let next: string | undefined;
    for (;;) {
      const resp = await this.get<Domain.ListResponse<T>>(next ?? path, { query: next ? undefined : q });
      const items = resp.items ?? resp.data ?? resp.results ?? [];
      for (const it of items) yield it;

      if (resp.next_page_token) {
        q = { ...q, page_token: resp.next_page_token };
        continue;
      }
      if (resp.next && resp.next.startsWith("/")) {
        next = resp.next;
        continue;
      }
      // Try Link header pattern on last response via internal (not available here) — best effort only
      break;
    }
  }

  /** Stream NDJSON or SSE. Returns the native Response. Use helpers below to consume. */
  stream(path: string, mode: "ndjson" | "sse", opts: Omit<RequestOptions, "stream"> = {}) {
    return this.request<Response>("GET", path, { ...opts, stream: mode, responseType: "text" as any });
  }

  // ===== Domain: Evidence Packages =====
  async createEvidencePackage(pkg: Domain.EvidencePackage): Promise<Domain.EvidencePackage> {
    return this.post<Domain.EvidencePackage>("/v1/evidence-packages", { body: pkg });
  }

  async getEvidencePackage(id: string): Promise<Domain.EvidencePackage> {
    return this.get<Domain.EvidencePackage>(`/v1/evidence-packages/${encodeURIComponent(id)}`);
  }

  async *listEvidencePackages(query: { page_size?: number; from?: string; to?: string } = {}) {
    yield* this.paginate<Domain.EvidencePackage>("/v1/evidence-packages", query, query.page_size ?? 100);
  }

  async uploadEvidenceAttachment(evidenceId: string, files: Array<{ field: string; filename?: string; content: Blob | File }>, extra?: Record<string, string>) {
    return this.post<{ ok: true }>(`/v1/evidence-packages/${encodeURIComponent(evidenceId)}/attachments:upload`, {
      form: extra,
      files
    });
  }

  // ===== Domain: Retention =====
  evaluateRetention(record: Domain.RecordContext): Promise<Domain.EvaluationDecision> {
    return this.post<Domain.EvaluationDecision>("/v1/retention:evaluate", { body: { record } });
  }

  enforceRetention(req: Domain.EnforcementRequest): Promise<Domain.EnforcementResult> {
    return this.post<Domain.EnforcementResult>("/v1/retention:enforce", { body: req });
  }

  createPolicy(policy: Domain.RetentionPolicy): Promise<Domain.RetentionPolicy> {
    return this.post<Domain.RetentionPolicy>("/v1/retention/policies", { body: policy });
  }

  getPolicy(id: string): Promise<Domain.RetentionPolicy> {
    return this.get<Domain.RetentionPolicy>(`/v1/retention/policies/${encodeURIComponent(id)}`);
  }

  updatePolicy(policy: Domain.RetentionPolicy, ifMatchEtag?: string): Promise<Domain.RetentionPolicy> {
    return this.put<Domain.RetentionPolicy>(`/v1/retention/policies/${encodeURIComponent(policy.id)}`, {
      body: policy,
      headers: ifMatchEtag ? { "If-Match": ifMatchEtag } : undefined
    });
  }

  deletePolicy(id: string, allowMissing = true): Promise<{ id: string; deleted: boolean }> {
    return this.delete<{ id: string; deleted: boolean }>(`/v1/retention/policies/${encodeURIComponent(id)}`, {
      query: { allow_missing: allowMissing }
    });
  }

  async *listPolicies(query: { page_size?: number; only_enabled?: boolean; owner?: string } = {}) {
    yield* this.paginate<Domain.RetentionPolicy>("/v1/retention/policies", query, query.page_size ?? 100);
  }

  // ===== Streaming helpers =====
  /** Consume NDJSON Response as async iterator of parsed objects */
  static async *ndjson<T = any>(resp: Response): AsyncGenerator<T, void, unknown> {
    const reader = resp.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        yield JSON.parse(line) as T;
      }
    }
    if (buf.trim()) yield JSON.parse(buf) as T;
  }

  /** Consume SSE Response as async iterator of {event?, data} */
  static async *sse(resp: Response): AsyncGenerator<{ event?: string; data: string }, void, unknown> {
    const reader = resp.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let event: string | undefined;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let data = "";
        event = undefined;
        for (const line of chunk.split("\n")) {
          const trimmed = line.replace(/\r$/, "");
          if (trimmed.startsWith("data:")) data += trimmed.slice(5).trim() + "\n";
          else if (trimmed.startsWith("event:")) event = trimmed.slice(6).trim();
        }
        yield { event, data: data.replace(/\n$/, "") };
      }
    }
  }

  // ===== Internal helpers =====
  private async resolveToken(): Promise<string | undefined> {
    if (this.staticToken) return this.staticToken;
    if (!this.getAccessToken) return undefined;
    const t = this.getAccessToken;
    return typeof t === "function" ? await t() : t;
  }

  private shouldRetry(method: HTTPMethod, status: number): boolean {
    const idempotent = method === "GET" || method === "HEAD" || method === "OPTIONS" || method === "DELETE";
    if (this.retryOn === "idempotent") {
      return idempotent ? (status >= 500 || status === 429) : status === 429;
    }
    return this.retryOn.includes(status);
  }
}

function anySignal(signals: Array<AbortSignal | undefined>) {
  const actual = signals.filter(Boolean) as AbortSignal[];
  if (actual.length === 0) return undefined;
  // Use AbortController to combine
  const c = new AbortController();
  const onAbort = (s: AbortSignal) => {
    if (!c.signal.aborted) c.abort(s.reason);
  };
  for (const s of actual) {
    if (s.aborted) return s;
    s.addEventListener("abort", () => onAbort(s), { once: true });
  }
  return c.signal;
}

async function safeParseJson(res: Response): Promise<any> {
  const txt = await res.text();
  if (!txt) return undefined;
  try { return JSON.parse(txt); } catch { return { message: txt }; }
}

function errMessage(res: Response, body: any): string {
  const generic = `HTTP ${res.status}`;
  if (!body) return generic;
  if (typeof body === "string") return `${generic}: ${body}`;
  return body.message ?? body.error ?? generic;
}

function backoffMs(base: number, attempt: number): number {
  const cap = 3000;
  const exp = Math.min(cap, base * Math.pow(2, attempt - 1));
  const jitter = Math.random() * base;
  return Math.min(cap, Math.floor(exp + jitter));
}
