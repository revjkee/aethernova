/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Policy Core TypeScript SDK (industrial edition)
 * - Zero external deps. Works in Node 18+ and modern browsers.
 * - Timeouts with AbortController.
 * - Retries with exponential backoff + jitter for transient failures.
 * - Circuit Breaker (CLOSED -> OPEN -> HALF_OPEN).
 * - Integrity SHA-256 helper for request bodies.
 * - Idempotency and correlation headers.
 */

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

export interface ClientOptions {
  baseUrl: string;                 // e.g. https://api.policy.example.com
  apiKey?: string;                 // Bearer token if used
  tenantId?: string;               // Optional multitenancy header
  defaultHeaders?: Record<string, string>;
  timeoutMs?: number;              // per request timeout
  retries?: number;                // max retry attempts on transient errors
  retryBackoffMs?: number;         // base backoff
  retryJitter?: boolean;           // add jitter to backoff
  breaker?: Partial<CircuitBreakerOptions>;
  fetchImpl?: typeof fetch;        // custom fetch for older runtimes
}

export interface CircuitBreakerOptions {
  failureThreshold: number;        // consecutive failures to OPEN
  halfOpenMaxCalls: number;        // allowed trial calls in HALF_OPEN
  openStateDurationMs: number;     // how long to stay OPEN before HALF_OPEN
}

export type BreakerState = "CLOSED" | "OPEN" | "HALF_OPEN";

export class CircuitBreaker {
  private opts: CircuitBreakerOptions;
  private state: BreakerState = "CLOSED";
  private failures = 0;
  private openedAt = 0;
  private halfOpenCalls = 0;

  constructor(opts?: Partial<CircuitBreakerOptions>) {
    this.opts = {
      failureThreshold: opts?.failureThreshold ?? 5,
      halfOpenMaxCalls: opts?.halfOpenMaxCalls ?? 2,
      openStateDurationMs: opts?.openStateDurationMs ?? 10_000,
    };
  }

  public getState(): BreakerState {
    if (this.state === "OPEN") {
      const elapsed = Date.now() - this.openedAt;
      if (elapsed >= this.opts.openStateDurationMs) {
        this.state = "HALF_OPEN";
        this.halfOpenCalls = 0;
      }
    }
    return this.state;
  }

  public onSuccess(): void {
    this.failures = 0;
    this.state = "CLOSED";
    this.halfOpenCalls = 0;
  }

  public onFailure(): void {
    if (this.state === "HALF_OPEN") {
      this.trip();
      return;
    }
    this.failures += 1;
    if (this.failures >= this.opts.failureThreshold) {
      this.trip();
    }
  }

  public canProceed(): boolean {
    const s = this.getState();
    if (s === "OPEN") return false;
    if (s === "HALF_OPEN") {
      if (this.halfOpenCalls >= this.opts.halfOpenMaxCalls) return false;
      this.halfOpenCalls += 1;
      return true;
    }
    return true;
  }

  private trip() {
    this.state = "OPEN";
    this.openedAt = Date.now();
  }
}

/* ========================= Types for Decision API ========================= */

export type DecisionEffect = "Permit" | "Deny";
export type ExplainMode = "off" | "summary" | "full";

export interface DecisionRequest<
  SubjectAttrs extends Record<string, any> = Record<string, any>,
  ResourceAttrs extends Record<string, any> = Record<string, any>
> {
  apiVersion: "policy-core/v1";
  kind: "DecisionRequest";
  requestId?: string; // optional client generated
  timestamp?: string; // ISO-8601
  tenant?: { id: string; environment?: string };
  correlationId?: string;
  idempotencyKey?: string;
  policy?: {
    set?: string;
    revision?: string;
    eval?: {
      timeoutMs?: number;
      explain?: ExplainMode | "trace" | "full";
      trace?: boolean;
      returnObligations?: boolean;
    };
  };
  subject: {
    id: string;
    type?: string;
    roles?: string[];
    groups?: string[];
    attributes?: SubjectAttrs;
    mfa?: {
      presented?: boolean;
      methods?: string[];
      lastVerifiedAt?: string;
    };
    [k: string]: any;
  };
  resource: {
    id: string;
    type: string;
    urn?: string;
    ownerId?: string;
    collection?: string;
    path?: string;
    labels?: Record<string, string>;
    classification?: string;
    createdAt?: string;
    attributes?: ResourceAttrs;
    [k: string]: any;
  };
  action: {
    name: string;
    operation?: "read" | "write" | "create" | "update" | "delete" | "list" | "approve" | "execute" | "admin" | string;
    http?: { method?: string; path?: string };
    [k: string]: any;
  };
  context?: {
    purposeOfUse?: string;
    justification?: string;
    channel?: string;
    originApp?: string;
    requestIp?: string;
    location?: { country?: string; city?: string; lat?: number; lon?: number };
    device?: {
      id?: string;
      os?: { name?: string; version?: string };
      managed?: boolean;
      trustedNetwork?: boolean;
      posture?: Record<string, any>;
    };
    session?: { id?: string; startedAt?: string; expiresAt?: string };
    risk?: { score?: number; level?: "low" | "medium" | "high"; signals?: string[] };
    jurisdiction?: string[];
    dataResidency?: string;
    requestTime?: string;
    timezone?: string;
    [k: string]: any;
  };
  constraints?: {
    dataFilter?: {
      allowFields?: string[];
      masking?: Array<{ field: string; method: "hash" | "redact" | "last4" | "custom"; params?: Record<string, any> }>;
      rowLevel?: { where?: string } | { language?: "cel" | "sql"; expr: string };
    };
    obligations?: Array<{ on: DecisionEffect | "Any"; type: string; params?: Record<string, any> }>;
  };
  cache?: { allow?: boolean; ttlSeconds?: number; keyParts?: string[] };
  requestedDecisions?: Array<"permit" | "explain" | "obligations">;
  ext?: Record<string, any>;
  integrity?: { alg?: "sha256"; hash: string };
}

export interface DecisionResponse {
  apiVersion: "policy-core/v1";
  kind: "DecisionResponse";
  requestId: string;
  correlationId?: string;
  decision: DecisionEffect;
  obligations?: Array<{ on: DecisionEffect | "Any"; type: string; params?: Record<string, any> }>;
  explain?: {
    mode: ExplainMode | "full";
    traceId?: string;
    summary?: string;
    rulesFired?: string[];
  };
  cache?: { hit?: boolean; ttlRemainingSeconds?: number };
  policy?: { set?: string; revision?: string };
  meta?: {
    receivedAt?: string;
    processedAt?: string;
    processingTimeMs?: number;
  };
}

export interface BatchDecisionResponse {
  apiVersion: "policy-core/v1";
  kind: "DecisionBatchResponse";
  items: Array<{
    index: number;
    requestId?: string;
    status: number;
    body?: DecisionResponse;
    error?: ApiErrorBody;
  }>;
}

export interface ApiErrorBody {
  error: string;
  message?: string;
  code?: string;
  requestId?: string;
  details?: any;
}

/* ================================ Errors ================================== */

export class PolicyCoreError extends Error {
  public status?: number;
  public body?: ApiErrorBody;
  public requestId?: string;
  public correlationId?: string;
  constructor(message: string, opts?: { status?: number; body?: ApiErrorBody; requestId?: string; correlationId?: string }) {
    super(message);
    this.name = "PolicyCoreError";
    this.status = opts?.status;
    this.body = opts?.body;
    this.requestId = opts?.requestId ?? opts?.body?.requestId;
    this.correlationId = opts?.correlationId;
  }
}

/* ============================== Utilities ================================= */

const isTransientStatus = (s: number) => s === 408 || s === 429 || (s >= 500 && s <= 599);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function computeBackoff(attempt: number, base: number, jitter: boolean): number {
  const exp = Math.min(attempt, 6); // cap growth
  const delay = base * Math.pow(2, exp); // 0,1,2 -> base, 2*base, 4*base...
  if (!jitter) return delay;
  const rand = Math.random() * delay * 0.2; // up to 20 percent jitter
  return delay - delay * 0.1 + rand; // between 90 percent and 110 percent of delay
}

function safeJsonParse<T = any>(text: string): T | undefined {
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}

function normalizeBaseUrl(u: string): string {
  return u.endsWith("/") ? u.slice(0, -1) : u;
}

function pickFetch(custom?: typeof fetch): typeof fetch {
  if (custom) return custom;
  if (typeof fetch !== "undefined") return fetch;
  throw new Error("No fetch implementation found. Provide ClientOptions.fetchImpl for Node < 18.");
}

/* Web Crypto helpers */

async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const subtle = getSubtle();
  const digest = await subtle.digest("SHA-256", data);
  return buf2hex(new Uint8Array(digest));
}

function getSubtle(): SubtleCrypto {
  if (typeof globalThis !== "undefined" && (globalThis as any).crypto?.subtle) {
    return (globalThis as any).crypto.subtle as SubtleCrypto;
  }
  // Node.js fallback
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { webcrypto } = require("crypto");
    return webcrypto.subtle as SubtleCrypto;
  } catch {
    throw new Error("Web Crypto API is not available. For Node < 16.5, install a polyfill or upgrade.");
  }
}

function buf2hex(buf: Uint8Array): string {
  let s = "";
  for (let i = 0; i < buf.length; i++) s += buf[i].toString(16).padStart(2, "0");
  return s;
}

function randomUUID(): string {
  if (typeof crypto !== "undefined" && (crypto as any).randomUUID) {
    return (crypto as any).randomUUID();
  }
  // RFC4122 v4 polyfill using Web Crypto
  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && (crypto as any).getRandomValues) {
    (crypto as any).getRandomValues(bytes);
  } else {
    // Node fallback
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { randomFillSync } = require("crypto");
    randomFillSync(bytes);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/* =============================== The Client =============================== */

export class PolicyCoreClient {
  private baseUrl: string;
  private apiKey?: string;
  private tenantId?: string;
  private headers: Record<string, string>;
  private timeoutMs: number;
  private retries: number;
  private retryBackoffMs: number;
  private retryJitter: boolean;
  private fetchImpl: typeof fetch;
  private breaker: CircuitBreaker;

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new Error("baseUrl is required");
    this.baseUrl = normalizeBaseUrl(opts.baseUrl);
    this.apiKey = opts.apiKey;
    this.tenantId = opts.tenantId;
    this.headers = {
      "Content-Type": "application/json",
      "Accept": "application/json",
      ...(opts.defaultHeaders ?? {}),
    };
    if (this.apiKey) this.headers["Authorization"] = `Bearer ${this.apiKey}`;
    if (this.tenantId) this.headers["X-Tenant-ID"] = this.tenantId;

    this.timeoutMs = opts.timeoutMs ?? 2000;
    this.retries = Math.max(0, opts.retries ?? 2);
    this.retryBackoffMs = Math.max(50, opts.retryBackoffMs ?? 200);
    this.retryJitter = opts.retryJitter ?? true;
    this.fetchImpl = pickFetch(opts.fetchImpl);
    this.breaker = new CircuitBreaker(opts.breaker);
  }

  /**
   * Compute integrity SHA-256 hex of a JSON-serializable payload.
   */
  public async computeIntegrity(payload: unknown): Promise<string> {
    const json = JSON.stringify(payload);
    return sha256Hex(json);
  }

  /**
   * Perform a policy decision call.
   */
  public async decide<TSub extends Record<string, any> = Record<string, any>, TRes extends Record<string, any> = Record<string, any>>(
    request: DecisionRequest<TSub, TRes>,
    opts?: { idempotencyKey?: string; correlationId?: string; signal?: AbortSignal }
  ): Promise<DecisionResponse> {
    const body = this.prepareDecisionRequest(request, opts);
    return this.request<DecisionResponse>("/v1/decide", "POST", body, {
      idempotencyKey: body.idempotencyKey,
      correlationId: body.correlationId,
      timeoutMs: request.policy?.eval?.timeoutMs ?? this.timeoutMs,
      signal: opts?.signal,
    });
  }

  /**
   * Perform a batch policy decision call.
   */
  public async decideBatch(
    requests: DecisionRequest[],
    opts?: { correlationId?: string; signal?: AbortSignal }
  ): Promise<BatchDecisionResponse> {
    const items = requests.map((r) => this.prepareDecisionRequest(r, undefined));
    return this.request<BatchDecisionResponse>("/v1/decide:batch", "POST", { items }, {
      correlationId: opts?.correlationId ?? randomUUID(),
      timeoutMs: this.timeoutMs,
      signal: opts?.signal,
    });
  }

  /**
   * Health check endpoint.
   */
  public async health(): Promise<{ status: "ok" | "degraded" | "down"; version?: string; revision?: string }> {
    return this.request("/health", "GET");
  }

  /* ============================ Private internals ============================ */

  private prepareDecisionRequest(req: DecisionRequest, opt?: { idempotencyKey?: string; correlationId?: string }): DecisionRequest {
    const now = new Date().toISOString();
    return {
      apiVersion: "policy-core/v1",
      kind: "DecisionRequest",
      ...req,
      requestId: req.requestId ?? randomUUID(),
      correlationId: opt?.correlationId ?? req.correlationId ?? randomUUID(),
      idempotencyKey: opt?.idempotencyKey ?? req.idempotencyKey ?? this.deriveIdempotencyKey(req),
      timestamp: req.timestamp ?? now,
    };
  }

  private deriveIdempotencyKey(req: DecisionRequest): string {
    // A simple deterministic key using stable parts; callers can override.
    const parts = [
      req.tenant?.id ?? "",
      req.subject?.id ?? "",
      req.action?.name ?? "",
      req.resource?.type ?? "",
      req.resource?.id ?? "",
    ].join("|");
    // If subtle is available, hash parts; otherwise fall back to randomUUID.
    try {
      const enc = new TextEncoder().encode(parts);
      // Note: intentionally not awaited here; but we need a sync key. Use random if crypto not sync.
      // Return a simple prefix plus randomUUID to guarantee uniqueness.
      return `idem-${parts.slice(0, 40)}-${randomUUID()}`;
    } catch {
      return `idem-${randomUUID()}`;
    }
  }

  private async request<T = any>(
    path: string,
    method: HttpMethod,
    body?: unknown,
    meta?: { idempotencyKey?: string; correlationId?: string; timeoutMs?: number; signal?: AbortSignal }
  ): Promise<T> {
    if (!this.breaker.canProceed()) {
      throw new PolicyCoreError("Circuit breaker is OPEN", { status: 503 });
    }

    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = { ...this.headers };
    if (meta?.idempotencyKey) headers["Idempotency-Key"] = meta.idempotencyKey;
    if (meta?.correlationId) headers["X-Correlation-ID"] = meta.correlationId;

    const maxAttempts = 1 + this.retries;
    let lastErr: unknown;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      // Timeout control
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(new DOMException("Timeout", "AbortError")), meta?.timeoutMs ?? this.timeoutMs);
      const signal = this.mergeSignals(controller.signal, meta?.signal);

      try {
        const res = await this.fetchImpl(url, {
          method,
          headers,
          body: body !== undefined && method !== "GET" ? JSON.stringify(body) : undefined,
          signal,
        } as RequestInit);

        const requestId = res.headers.get("x-request-id") ?? undefined;
        const correlationId = res.headers.get("x-correlation-id") ?? undefined;

        if (res.ok) {
          const txt = await res.text();
          const json = txt ? safeJsonParse<T>(txt) : (undefined as any);
          this.breaker.onSuccess();
          // Update rate limit info if needed. Users can read headers via getRateLimitFromHeaders if we expose it later.
          return json ?? ({} as T);
        }

        // Non-2xx: try to parse error
        const errText = await res.text();
        const errBody = errText ? safeJsonParse<ApiErrorBody>(errText) : undefined;
        const isTransient = isTransientStatus(res.status);

        if (isTransient && attempt < maxAttempts - 1) {
          await this.backoff(attempt);
          continue;
        }

        // Fatal error
        this.breaker.onFailure();
        throw new PolicyCoreError(
          errBody?.message ?? `HTTP ${res.status} ${res.statusText}`,
          { status: res.status, body: errBody, requestId, correlationId }
        );
      } catch (e: any) {
        lastErr = e;
        // Abort and network errors
        const isAbort = e?.name === "AbortError";
        const isNet = e?.name === "TypeError" || e?.code === "ECONNRESET";
        if ((isAbort || isNet) && attempt < maxAttempts - 1) {
          await this.backoff(attempt);
          continue;
        }
        this.breaker.onFailure();
        if (e instanceof PolicyCoreError) throw e;
        throw new PolicyCoreError(e?.message ?? "Network error", {});
      } finally {
        clearTimeout(timeout);
      }
    }

    // If we are here, retries exhausted
    if (lastErr instanceof Error) throw lastErr;
    throw new PolicyCoreError("Unknown error after retries", {});
  }

  private async backoff(attempt: number): Promise<void> {
    const delay = computeBackoff(attempt, this.retryBackoffMs, this.retryJitter);
    await sleep(delay);
  }

  private mergeSignals(a: AbortSignal, b?: AbortSignal): AbortSignal {
    if (!b) return a;
    // Composite signal: abort when either aborts
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    if (a.aborted || b.aborted) {
      controller.abort();
      return controller.signal;
    }
    a.addEventListener("abort", onAbort, { once: true });
    b.addEventListener("abort", onAbort, { once: true });
    return controller.signal;
  }
}

/* ============================== Example Usage ==============================

import { PolicyCoreClient } from "./client";

const client = new PolicyCoreClient({
  baseUrl: "https://api.policy.example.com",
  apiKey: process.env.POLICY_TOKEN,
  tenantId: "acme",
  timeoutMs: 1500,
  retries: 2,
});

const req: DecisionRequest = {
  apiVersion: "policy-core/v1",
  kind: "DecisionRequest",
  subject: { id: "user:42", attributes: { department: "finance" } },
  resource: { id: "invoice:2025/08/INV-000123", type: "invoice", attributes: { amount: 1999.99 } },
  action: { name: "approve" },
};

const integrity = await client.computeIntegrity(req);
req.integrity = { alg: "sha256", hash: integrity };

const res = await client.decide(req);
console.log(res.decision);

============================================================================= */
