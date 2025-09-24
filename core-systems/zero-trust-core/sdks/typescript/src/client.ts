// file: zero-trust-core/sdks/typescript/src/client.ts
/* eslint-disable no-console */
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface RetryPolicy {
  attempts: number;           // total attempts including the first
  baseDelayMs: number;        // initial backoff
  maxDelayMs: number;         // cap on backoff
  retryOnStatuses?: number[]; // default: 408, 425, 429, 500-599
}

export interface Telemetry {
  app: string;
  version: string;
}

export interface ClientConfig {
  baseUrl: string;                          // e.g. "https://ztc.example.com/api/v1"
  defaultHeaders?: Record<string, string>;  // extra headers
  timeoutMs?: number;                       // per-request timeout
  retry?: RetryPolicy;                      // retry policy
  telemetry?: Telemetry;                    // X-Client header
  fetchImpl?: typeof fetch;                 // custom fetch (Node polyfill if needed)
  eventSourceImpl?: typeof EventSource;     // custom EventSource (for SSE in Node or special env)
  requestIdHeader?: string;                 // default "X-Request-ID"
  generateIdempotencyKey?: () => string;    // custom idempotency key generator
  authProvider?: AuthProvider | null;       // token provider (optional)
}

export interface AuthProvider {
  getAccessToken(): Promise<string | null> | string | null;
  refresh?(): Promise<boolean>; // return true if refreshed
  clear?(): void;
}

export interface RequestOptions {
  method?: HttpMethod;
  query?: Record<string, string | number | boolean | undefined | null>;
  headers?: Record<string, string>;
  json?: unknown;           // serialized as JSON if provided
  body?: BodyInit;          // use raw body instead of json
  etag?: string | null;     // If-Match header
  idempotency?: boolean;    // adds Idempotency-Key for unsafe methods
  timeoutMs?: number;       // overrides config
  signal?: AbortSignal;     // external cancellation
  retryPolicy?: RetryPolicy;// overrides config
}

export interface ResponseEnvelope<T> {
  data: T;
  status: number;
  headers: Headers;
  etag: string | null;
  requestId: string | null;
}

export class HttpError<T = unknown> extends Error {
  readonly status: number;
  readonly data: T | null;
  readonly headers: Headers;
  readonly requestId: string | null;
  constructor(message: string, status: number, data: T | null, headers: Headers) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.data = data;
    this.headers = headers;
    this.requestId = headers.get("X-Request-ID");
  }
}

export class TimeoutError extends Error {
  constructor(message = "Request timed out") {
    super(message);
    this.name = "TimeoutError";
  }
}

// Utilities
function hasFetch(cfg: ClientConfig): cfg is ClientConfig & { fetchImpl: typeof fetch } {
  return typeof (cfg.fetchImpl ?? globalThis.fetch) === "function";
}

function randId(len = 32): string {
  const g = (globalThis as any).crypto;
  if (g?.getRandomValues) {
    const a = new Uint8Array(len);
    g.getRandomValues(a);
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let s = "";
    for (let i = 0; i < len; i++) s += alphabet[a[i] % alphabet.length];
    return s;
  }
  // Fallback
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

function jitteredBackoff(attempt: number, base: number, cap: number): number {
  // Exponential backoff with full jitter
  const exp = Math.min(cap, base * Math.pow(2, attempt - 1));
  return Math.floor(Math.random() * exp);
}

function buildQuery(q?: RequestOptions["query"]): string {
  if (!q) return "";
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null) continue;
    sp.append(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

function normalizeRetryPolicy(p?: RetryPolicy): Required<RetryPolicy> {
  const rp = p ?? { attempts: 3, baseDelayMs: 200, maxDelayMs: 2000 };
  const retryOn = rp.retryOnStatuses ?? [];
  return {
    attempts: Math.max(1, rp.attempts ?? 3),
    baseDelayMs: Math.max(1, rp.baseDelayMs ?? 200),
    maxDelayMs: Math.max(rp.baseDelayMs ?? 200, rp.maxDelayMs ?? 2000),
    retryOnStatuses: retryOn.length ? retryOn : [408, 425, 429, 500, 502, 503, 504]
  };
}

function isJsonContent(h: Headers): boolean {
  const ct = (h.get("Content-Type") || "").toLowerCase();
  return ct.includes("application/json") || ct.endsWith("+json");
}

export class ZeroTrustCoreClient {
  readonly cfg: Required<Omit<ClientConfig,
    "authProvider" | "defaultHeaders" | "timeoutMs" | "retry" | "requestIdHeader" |
    "telemetry" | "fetchImpl" | "eventSourceImpl" | "generateIdempotencyKey">> & {
      authProvider: AuthProvider | null;
      defaultHeaders: Record<string, string>;
      timeoutMs: number;
      retry: Required<RetryPolicy>;
      requestIdHeader: string;
      telemetry: Telemetry | null;
      fetchImpl: typeof fetch;
      eventSourceImpl: typeof EventSource | null;
      generateIdempotencyKey: () => string;
    };

  constructor(config: ClientConfig) {
    if (!config || !config.baseUrl) {
      throw new Error("baseUrl is required");
    }
    const fetchImpl = config.fetchImpl ?? (globalThis.fetch as any);
    if (typeof fetchImpl !== "function") {
      throw new Error("fetch implementation not found. Pass fetchImpl in ClientConfig for Node < 18");
    }
    this.cfg = {
      baseUrl: config.baseUrl.replace(/\/+$/, ""),
      authProvider: config.authProvider ?? null,
      defaultHeaders: { ...(config.defaultHeaders ?? {}) },
      timeoutMs: Math.max(1000, config.timeoutMs ?? 8000),
      retry: normalizeRetryPolicy(config.retry),
      telemetry: config.telemetry ?? null,
      requestIdHeader: config.requestIdHeader ?? "X-Request-ID",
      fetchImpl,
      eventSourceImpl: config.eventSourceImpl ?? (typeof EventSource !== "undefined" ? EventSource : null),
      generateIdempotencyKey: config.generateIdempotencyKey ?? (() =>
        (globalThis.crypto?.randomUUID?.() ?? `idem_${randId(24)}`))
    };
  }

  // Core request
  async request<T = unknown>(path: string, opts: RequestOptions = {}): Promise<ResponseEnvelope<T>> {
    const method: HttpMethod = opts.method ?? "GET";
    const qp = buildQuery(opts.query);
    const url = path.startsWith("http") ? path : `${this.cfg.baseUrl}/${path.replace(/^\/+/, "")}${qp}`;

    // headers
    const headers = new Headers(this.cfg.defaultHeaders);
    headers.set("Accept", "application/json");
    if (this.cfg.telemetry) {
      headers.set("X-Client", `${this.cfg.telemetry.app}/${this.cfg.telemetry.version}`);
    }
    const reqId = randId(16);
    if (this.cfg.requestIdHeader) headers.set(this.cfg.requestIdHeader, reqId);
    if (opts.etag) headers.set("If-Match", opts.etag);
    if (opts.idempotency && method !== "GET") headers.set("Idempotency-Key", this.cfg.generateIdempotencyKey());
    if (opts.headers) for (const [k, v] of Object.entries(opts.headers)) headers.set(k, v);

    // body
    let body: BodyInit | undefined = undefined;
    if (opts.body != null && opts.json != null) {
      throw new Error("Provide either json or body, not both");
    }
    if (opts.json != null) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(opts.json);
    } else if (opts.body != null) {
      body = opts.body;
    }

    // auth
    const applyAuth = async () => {
      if (!this.cfg.authProvider) return;
      const token = await this.cfg.authProvider.getAccessToken();
      if (token) headers.set("Authorization", `Bearer ${token}`);
    };
    await applyAuth();

    const timeoutMs = Math.max(1000, opts.timeoutMs ?? this.cfg.timeoutMs);
    const retry = normalizeRetryPolicy(opts.retryPolicy ?? this.cfg.retry);

    let lastErr: unknown = null;

    for (let attempt = 1; attempt <= retry.attempts; attempt++) {
      // timeout + external signal composition
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new TimeoutError().message), timeoutMs);
      const signal = controller.signal;

      try {
        const res = await this.cfg.fetchImpl(url, { method, headers, body, signal, credentials: "include", cache: "no-store" });

        // 401 handling with optional refresh
        if (res.status === 401 && this.cfg.authProvider?.refresh) {
          const ok = await this.cfg.authProvider.refresh();
          if (ok) {
            headers.delete("Authorization");
            await applyAuth();
            clearTimeout(timer);
            // retry immediately without counting as extra attempt
            attempt--;
            continue;
          }
        }

        if (this.shouldRetry(res.status, retry.retryOnStatuses)) {
          if (attempt < retry.attempts) {
            clearTimeout(timer);
            await this.delay(jitteredBackoff(attempt, retry.baseDelayMs, retry.maxDelayMs));
            continue;
          }
        }

        const etag = res.headers.get("ETag");
        const reqIdResp = res.headers.get(this.cfg.requestIdHeader) ?? res.headers.get("X-Request-ID");

        let parsed: any = null;
        if (res.status !== 204) {
          if (isJsonContent(res.headers)) {
            // tolerate malformed or empty bodies safely
            const txt = await res.text();
            parsed = txt ? JSON.parse(txt) : null;
          } else {
            parsed = await res.text();
          }
        }

        if (!res.ok) {
          throw new HttpError(`HTTP ${res.status}`, res.status, parsed, res.headers);
        }

        clearTimeout(timer);
        return { data: parsed as T, status: res.status, headers: res.headers, etag, requestId: reqIdResp };
      } catch (err: any) {
        lastErr = err;
        clearTimeout(timer);
        // Abort or Timeout are not retriable beyond policy
        const timeout = err instanceof TimeoutError || (err?.name === "AbortError");
        // HttpError retry
        const http = err instanceof HttpError ? err : null;

        if (http && this.shouldRetry(http.status, retry.retryOnStatuses) && attempt < retry.attempts) {
          await this.delay(jitteredBackoff(attempt, retry.baseDelayMs, retry.maxDelayMs));
          continue;
        }
        if (!http && !timeout && attempt < retry.attempts) {
          await this.delay(jitteredBackoff(attempt, retry.baseDelayMs, retry.maxDelayMs));
          continue;
        }
        // give up
        if (http) throw http;
        if (timeout) throw new TimeoutError();
        throw err;
      }
    }

    // Should not reach here
    throw lastErr instanceof Error ? lastErr : new Error("Request failed");
  }

  private shouldRetry(status: number, retryOn: number[]): boolean {
    return retryOn.includes(status) || (status >= 500 && status <= 599);
  }

  private async delay(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }

  // Convenience helpers
  get<T = unknown>(path: string, opts: Omit<RequestOptions, "method"> = {}) {
    return this.request<T>(path, { ...opts, method: "GET" });
  }
  post<T = unknown>(path: string, opts: Omit<RequestOptions, "method"> = {}) {
    return this.request<T>(path, { ...opts, method: "POST" });
  }
  put<T = unknown>(path: string, opts: Omit<RequestOptions, "method"> = {}) {
    return this.request<T>(path, { ...opts, method: "PUT" });
  }
  patch<T = unknown>(path: string, opts: Omit<RequestOptions, "method"> = {}) {
    return this.request<T>(path, { ...opts, method: "PATCH" });
  }
  delete<T = unknown>(path: string, opts: Omit<RequestOptions, "method"> = {}) {
    return this.request<T>(path, { ...opts, method: "DELETE" });
  }

  // SSE (Server-Sent Events)
  sse(path: string, options: {
    query?: Record<string, string | number | boolean | undefined | null>;
    headers?: Record<string, string>;
    onMessage: (event: MessageEvent) => void;
    onError?: (ev: Event) => void;
    onOpen?: (ev: Event) => void;
  }): EventSource {
    if (!this.cfg.eventSourceImpl) {
      throw new Error("EventSource is not available. Provide eventSourceImpl in ClientConfig");
    }
    const qp = buildQuery(options.query);
    const url = path.startsWith("http") ? path : `${this.cfg.baseUrl}/${path.replace(/^\/+/, "")}${qp}`;
    const ES = this.cfg.eventSourceImpl;
    // Note: headers support requires polyfilled EventSource; native doesn't accept custom headers.
    const es = new ES(url);
    if (options.onOpen) es.addEventListener("open", options.onOpen);
    es.addEventListener("message", options.onMessage);
    if (options.onError) es.addEventListener("error", options.onError);
    return es;
  }

  // Cursor paginator helper (key set by API; example name "next_page_cursor"). I cannot verify this.
  async *cursorPaginate<TItem = unknown>(path: string, params: {
    pageSize?: number; cursorParamName?: string; nextCursorField?: string;
    query?: Record<string, string | number | boolean | undefined | null>;
    stopAfter?: number; // safety cap
  } = {}): AsyncGenerator<TItem[], void, unknown> {
    const pageSize = params.pageSize ?? 100;
    const cursorParamName = params.cursorParamName ?? "page_cursor";
    const nextCursorField = params.nextCursorField ?? "next_page_cursor";
    const stopAfter = params.stopAfter ?? 1000;

    let cursor: string | undefined = undefined;
    let yielded = 0;
    while (yielded < stopAfter) {
      const query = { ...(params.query ?? {}), page_size: pageSize, ...(cursor ? { [cursorParamName]: cursor } : {}) };
      const { data } = await this.get<any>(path, { query });
      const items: TItem[] = Array.isArray(data?.items) ? data.items : [];
      yield items;
      yielded += 1;
      const next = (data && typeof data === "object") ? data[nextCursorField] : null;
      if (!next) break;
      cursor = String(next);
    }
  }
}

/**
 * Static token provider: stores a Bearer token in memory only.
 * For ephemeral runtime use; for PKCE/OIDC supply a custom provider.
 */
export class StaticTokenAuth implements AuthProvider {
  private token: string | null;
  constructor(token: string | null) { this.token = token; }
  getAccessToken(): string | null { return this.token; }
  setToken(token: string | null) { this.token = token; }
  refresh(): Promise<boolean> { return Promise.resolve(false); }
  clear() { this.token = null; }
}

/**
 * Minimal OIDC PKCE helper (browser-focused).
 * Stores refresh token in sessionStorage; access token in memory.
 * I cannot verify specific endpoint paths of your IdP.
 */
export class OidcPkceAuth implements AuthProvider {
  private accessToken: string | null = null;
  private idToken: string | null = null;
  private readonly key = "ztc.oidc.pkce.v1";
  constructor(private cfg: {
    issuer: string;
    clientId: string;
    redirectUri: string;
    scope?: string;
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
    storage?: Storage; // default sessionStorage
  }) {
    this.cfg.storage = this.cfg.storage ?? globalThis.sessionStorage;
  }
  getAccessToken(): string | null {
    return this.accessToken;
  }
  clear() {
    this.accessToken = null;
    this.idToken = null;
    this.cfg.storage?.removeItem(this.key);
  }
  async startLogin(stateExtra?: Record<string, string>) {
    const state = randId(24);
    const verifier = randId(64);
    const challenge = await this.sha256B64Url(verifier);
    this.cfg.storage?.setItem(this.key, JSON.stringify({ state, verifier, ts: Date.now() }));
    const params = new URLSearchParams({
      client_id: this.cfg.clientId,
      redirect_uri: this.cfg.redirectUri,
      response_type: "code",
      scope: this.cfg.scope ?? "openid profile email offline_access",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state
    });
    if (stateExtra) for (const [k, v] of Object.entries(stateExtra)) params.append(k, v);
    const authz = this.cfg.authorizationEndpoint ?? `${this.cfg.issuer.replace(/\/+$/, "")}/protocol/openid-connect/auth`;
    globalThis.location.assign(`${authz}?${params.toString()}`);
  }
  async completeLogin(urlParams: URLSearchParams): Promise<void> {
    const store = this.cfg.storage?.getItem(this.key);
    if (!store) throw new Error("PKCE state not found");
    const { state, verifier } = JSON.parse(store);
    if (urlParams.get("state") !== state) throw new Error("PKCE state mismatch");
    const code = urlParams.get("code");
    if (!code) throw new Error("code missing");
    const tokenUrl = this.cfg.tokenEndpoint ?? `${this.cfg.issuer.replace(/\/+$/, "")}/protocol/openid-connect/token`;
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: this.cfg.clientId,
      redirect_uri: this.cfg.redirectUri,
      code_verifier: verifier
    });
    const res = await fetch(tokenUrl, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
    if (!res.ok) throw new Error(`OIDC token exchange failed: ${res.status}`);
    const t = await res.json();
    this.accessToken = t.access_token || null;
    this.idToken = t.id_token || null;
    this.cfg.storage?.setItem(this.key, JSON.stringify({ state, verifier, ts: Date.now(), refresh_token: t.refresh_token || null }));
    // strip code/state from URL
    const u = new URL(globalThis.location.href);
    u.searchParams.delete("code");
    u.searchParams.delete("state");
    if (globalThis.history?.replaceState) globalThis.history.replaceState({}, globalThis.document?.title ?? "", u.toString());
  }
  async refresh(): Promise<boolean> {
    const store = this.cfg.storage?.getItem(this.key);
    if (!store) return false;
    const { refresh_token } = JSON.parse(store);
    if (!refresh_token) return false;
    const tokenUrl = this.cfg.tokenEndpoint ?? `${this.cfg.issuer.replace(/\/+$/, "")}/protocol/openid-connect/token`;
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token,
      client_id: this.cfg.clientId
    });
    const res = await fetch(tokenUrl, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
    if (!res.ok) return false;
    const t = await res.json();
    this.accessToken = t.access_token || this.accessToken;
    this.idToken = t.id_token || this.idToken;
    this.cfg.storage?.setItem(this.key, JSON.stringify({ refresh_token: t.refresh_token || refresh_token }));
    return true;
  }
  private async sha256B64Url(s: string): Promise<string> {
    const g = (globalThis as any).crypto;
    if (!g?.subtle) throw new Error("crypto.subtle not available");
    const data = new TextEncoder().encode(s);
    const hash = await g.subtle.digest("SHA-256", data);
    const b = String.fromCharCode(...new Uint8Array(hash));
    return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
}

// Example domain types (not authoritative). I cannot verify this.
export interface Health { status: "ok" | "degraded" | "fail"; details?: Record<string, unknown>; }
export interface SessionInfo { session_id: string; user_id: string; created_at: string; expires_at: string; }

// Example service wrapper. Endpoints are illustrative. I cannot verify this.
export class ZtcApi {
  constructor(private readonly client: ZeroTrustCoreClient) {}

  // GET /healthz
  health(): Promise<ResponseEnvelope<Health>> {
    return this.client.get<Health("ok" | "degraded" | "fail")>("healthz");
  }

  // GET /readyz
  readiness(): Promise<ResponseEnvelope<{ ready: boolean }>> {
    return this.client.get<{ ready: boolean }>("readyz");
  }

  // POST /sessions/refresh
  refreshSession(etag?: string) {
    return this.client.post<SessionInfo>("sessions/refresh", { idempotency: true, etag });
  }

  // Example: cursor pagination for posture events
  async *listPostureEvents(opts: { pageSize?: number } = {}) {
    for await (const batch of this.client.cursorPaginate<any>("posture/events", { pageSize: opts.pageSize })) {
      yield batch;
    }
  }

  // Example: send posture event
  sendPostureEvent(ev: unknown) {
    return this.client.post<{ accepted: boolean }>("posture/events", { json: ev, idempotency: true });
  }
}
