/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Ledger Core SDK — промышленный HTTP/Fetch клиент.
 * Совместим с Node 18+, Deno, Browser. Без внешних зависимостей.
 */

export type FetchLike = typeof fetch;

export interface RetryPolicy {
  maxRetries: number;              // общее число попыток, включая первую = 0 (без ретраев)
  baseDelayMs: number;             // базовая задержка (экспоненциальная)
  maxDelayMs: number;              // потолок задержки
  jitter: "full" | "none";         // тип джиттера
  retryOn: Array<number | "network" | "5xx" | "429" | "retryableError">;
}

export interface CircuitBreakerOptions {
  failureThreshold: number;        // сколько подряд неудач переводит в Open
  successThreshold: number;        // сколько подряд успехов в HalfOpen → Close
  openStateDurationMs: number;     // сколько держать Open перед HalfOpen
}

export interface AuthProvider {
  /**
   * Возвращает заголовки аутентификации (например, Bearer).
   * Может быть синхронным или асинхронным; вызывается перед каждым запросом при необходимости.
   */
  getAuthHeaders(): Promise<Record<string, string>> | Record<string, string>;
}

export interface ClientOptions {
  baseUrl: string;                 // например: https://api.ledger.example.com
  fetch?: FetchLike;               // пользовательский fetch, по умолчанию — глобальный
  defaultHeaders?: Record<string, string>;
  timeoutMs?: number;              // общий таймаут запроса
  userAgent?: string;              // будет добавлен как User-Agent (в браузере игнорируется)
  auth?: AuthProvider;             // поставщик токена
  retry?: Partial<RetryPolicy>;
  breaker?: Partial<CircuitBreakerOptions>;
  /**
   * Генератор traceparent (W3C). Если передан — SDK добавит заголовок traceparent.
   * Возвращайте строку формата 00-<traceId>-<spanId>-<flags>.
   */
  traceparentFactory?: () => string | undefined;
  /**
   * Вы можете задать фабрику корреляционного идентификатора.
   * По умолчанию — uuid v4 (упрощенная реализация).
   */
  correlationIdFactory?: () => string;
  /**
   * Хуки для телеметрии/логирования.
   */
  hooks?: {
    beforeRequest?: (ctx: RequestContext) => void | Promise<void>;
    afterResponse?: (ctx: ResponseContext) => void | Promise<void>;
  };
}

/* ----------------------------- Ошибки (совместимо с error.proto) ----------------------------- */

export enum Severity {
  SEVERITY_UNSPECIFIED = 0,
  SEVERITY_INFO = 1,
  SEVERITY_WARNING = 2,
  SEVERITY_ERROR = 3,
  SEVERITY_CRITICAL = 4,
}

export interface FieldViolation {
  field: string;
  description?: string;
  value?: string;
}

export type AuthReason =
  | "REASON_UNSPECIFIED"
  | "REASON_UNAUTHENTICATED"
  | "REASON_PERMISSION_DENIED"
  | "REASON_EXPIRED"
  | "REASON_MFA_REQUIRED"
  | "REASON_MFA_FAILED";

export interface AuthViolation {
  reason: AuthReason;
  subject?: string;
  resource?: string;
  policy_hint?: string;
}

export interface QuotaViolation {
  subject?: string;
  metric?: string;
  limit?: number;
  current?: number;
  window?: string;
}

export interface RateLimitDetail {
  limit?: number;
  remaining?: number;
  reset_at_unix?: number;
  scope?: string;
}

export interface ConflictDetail {
  resource_type?: string;
  resource_id?: string;
  expected_version?: string;
  actual_version?: string;
}

export interface ResourceNotFoundDetail {
  resource_type?: string;
  resource_id?: string;
}

export interface UpstreamDetail {
  system?: string;
  status_code?: number;
  endpoint?: string;
  operation?: string;
}

export interface DomainViolation {
  domain?: string;
  rule?: string;
  description?: string;
}

export type ErrorDetail =
  | { field_violation: FieldViolation }
  | { auth_violation: AuthViolation }
  | { quota_violation: QuotaViolation }
  | { rate_limit: RateLimitDetail }
  | { conflict: ConflictDetail }
  | { not_found: ResourceNotFoundDetail }
  | { upstream: UpstreamDetail }
  | { domain_violation: DomainViolation };

export interface LocalizedMessage {
  locale?: string;   // BCP-47
  message?: string;
}

export interface LedgerErrorPayload {
  code: string;
  message: string;
  correlation_id?: string;
  severity?: Severity;
  http_status?: number;
  retryable?: boolean;
  details?: ErrorDetail[];
  metadata?: Record<string, string>;
  localized?: LocalizedMessage;
}

export class LedgerError extends Error {
  public readonly code: string;
  public readonly httpStatus?: number;
  public readonly retryable: boolean;
  public readonly correlationId?: string;
  public readonly severity?: Severity;
  public readonly details?: ErrorDetail[];
  public readonly metadata?: Record<string, string>;
  constructor(payload: LedgerErrorPayload) {
    super(payload.localized?.message || payload.message || payload.code);
    this.name = "LedgerError";
    this.code = payload.code;
    this.httpStatus = payload.http_status;
    this.retryable = Boolean(payload.retryable);
    this.correlationId = payload.correlation_id;
    this.severity = payload.severity;
    this.details = payload.details;
    this.metadata = payload.metadata;
  }
}

/* ----------------------------- Внутренние контексты запроса/ответа ----------------------------- */

type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

interface RequestContext {
  url: string;
  method: HttpMethod;
  headers: Record<string, string>;
  body?: any;
  attempt: number;
  correlationId: string;
  traceparent?: string;
}

interface ResponseContext {
  request: RequestContext;
  response?: Response;
  parsedBody?: any;
  error?: unknown;
  rateLimit?: RateLimitInfo;
}

export interface RateLimitInfo {
  limit?: number;
  remaining?: number;
  resetAt?: Date;
  scope?: string;
  retryAfterMs?: number;
}

/* ----------------------------- Утилиты ----------------------------- */

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function defaultUuidV4(): string {
  // Упрощенная реализация для отсутствия зависимостей.
  // Для критичного продакшена можно заменить на crypto.randomUUID().
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    // @ts-ignore
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function mergeHeaders(...groups: Array<Record<string, string> | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const g of groups) {
    if (!g) continue;
    for (const [k, v] of Object.entries(g)) {
      if (v != null) out[k] = v;
    }
  }
  return out;
}

function parseRetryAfter(h: string | null): number | undefined {
  if (!h) return;
  // seconds or HTTP-date; поддержим секунды
  const asInt = parseInt(h, 10);
  if (!Number.isNaN(asInt)) return asInt * 1000;
  const date = new Date(h);
  const diff = date.getTime() - Date.now();
  return diff > 0 ? diff : undefined;
}

function computeBackoffMs(attempt: number, policy: Required<RetryPolicy>, retryAfterMs?: number): number {
  if (retryAfterMs && retryAfterMs > 0) return clamp(retryAfterMs, 0, policy.maxDelayMs);
  const expo = policy.baseDelayMs * Math.pow(2, attempt - 1);
  const capped = Math.min(expo, policy.maxDelayMs);
  if (policy.jitter === "full") return Math.floor(Math.random() * capped);
  return capped;
}

/* ----------------------------- Circuit Breaker ----------------------------- */

class CircuitBreaker {
  private readonly opts: Required<CircuitBreakerOptions>;
  private failures = 0;
  private successesHalfOpen = 0;
  private state: "CLOSED" | "OPEN" | "HALF_OPEN" = "CLOSED";
  private nextAttemptAt = 0;

  constructor(opts?: Partial<CircuitBreakerOptions>) {
    this.opts = {
      failureThreshold: opts?.failureThreshold ?? 5,
      successThreshold: opts?.successThreshold ?? 2,
      openStateDurationMs: opts?.openStateDurationMs ?? 15_000,
    };
  }

  canRequest(): boolean {
    if (this.state === "CLOSED") return true;
    const now = Date.now();
    if (this.state === "OPEN" && now >= this.nextAttemptAt) {
      this.state = "HALF_OPEN";
      this.successesHalfOpen = 0;
      return true;
    }
    return this.state === "HALF_OPEN";
  }

  onSuccess(): void {
    if (this.state === "HALF_OPEN") {
      this.successesHalfOpen += 1;
      if (this.successesHalfOpen >= this.opts.successThreshold) {
        this.reset();
      }
      return;
    }
    if (this.state === "OPEN") return;
    this.failures = 0;
  }

  onFailure(): void {
    if (this.state === "HALF_OPEN") {
      this.trip();
      return;
    }
    this.failures += 1;
    if (this.failures >= this.opts.failureThreshold) {
      this.trip();
    }
  }

  private trip(): void {
    this.state = "OPEN";
    this.nextAttemptAt = Date.now() + this.opts.openStateDurationMs;
    this.failures = 0;
    this.successesHalfOpen = 0;
  }

  private reset(): void {
    this.state = "CLOSED";
    this.failures = 0;
    this.successesHalfOpen = 0;
    this.nextAttemptAt = 0;
  }
}

/* ----------------------------- Клиент ----------------------------- */

export interface RequestOptions {
  headers?: Record<string, string>;
  /**
   * Идемпотентный запрос — если true, SDK добавит Idempotency-Key (если его нет).
   */
  idempotent?: boolean;
  /**
   * Переопределить таймаут (мс) для конкретного вызова.
   */
  timeoutMs?: number;
  /**
   * Переопределить retry‑политику для конкретного вызова.
   */
  retry?: Partial<RetryPolicy>;
  /**
   * Подменить базовый path (например, для версионирования).
   */
  basePathOverride?: string;
  /**
   * Передать собственный correlation id (иначе будет сгенерирован).
   */
  correlationId?: string;
}

const DEFAULT_RETRY: Required<RetryPolicy> = {
  maxRetries: 3,
  baseDelayMs: 200,
  maxDelayMs: 5_000,
  jitter: "full",
  retryOn: ["network", "5xx", "429", "retryableError"],
};

export class LedgerClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly defaultHeaders: Record<string, string>;
  private readonly timeoutMs: number;
  private readonly retryPolicy: Required<RetryPolicy>;
  private readonly breaker: CircuitBreaker;
  private readonly ua?: string;
  private readonly auth?: AuthProvider;
  private readonly traceparentFactory?: () => string | undefined;
  private readonly correlationIdFactory: () => string;
  private readonly hooks?: ClientOptions["hooks"];

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new Error("baseUrl is required");
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.fetchImpl = opts.fetch ?? fetch;
    this.defaultHeaders = opts.defaultHeaders ?? {};
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.retryPolicy = { ...DEFAULT_RETRY, ...(opts.retry ?? {}) };
    this.breaker = new CircuitBreaker(opts.breaker);
    this.ua = opts.userAgent;
    this.auth = opts.auth;
    this.traceparentFactory = opts.traceparentFactory;
    this.correlationIdFactory = opts.correlationIdFactory ?? defaultUuidV4;
    this.hooks = opts.hooks;
  }

  /* ------------------------- Публичные удобные методы API (примеры) ------------------------- */

  /**
   * Пример: получить транзакцию по id.
   */
  async getTransaction<T = any>(id: string, options?: RequestOptions): Promise<T> {
    return this.request<T>("GET", `/api/v1/tx/${encodeURIComponent(id)}`, undefined, undefined, options);
  }

  /**
   * Пример: создать транзакцию (идемпотентный POST).
   */
  async createTransaction<T = any>(payload: Record<string, any>, options?: RequestOptions): Promise<T> {
    const reqOpts: RequestOptions = { idempotent: true, ...options };
    return this.request<T>("POST", `/api/v1/tx`, undefined, payload, reqOpts);
  }

  /**
   * Пример: листинг с пагинацией (cursor‑based).
   */
  paginateTransactions<T = any>(params?: Record<string, any>, pageSize = 100, options?: RequestOptions) {
    return this.paginate<T>("/api/v1/tx", { ...params, limit: pageSize }, options);
  }

  /* ------------------------- Универсальный запрос ------------------------- */

  async request<T>(
    method: HttpMethod,
    path: string,
    query?: Record<string, any>,
    body?: any,
    options?: RequestOptions
  ): Promise<T> {
    if (!this.breaker.canRequest()) {
      const err = new LedgerError({
        code: "CIRCUIT_OPEN",
        message: "Circuit breaker is open",
        http_status: 503,
        retryable: true,
      });
      throw err;
    }

    const retry = { ...this.retryPolicy, ...(options?.retry ?? {}) } as Required<RetryPolicy>;
    const url = this.buildUrl(path, query, options?.basePathOverride);
    const correlationId = options?.correlationId ?? this.correlationIdFactory();
    const controller = new AbortController();

    const attemptOnce = async (attempt: number): Promise<{ ok: boolean; value: T | LedgerError; ctx: ResponseContext }> => {
      const headers: Record<string, string> = mergeHeaders(
        {
          Accept: "application/json",
          "Content-Type": body === undefined || body instanceof FormData ? "application/json" : "application/json",
          "X-Request-ID": correlationId,
        },
        this.ua ? { "User-Agent": this.ua } : undefined,
        this.defaultHeaders,
        options?.headers
      );

      // Аутентификация
      if (this.auth) {
        const authHeaders = await this.auth.getAuthHeaders();
        Object.assign(headers, authHeaders || {});
      }

      // Идемпотентность
      if (options?.idempotent && !headers["Idempotency-Key"]) {
        headers["Idempotency-Key"] = this.correlationIdFactory();
      }

      // Traceparent
      const traceparent = this.traceparentFactory?.();
      if (traceparent) headers["traceparent"] = traceparent;

      const timeout = options?.timeoutMs ?? this.timeoutMs;
      const timer = setTimeout(() => controller.abort(), timeout);

      const reqCtx: RequestContext = { url, method, headers, body, attempt, correlationId, traceparent };
      if (this.hooks?.beforeRequest) await this.hooks.beforeRequest(reqCtx);

      let resp: Response | undefined;
      let parsed: any | undefined;
      let rate: RateLimitInfo | undefined;

      try {
        const init: RequestInit = {
          method,
          headers,
          signal: controller.signal,
        };

        if (body !== undefined) {
          if (body instanceof FormData) {
            // Браузер сам выставит корректные boundary; в Node 18 FormData также поддерживается.
            // @ts-ignore
            init.body = body;
            // content-type оставляем управлять платформе
            delete headers["Content-Type"];
          } else {
            init.body = JSON.stringify(body);
          }
        }

        resp = await this.fetchImpl(url, init);

        rate = this.extractRateLimit(resp);
        const isJson = (resp.headers.get("content-type") || "").includes("application/json");
        if (isJson) {
          parsed = await resp.json().catch(() => undefined);
        } else if (resp.ok) {
          // типизированный возврат без JSON (на усмотрение вызывающего)
          parsed = (await resp.text()) as any;
        }

        if (resp.ok) {
          this.breaker.onSuccess();
          const ctx: ResponseContext = { request: reqCtx, response: resp, parsedBody: parsed, rateLimit: rate };
          if (this.hooks?.afterResponse) await this.hooks.afterResponse(ctx);
          return { ok: true, value: parsed as T, ctx };
        }

        // Попробуем нормализовать ошибку
        const err = this.toLedgerError(resp, parsed, correlationId);
        const ctx: ResponseContext = { request: reqCtx, response: resp, parsedBody: parsed, error: err, rateLimit: rate };
        if (this.hooks?.afterResponse) await this.hooks.afterResponse(ctx);
        return { ok: false, value: err, ctx };
      } catch (e: any) {
        const networkErr = new LedgerError({
          code: e?.name === "AbortError" ? "REQUEST_TIMEOUT" : "NETWORK_ERROR",
          message: e?.message || "Network/timeout error",
          http_status: undefined,
          retryable: true,
          correlation_id: correlationId,
        });
        const ctx: ResponseContext = { request: reqCtx, error: networkErr };
        if (this.hooks?.afterResponse) await this.hooks.afterResponse(ctx);
        return { ok: false, value: networkErr, ctx };
      } finally {
        clearTimeout(timer);
      }
    };

    let attempt = 0;
    let lastError: LedgerError | undefined;
    let retryAfterMs: number | undefined;

    while (attempt <= retry.maxRetries) {
      attempt += 1;

      // Respect circuit breaker state before each attempt
      if (!this.breaker.canRequest()) {
        const err = new LedgerError({
          code: "CIRCUIT_OPEN",
          message: "Circuit breaker is open",
          http_status: 503,
          retryable: true,
          correlation_id: undefined,
        });
        throw err;
      }

      const res = await attemptOnce(attempt);
      if (res.ok) return res.value as T;

      const err = res.value as LedgerError;
      lastError = err;

      // Решение о ретрае
      const status = err.httpStatus;
      let shouldRetry = false;

      if (retry.retryOn.includes("retryableError") && err.retryable) shouldRetry = true;
      if (retry.retryOn.includes("network") && (err.code === "NETWORK_ERROR" || err.code === "REQUEST_TIMEOUT")) {
        shouldRetry = true;
      }
      if (typeof status === "number") {
        if (retry.retryOn.includes("429") && status === 429) shouldRetry = true;
        if (retry.retryOn.includes("5xx") && status >= 500 && status <= 599) shouldRetry = true;
        if (retry.retryOn.includes(status)) shouldRetry = true;
      }

      if (!shouldRetry || attempt > retry.maxRetries + 1) {
        this.breaker.onFailure();
        throw err;
      }

      // Уважим Retry-After, если был
      retryAfterMs = parseRetryAfter(res.ctx.response?.headers.get("retry-after") ?? null);

      const backoff = computeBackoffMs(attempt, retry, retryAfterMs);
      await sleep(backoff);
      // При этом считаем попытку неуспеха для брейкера только если окончательно сдаёмся
      // (см. throw выше). Здесь не меняем счетчик.
    }

    // Если вышли по циклу — бросаем последнее
    this.breaker.onFailure();
    throw lastError!;
  }

  /* ------------------------- Пагинация ------------------------- */

  /**
   * Универсальный пагинатор. Поддерживает cursor‑based (next_cursor) и page‑based (page/totalPages).
   * Ожидаемый формат ответа:
   *  - { data: T[], next_cursor?: string }  ИЛИ
   *  - { data: T[], page: number, total_pages: number }
   */
  async *paginate<T = any>(
    path: string,
    query?: Record<string, any>,
    options?: RequestOptions
  ): AsyncGenerator<T, void, unknown> {
    let params = { ...(query || {}) };
    for (;;) {
      const page = await this.request<any>("GET", path, params, undefined, options);
      const items: T[] = Array.isArray(page) ? page : Array.isArray(page?.data) ? page.data : [];
      for (const it of items) yield it;

      if (page?.next_cursor) {
        params = { ...(params || {}), cursor: page.next_cursor };
        continue;
      }
      const p = page?.page;
      const tp = page?.total_pages;
      if (typeof p === "number" && typeof tp === "number" && p < tp) {
        params = { ...(params || {}), page: p + 1 };
        continue;
      }
      break;
    }
  }

  /* ------------------------- Стриминг: NDJSON и SSE ------------------------- */

  /**
   * Чтение NDJSON потока.
   */
  async *streamNdjson<T = any>(
    path: string,
    query?: Record<string, any>,
    options?: RequestOptions
  ): AsyncGenerator<T, void, unknown> {
    const url = this.buildUrl(path, query, options?.basePathOverride);
    const headers: Record<string, string> = mergeHeaders(
      { Accept: "application/x-ndjson", "X-Request-ID": options?.correlationId ?? this.correlationIdFactory() },
      this.defaultHeaders,
      options?.headers
    );
    if (this.auth) Object.assign(headers, await this.auth.getAuthHeaders());

    const resp = await this.fetchImpl(url, { method: "GET", headers });
    if (!resp.ok || !resp.body) throw this.toLedgerError(resp, await safeJson(resp), headers["X-Request-ID"]);

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try {
          yield JSON.parse(line) as T;
        } catch {
          // игнорируем поломанные строки
        }
      }
    }
    if (buf.trim()) {
      try {
        yield JSON.parse(buf) as T;
      } catch {
        // ignore tail
      }
    }
  }

  /* ------------------------- Приватные утилиты клиента ------------------------- */

  private buildUrl(path: string, query?: Record<string, any>, basePathOverride?: string): string {
    const base = basePathOverride ? this.baseUrl + basePathOverride.replace(/\/+$/, "") : this.baseUrl;
    const p = path.startsWith("/") ? path : `/${path}`;
    const url = new URL(base + p);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v === undefined || v === null) continue;
        if (Array.isArray(v)) v.forEach((vv) => url.searchParams.append(k, String(vv)));
        else url.searchParams.set(k, String(v));
      }
    }
    return url.toString();
  }

  private toLedgerError(resp: Response, parsed: any, correlationId?: string): LedgerError {
    // Если это наш унифицированный формат — используем его.
    if (parsed && typeof parsed === "object" && parsed.code && parsed.message) {
      return new LedgerError({
        code: String(parsed.code),
        message: String(parsed.localized?.message || parsed.message),
        correlation_id: parsed.correlation_id || correlationId,
        severity: parsed.severity,
        http_status: resp.status,
        retryable: Boolean(parsed.retryable) || resp.status === 429 || (resp.status >= 500 && resp.status <= 599),
        details: parsed.details,
        metadata: parsed.metadata,
        localized: parsed.localized,
      });
    }

    // Иначе — синтезируем общее представление
    const code =
      resp.status === 401
        ? "UNAUTHENTICATED"
        : resp.status === 403
        ? "PERMISSION_DENIED"
        : resp.status === 404
        ? "NOT_FOUND"
        : resp.status === 409
        ? "CONFLICT"
        : resp.status === 429
        ? "RATE_LIMITED"
        : resp.status >= 500
        ? "UPSTREAM_UNAVAILABLE"
        : "BAD_REQUEST";

    const message =
      typeof parsed === "string"
        ? parsed
        : typeof parsed?.error === "string"
        ? parsed.error
        : parsed?.message || `HTTP ${resp.status}`;

    return new LedgerError({
      code,
      message,
      correlation_id: correlationId,
      http_status: resp.status,
      retryable: resp.status === 429 || (resp.status >= 500 && resp.status <= 599),
    });
  }

  private extractRateLimit(resp?: Response): RateLimitInfo | undefined {
    if (!resp) return;
    const limit = maybeInt(resp.headers.get("x-ratelimit-limit"));
    const remaining = maybeInt(resp.headers.get("x-ratelimit-remaining"));
    const reset = maybeInt(resp.headers.get("x-ratelimit-reset"));
    const scope = resp.headers.get("x-ratelimit-scope") || undefined;
    const retryAfterMs = parseRetryAfter(resp.headers.get("retry-after"));
    const resetAt = reset ? new Date(reset * 1000) : undefined;
    if (limit || remaining || resetAt || scope || retryAfterMs) {
      return { limit, remaining, resetAt, scope, retryAfterMs };
    }
    return;
  }
}

function maybeInt(v: string | null): number | undefined {
  if (v == null) return;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : undefined;
}

async function safeJson(resp: Response): Promise<any | undefined> {
  const ct = resp.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return;
  try {
    return await resp.json();
  } catch {
    return;
  }
}

/* -------------------------------- Пример использования (для справки)
const client = new LedgerClient({
  baseUrl: "https://api.ledger.example.com",
  auth: {
    async getAuthHeaders() {
      return { Authorization: `Bearer ${await getAccessToken()}` };
    },
  },
  userAgent: "ledger-core-sdk/1.0.0",
  traceparentFactory: () => "00-" + randomTraceId() + "-" + randomSpanId() + "-01",
});

const tx = await client.createTransaction({ amount: 100, currency: "EUR" });
for await (const t of client.paginateTransactions({ status: "posted" }, 200)) {
  console.log(t);
}
---------------------------------- */
