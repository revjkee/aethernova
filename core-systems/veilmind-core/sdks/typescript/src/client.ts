/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * veilmind-core TypeScript SDK — промышленная реализация клиентского API.
 *
 * Особенности безопасности:
 *  - Таймаут каждого запроса через AbortController
 *  - Экспоненциальные ретраи с джиттером для 429/5xx/сетевых ошибок
 *  - Идемпотентные POST (Idempotency-Key)
 *  - Строгая проверка Content-Type и безопасный парсинг JSON
 *  - Опциональная HMAC-подпись (server-to-server): X-VM-Signature
 *  - Заголовок X-Client-TraceId и корреляция запросов
 *
 * Зависимости: нет (используется встроенный fetch; для Node 18+ либо полифилл).
 */

export type FetchLike = typeof fetch;

export interface ClientOptions {
  baseUrl: string;                 // https://pep.example/v1
  apiKey?: string;                 // Для Authorization: Bearer
  hmacSecret?: string;             // Для X-VM-Signature (server-to-server). Не используйте в браузере.
  defaultTimeoutMs?: number;       // По умолчанию 5000
  maxRetries?: number;             // По умолчанию 3
  backoffBaseMs?: number;          // По умолчанию 200 (экспонента)
  backoffMaxMs?: number;           // По умолчанию 5000
  userAgent?: string;              // Добавится как X-Client-Agent
  defaultHeaders?: Record<string, string>;
  fetch?: FetchLike;               // Кастомный fetch (например, из undici)
  telemetry?: {
    enabled: boolean;              // По умолчанию false
    bufferSize?: number;           // По умолчанию 50
    flushIntervalMs?: number;      // По умолчанию 5000
    path?: string;                 // По умолчанию /v1/telemetry/events
  };
}

/** Узкотипизированные ошибки SDK */
export class VeilmindError extends Error {
  public readonly code: string;
  public readonly status?: number;
  public readonly details?: unknown;
  constructor(message: string, code = "VM_ERR", status?: number, details?: unknown) {
    super(message);
    this.name = "VeilmindError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export class TimeoutError extends VeilmindError {
  constructor(ms: number) {
    super(`Request timed out after ${ms} ms`, "VM_TIMEOUT");
    this.name = "TimeoutError";
  }
}

export class NetworkError extends VeilmindError {
  constructor(message: string) {
    super(message, "VM_NETWORK");
    this.name = "NetworkError";
  }
}

export class ApiError extends VeilmindError {
  public readonly responseBody?: unknown;
  constructor(status: number, message: string, details?: unknown) {
    super(message, "VM_API", status, details);
    this.name = "ApiError";
    this.responseBody = details;
  }
}

/** Утилиты */
const DEFAULTS = {
  TIMEOUT_MS: 5000,
  RETRIES: 3,
  BACKOFF_BASE_MS: 200,
  BACKOFF_MAX_MS: 5000,
};

function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof window.document !== "undefined";
}

function normalizeBaseUrl(u: string): string {
  // Убираем завершающий слэш
  return u.replace(/\/+$/, "");
}

function joinUrl(base: string, path: string): string {
  if (!path.startsWith("/")) path = `/${path}`;
  return `${normalizeBaseUrl(base)}${path}`;
}

function randomTraceId(): string {
  // 128-бит как base32 без паддинга
  if (typeof crypto !== "undefined" && "getRandomValues" in crypto) {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  // Node до 19 без webcrypto
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require("crypto") as typeof import("crypto");
    return nodeCrypto.randomBytes(16).toString("hex");
  } catch {
    // Деградация
    return Math.random().toString(16).slice(2) + Date.now().toString(16);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

function computeBackoff(attempt: number, base: number, max: number): number {
  const exp = Math.min(max, base * Math.pow(2, attempt));
  // full jitter
  return Math.floor(Math.random() * exp);
}

async function sha256Hex(input: string): Promise<string> {
  if (typeof crypto !== "undefined" && "subtle" in crypto) {
    const enc = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  // Node
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const nodeCrypto = require("crypto") as typeof import("crypto");
  return nodeCrypto.createHash("sha256").update(input).digest("hex");
}

async function hmacSha256Hex(secret: string, data: string): Promise<string> {
  if (typeof crypto !== "undefined" && "subtle" in crypto) {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
    return Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  // Node
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const nodeCrypto = require("crypto") as typeof import("crypto");
  return nodeCrypto.createHmac("sha256", secret).update(data).digest("hex");
}

function contentTypeIsJson(ct?: string | null): boolean {
  if (!ct) return false;
  return /^application\/(problem\+json|json)(;|$)/i.test(ct);
}

function pick<T extends object>(obj: T, allowed: (keyof T)[]): Partial<T> {
  const out: Partial<T> = {};
  for (const k of allowed) {
    if (k in obj) out[k] = obj[k];
  }
  return out;
}

/** Типы домена (минимальный стабильный слой) */
export interface Subject {
  user?: { id: string; groups?: string[]; privilege?: "admin" | "ops" | "user" };
  device?: { id: string; posture_id?: string };
  session?: { id?: string; mfaSatisfied?: boolean };
}

export interface ResourceRef {
  id?: string;
  labels?: Record<string, string>;
}

export type Action = "read" | "list" | "write" | "delete" | "admin";

export interface EnvironmentCtx {
  ip?: string;
  geo?: string;
  asn?: number;
  userAgent?: string;
  timestamp?: string; // RFC3339
}

export interface DecisionRequest {
  subject: Subject;
  action: Action;
  resource: ResourceRef;
  environment?: EnvironmentCtx;
  // Необязательные расширения:
  context?: Record<string, any>;
  // Идемпотентность (переопределит авто):
  idempotencyKey?: string;
}

export interface Obligation {
  type: "mfa" | "header" | "mask" | "route" | "log";
  params?: Record<string, any>;
}

export type DecisionAction = "allow" | "step_up" | "quarantine" | "deny";

export interface DecisionResponse {
  decision: DecisionAction;
  reason?: string;
  score?: {
    total?: number; // 0..100
    band?: "low" | "medium" | "high" | "critical";
  };
  obligations?: Obligation[];
  policy?: {
    matchedRule?: string;
    version?: string;
  };
  traceId?: string;
}

export interface RiskScoreRequest {
  subject: Subject;
  resource?: ResourceRef;
  action?: Action;
  environment?: EnvironmentCtx;
  signals?: Record<string, any>;
}

export interface RiskScoreResponse {
  total: number; // 0..100
  band: "low" | "medium" | "high" | "critical";
  explanations?: Array<{ key: string; score: number }>;
  traceId?: string;
}

export interface ConsentState {
  [purposeId: string]: "allow" | "deny" | "prompt";
}

export interface ConsentGetRequest {
  subjectId: string;       // Псевдонимизированный ID
  purposes?: string[];     // Если пусто — вернуть все
}

export interface ConsentSetRequest {
  subjectId: string;
  changes: {
    [purposeId: string]: "allow" | "deny";
  };
  evidence?: {
    uiVersion?: string;
    ipHash?: string;
    userAgent?: string;
  };
}

/** Телеметрия (опционально) */
export interface TelemetryEvent {
  type: "access" | "risk" | "audit" | "custom";
  ts?: string; // RFC3339
  subject?: { id?: string; device?: string };
  fields?: Record<string, any>;
}

/** Основной клиент */
export class VeilmindClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly hmacSecret?: string;
  private readonly fetch: FetchLike;
  private readonly defaultTimeout: number;
  private readonly maxRetries: number;
  private readonly backoffBase: number;
  private readonly backoffMax: number;
  private readonly defaultHeaders: Record<string, string>;
  private readonly userAgent?: string;

  // Телеметрия
  private telemetryEnabled = false;
  private telemetryBuffer: TelemetryEvent[] = [];
  private telemetryBufferSize = 50;
  private telemetryFlushIntervalMs = 5000;
  private telemetryPath = "/v1/telemetry/events";
  private telemetryTimer?: ReturnType<typeof setInterval>;

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new VeilmindError("baseUrl is required", "VM_CONFIG");
    this.baseUrl = normalizeBaseUrl(opts.baseUrl);
    this.apiKey = opts.apiKey;
    this.hmacSecret = opts.hmacSecret;
    this.fetch = opts.fetch ?? (globalThis.fetch as FetchLike);
    if (typeof this.fetch !== "function") {
      throw new VeilmindError("Global fetch is not available; provide ClientOptions.fetch", "VM_CONFIG");
    }
    this.defaultTimeout = opts.defaultTimeoutMs ?? DEFAULTS.TIMEOUT_MS;
    this.maxRetries = Math.max(0, opts.maxRetries ?? DEFAULTS.RETRIES);
    this.backoffBase = opts.backoffBaseMs ?? DEFAULTS.BACKOFF_BASE_MS;
    this.backoffMax = opts.backoffMaxMs ?? DEFAULTS.BACKOFF_MAX_MS;
    this.userAgent = opts.userAgent;
    this.defaultHeaders = {
      "Accept": "application/json",
      "Content-Type": "application/json",
      ...(opts.defaultHeaders ?? {}),
    };

    // Телеметрия
    if (opts.telemetry?.enabled) {
      this.telemetryEnabled = true;
      this.telemetryBufferSize = opts.telemetry.bufferSize ?? 50;
      this.telemetryFlushIntervalMs = opts.telemetry.flushIntervalMs ?? 5000;
      this.telemetryPath = opts.telemetry.path ?? "/v1/telemetry/events";
      this.startTelemetryTimer();
    }
  }

  /** Остановить фоновый таймер телеметрии (если включен) */
  public stop(): void {
    if (this.telemetryTimer) {
      clearInterval(this.telemetryTimer);
      this.telemetryTimer = undefined;
    }
  }

  /** Решение PEP/PDP */
  public async decide(input: DecisionRequest, timeoutMs?: number): Promise<DecisionResponse> {
    const path = "/v1/decision";
    const body = pick(input, ["subject", "action", "resource", "environment", "context"]);
    const idemp = input.idempotencyKey ?? (await sha256Hex(JSON.stringify(body)).catch(() => randomTraceId()));
    const res = await this.request<DecisionResponse>("POST", path, body, {
      timeoutMs,
      idempotencyKey: idemp,
    });
    return res;
  }

  /** Получить риск‑скор */
  public async scoreRisk(input: RiskScoreRequest, timeoutMs?: number): Promise<RiskScoreResponse> {
    const path = "/v1/risk/score";
    const body = pick(input, ["subject", "resource", "action", "environment", "signals"]);
    return this.request<RiskScoreResponse>("POST", path, body, { timeoutMs });
  }

  /** Получить состояние согласий */
  public async getConsent(input: ConsentGetRequest, timeoutMs?: number): Promise<ConsentState> {
    const query = new URLSearchParams();
    query.set("subjectId", input.subjectId);
    if (input.purposes && input.purposes.length) {
      for (const p of input.purposes) query.append("purpose", p);
    }
    const path = `/v1/consent/state?${query.toString()}`;
    return this.request<ConsentState>("GET", path, undefined, { timeoutMs });
  }

  /** Установить/изменить согласия */
  public async setConsent(input: ConsentSetRequest, timeoutMs?: number): Promise<{ updated: string[] }> {
    const path = "/v1/consent/state";
    const body = pick(input, ["subjectId", "changes", "evidence"]);
    const idemp = await sha256Hex(`${input.subjectId}:${JSON.stringify(input.changes)}`).catch(() => randomTraceId());
    return this.request<{ updated: string[] }>("POST", path, body, { timeoutMs, idempotencyKey: idemp });
  }

  /** Отправить событие телеметрии (буферизуется, если включено) */
  public async emit(event: TelemetryEvent): Promise<void> {
    if (!this.telemetryEnabled) return;
    const ev: TelemetryEvent = {
      ts: event.ts ?? new Date().toISOString(),
      ...event,
    };
    this.telemetryBuffer.push(ev);
    if (this.telemetryBuffer.length >= this.telemetryBufferSize) {
      await this.flush().catch(() => void 0);
    }
  }

  /** Принудительно отправить накопленную телеметрию */
  public async flush(): Promise<void> {
    if (!this.telemetryEnabled) return;
    if (this.telemetryBuffer.length === 0) return;
    const batch = this.telemetryBuffer.splice(0, this.telemetryBuffer.length);
    try {
      await this.request<unknown>("POST", this.telemetryPath, { events: batch }, { timeoutMs: 3000 });
    } catch {
      // Возврат буфера на место при ошибке (ограниченно)
      this.telemetryBuffer.unshift(...batch);
    }
  }

  /** Внутренний запрос с политикой ретраев/таймаутов/подписью/HDR */
  private async request<T>(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    body?: unknown,
    opts?: { timeoutMs?: number; idempotencyKey?: string },
  ): Promise<T> {
    const url = path.startsWith("http") ? path : joinUrl(this.baseUrl, path);
    const controller = new AbortController();
    const timeout = opts?.timeoutMs ?? this.defaultTimeout;
    const timer = setTimeout(() => controller.abort(), timeout);

    const traceId = randomTraceId();
    const headers: Record<string, string> = {
      ...this.defaultHeaders,
      "X-Client-TraceId": traceId,
      "X-Client-Agent": this.userAgent ?? `veilmind-ts-sdk/1`,
    };
    if (this.apiKey) headers["Authorization"] = `Bearer ${this.apiKey}`;
    if (opts?.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;

    const payload = body === undefined ? undefined : JSON.stringify(body);

    // Подпись HMAC для server-to-server (не используйте в браузере)
    if (this.hmacSecret && !isBrowser()) {
      const ts = Math.floor(Date.now() / 1000).toString();
      headers["X-VM-Timestamp"] = ts;
      const canonical = [method, new URL(url).pathname, ts, payload ?? ""].join("\n");
      headers["X-VM-Signature"] = `sha256=${await hmacSha256Hex(this.hmacSecret, canonical)}`;
    }

    let lastErr: unknown;
    try {
      for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
        try {
          const resp = await this.fetch(url, {
            method,
            headers,
            body: payload,
            signal: controller.signal,
          });

          const ct = resp.headers.get("content-type");
          const isJson = contentTypeIsJson(ct);
          if (resp.ok) {
            if (method === "DELETE") {
              clearTimeout(timer);
              return undefined as unknown as T;
            }
            if (!isJson) {
              // Защита от неожиданных типов
              const text = await resp.text().catch(() => "");
              clearTimeout(timer);
              throw new ApiError(resp.status, "Unexpected content type", text);
            }
            const data = (await resp.json()) as T;
            clearTimeout(timer);
            return data;
          }

          // Ошибочные коды
          let errBody: any = undefined;
          if (isJson) {
            errBody = await resp.json().catch(() => undefined);
          } else {
            errBody = await resp.text().catch(() => undefined);
          }
          // Ретраим только транзиентные
          if (resp.status === 429 || (resp.status >= 500 && resp.status <= 599)) {
            const backoff = computeBackoff(attempt, this.backoffBase, this.backoffMax);
            await sleep(backoff);
            continue;
          }

          clearTimeout(timer);
          throw new ApiError(
            resp.status,
            (errBody && (errBody.title || errBody.message)) || `HTTP ${resp.status}`,
            errBody,
          );
        } catch (e: any) {
          if (e?.name === "AbortError") {
            clearTimeout(timer);
            throw new TimeoutError(timeout);
          }
          // Сетевые/транзиентные — ретрай
          const transient =
            e instanceof NetworkError ||
            (typeof e?.code === "string" && ["ECONNRESET", "ENOTFOUND", "EAI_AGAIN"].includes(e.code)) ||
            e?.name === "FetchError";
          if (attempt < this.maxRetries && transient) {
            const backoff = computeBackoff(attempt, this.backoffBase, this.backoffMax);
            await sleep(backoff);
            continue;
          }
          lastErr = e;
          throw e;
        }
      }
      // Если вышли из цикла без возврата
      clearTimeout(timer);
      throw lastErr ?? new VeilmindError("Request failed", "VM_UNKNOWN");
    } catch (e: any) {
      if (e instanceof VeilmindError) throw e;
      if (e?.name === "AbortError") throw new TimeoutError(timeout);
      // Обернём как сетевую
      throw new NetworkError(e?.message ?? "Network/Fetch error");
    } finally {
      clearTimeout(timer);
    }
  }

  /** Запустить авто‑сброс телеметрии */
  private startTelemetryTimer(): void {
    if (!this.telemetryEnabled) return;
    // Не создавать второй таймер
    if (this.telemetryTimer) return;
    this.telemetryTimer = setInterval(() => {
      this.flush().catch(() => void 0);
    }, this.telemetryFlushIntervalMs);
    // В браузере — не будить вкладку
    // @ts-ignore
    if (this.telemetryTimer && typeof this.telemetryTimer.unref === "function") {
      // Node: позволить процессу завершиться
      // @ts-ignore
      this.telemetryTimer.unref();
    }
  }
}

/* ===========================
   Пример использования (Node)
   ===========================
import { VeilmindClient } from "./client";

const client = new VeilmindClient({
  baseUrl: "https://pep.example.com/v1",
  apiKey: process.env.VEILMIND_API_KEY,
  hmacSecret: process.env.VEILMIND_HMAC_SECRET, // Серверное окружение
  defaultTimeoutMs: 3000,
  maxRetries: 3,
  telemetry: { enabled: true, bufferSize: 100, flushIntervalMs: 2000 },
});

async function main() {
  const decision = await client.decide({
    subject: { user: { id: "alice@corp.local", privilege: "ops" }, device: { id: "D-1" } },
    action: "write",
    resource: { id: "cfg-1", labels: { sensitivity: "high", project: "veilmind" } },
    environment: { ip: "198.51.100.10", userAgent: "svc/1.0" },
  });

  if (decision.decision === "step_up") {
    // запросить MFA и повторить, передав session.mfaSatisfied=true
  }
  await client.emit({ type: "access", fields: { decision } });
  await client.flush();
  client.stop();
}
main().catch(console.error);
*/
