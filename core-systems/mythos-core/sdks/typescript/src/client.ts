/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Mythos Core TypeScript SDK – Industrial client
 * Runtime: Node >= 18 (native fetch/AbortController), Deno, Browsers
 *
 * Features:
 *  - Strong types for Dialogue/Turn/Timeline
 *  - fetch-based transport with deadlines (timeout), retries (expo backoff + jitter), and Retry-After
 *  - Auth: Bearer token provider or API key header
 *  - Observability hooks and X-Request-Id correlation
 *  - Pagination helpers + AsyncIterator
 *  - SSE stream as AsyncIterable for Dialogue events
 *  - Rich HTTP error with response body, status, code, request-id
 */

export type ISO8601 = string; // UTC date-time
export type UUID = string;

// -------------------------------
// Domain Types (aligned with proto/jsonschema in repo)
// -------------------------------

export type Actor = "ACTOR_UNSPECIFIED" | "ACTOR_USER" | "ACTOR_ASSISTANT" | "ACTOR_SYSTEM" | "ACTOR_TOOL";

export interface TokenUsage {
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
}

export type Severity = "SEVERITY_UNSPECIFIED" | "SEVERITY_LOW" | "SEVERITY_MEDIUM" | "SEVERITY_HIGH" | "SEVERITY_CRITICAL";

export interface SafetyLabel {
  policy: string;
  severity: Severity;
  tags?: string[];
  reason?: string;
  details?: Record<string, string>;
}

export interface Attachment {
  attachment_id: UUID;
  filename: string;
  mime_type: string;
  size_bytes: number;
  sha256_hex?: string;
  uri?: string;
  metadata?: Record<string, string | number | boolean | null>;
}

export interface ToolCall {
  call_id: UUID;
  tool_name: string;
  input?: Record<string, any>;
  output?: Record<string, any>;
  status?:
    | "TOOL_CALL_STATUS_UNSPECIFIED"
    | "TOOL_CALL_PENDING"
    | "TOOL_CALL_SUCCESS"
    | "TOOL_CALL_ERROR"
    | "TOOL_CALL_TIMEOUT"
    | "TOOL_CALL_CANCELLED";
  latency?: string; // google.protobuf.Duration as ISO8601 duration string if gateway encodes
  error_message?: string;
  attributes?: Record<string, string>;
}

export interface Participant {
  participant_id: UUID;
  display_name: string;
  role?: string;
  attributes?: Record<string, string>;
}

export interface Turn {
  turn_id: UUID;
  actor: Actor;
  created_at: ISO8601;
  parent_turn_id?: UUID;
  // body oneof
  text?: string;
  data?: Record<string, any>;
  tool?: ToolCall;

  attachments?: Attachment[];
  safety?: SafetyLabel[];
  usage?: TokenUsage;
  attributes?: Record<string, string>;
}

export type DialogueStatus = "DIALOGUE_STATUS_UNSPECIFIED" | "DIALOGUE_OPEN" | "DIALOGUE_CLOSED" | "DIALOGUE_ARCHIVED";

export interface Dialogue {
  dialogue_id: UUID;
  status: DialogueStatus;
  title?: string;
  participants?: Participant[];
  created_at: ISO8601;
  updated_at?: ISO8601;
  last_turn_id?: UUID;
  turns?: Turn[];
  labels?: Record<string, string>;
  usage_total?: TokenUsage;
}

export interface Page<T> {
  items: T[];
  nextPageToken?: string | null;
}

export interface CreateDialogueRequest {
  title?: string;
  participants?: Participant[];
  labels?: Record<string, string>;
  seed_turn?: TurnSeed;
}

export interface TurnSeed {
  actor: Actor;
  text?: string;
  data?: Record<string, any>;
  tool?: ToolCall;
  attachments?: Attachment[];
  attributes?: Record<string, string>;
}

export interface CreateDialogueResponse {
  dialogue: Dialogue;
}

export interface AppendTurnRequest {
  dialogue_id: UUID;
  actor: Actor;
  text?: string;
  data?: Record<string, any>;
  tool?: ToolCall;
  attachments?: Attachment[];
  attributes?: Record<string, string>;
  return_dialogue?: boolean;
}

export interface AppendTurnResponse {
  turn: Turn;
  dialogue?: Dialogue;
}

export interface GetDialogueRequest {
  dialogue_id: UUID;
  include_turns?: boolean;
  page_size?: number;
  page_token?: string;
}

export interface GetDialogueResponse {
  dialogue: Dialogue;
  turns?: Turn[];
  next_page_token?: string | null;
}

export interface ListDialoguesRequest {
  page_size?: number;
  page_token?: string;
  status?: DialogueStatus;
  label_filter?: Record<string, string>;
  query?: string;
}

export interface ListDialoguesResponse {
  dialogues: Dialogue[];
  next_page_token?: string | null;
}

// Streaming
export interface DialogueEvent {
  event_id: UUID;
  created_at: ISO8601;
  dialogue_id: UUID;
  event?:
    | { dialogue_created: { dialogue: Dialogue } }
    | { turn_appended: { turn: Turn; usage_total?: TokenUsage } }
    | { dialogue_updated: { status?: DialogueStatus; title?: string; labels?: Record<string, string> } }
    | { dialogue_closed: Record<string, never> }
    | { dialogue_archived: Record<string, never> };
  attributes?: Record<string, string>;
}

// -------------------------------
// Errors
// -------------------------------

export class MythosHttpError extends Error {
  public readonly status: number;
  public readonly method: string;
  public readonly url: string;
  public readonly code?: string;
  public readonly requestId?: string;
  public readonly details?: any;
  public readonly headers: Headers;

  constructor(args: {
    message: string;
    status: number;
    method: string;
    url: string;
    headers: Headers;
    body?: any;
  }) {
    super(args.message);
    this.name = "MythosHttpError";
    this.status = args.status;
    this.method = args.method;
    this.url = args.url;
    this.headers = args.headers;
    const rid = args.headers.get("x-request-id") || args.headers.get("x-amzn-requestid") || undefined;
    this.requestId = rid || undefined;
    if (args.body && typeof args.body === "object") {
      this.code = (args.body.code as string) || (args.body.error as string) || undefined;
      this.details = args.body;
    }
  }
}

// -------------------------------
// Config & Auth
// -------------------------------

export interface RetryPolicy {
  retries: number; // max attempts minus 1 (i.e. 3 => up to 3 retries)
  minDelayMs: number;
  maxDelayMs: number;
  backoffFactor: number; // exponential multiplier
  jitter: "none" | "full" | "equal";
  retryOn?: (status: number) => boolean; // default: 408/429/5xx
  respectRetryAfter?: boolean; // default: true
}

export interface AuthProvider {
  getToken?: () => Promise<string | null> | string | null;
  apiKey?: string;
  headerName?: string; // default: Authorization for Bearer, X-API-Key for apiKey
}

export interface ClientOptions {
  baseUrl: string; // e.g. https://mythos.example.com
  timeoutMs?: number; // default 15000
  retry?: Partial<RetryPolicy>;
  auth?: AuthProvider;
  defaultHeaders?: Record<string, string>;
  userAgent?: string;
  fetchFn?: typeof fetch;
  onRequest?: (info: { id: string; method: string; url: string; init: RequestInit }) => void;
  onResponse?: (info: {
    id: string;
    method: string;
    url: string;
    status: number;
    headers: Headers;
    durationMs: number;
  }) => void;
}

const DEFAULT_RETRY: RetryPolicy = {
  retries: 3,
  minDelayMs: 200,
  maxDelayMs: 3000,
  backoffFactor: 2,
  jitter: "full",
  retryOn: (s: number) => s === 408 || s === 429 || (s >= 500 && s !== 501 && s !== 505),
  respectRetryAfter: true,
};

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function expoDelay(attempt: number, pol: RetryPolicy): number {
  const base = Math.min(pol.maxDelayMs, pol.minDelayMs * Math.pow(pol.backoffFactor, attempt));
  if (pol.jitter === "none") return base;
  if (pol.jitter === "equal") return base / 2 + Math.random() * (base / 2);
  return Math.random() * base; // full jitter
}

function withQuery(url: string, query?: Record<string, string | number | boolean | undefined>): string {
  if (!query) return url;
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    usp.append(k, String(v));
  }
  if ([...usp.keys()].length === 0) return url;
  return `${url}?${usp.toString()}`;
}

function genRequestId(): string {
  // Simple UUIDv4-ish (non-crypto) for correlation; replace with crypto if needed
  const rnd = (n = 16) =>
    Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join("");
  return `${rnd(8)}-${rnd(4)}-4${rnd(3)}-${((8 + Math.random() * 4) | 0).toString(16)}${rnd(3)}-${rnd(12)}`;
}

// -------------------------------
/** Industrial HTTP client */
export class MythosClient {
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly retry: RetryPolicy;
  private readonly auth?: AuthProvider;
  private readonly defaultHeaders: Record<string, string>;
  private readonly userAgent?: string;
  private readonly fetchFn: typeof fetch;
  private readonly onRequest?: ClientOptions["onRequest"];
  private readonly onResponse?: ClientOptions["onResponse"];

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new Error("baseUrl is required");
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 15000;
    this.retry = { ...DEFAULT_RETRY, ...(opts.retry ?? {}) };
    this.auth = opts.auth;
    this.defaultHeaders = opts.defaultHeaders ?? {};
    this.userAgent = opts.userAgent;
    this.fetchFn = opts.fetchFn ?? (globalThis as any).fetch;
    if (!this.fetchFn) throw new Error("fetch is not available; provide fetchFn in ClientOptions");
    this.onRequest = opts.onRequest;
    this.onResponse = opts.onResponse;
  }

  // ------------- Public API -------------

  /** Create a dialogue */
  async createDialogue(req: CreateDialogueRequest, init?: RequestInit): Promise<CreateDialogueResponse> {
    return this.request<CreateDialogueResponse>("POST", "/api/v1/dialogues", { body: req, init, idempotent: true });
  }

  /** Append a turn to dialogue */
  async appendTurn(req: AppendTurnRequest, init?: RequestInit): Promise<AppendTurnResponse> {
    const path = `/api/v1/dialogues/${encodeURIComponent(req.dialogue_id)}/turns`;
    const { dialogue_id, ...payload } = req;
    return this.request<AppendTurnResponse>("POST", path, { body: payload, init });
  }

  /** Get dialogue (optionally include a page of turns) */
  async getDialogue(req: GetDialogueRequest, init?: RequestInit): Promise<GetDialogueResponse> {
    const q = {
      include_turns: req.include_turns,
      page_size: req.page_size,
      page_token: req.page_token,
    };
    const path = `/api/v1/dialogues/${encodeURIComponent(req.dialogue_id)}`;
    return this.request<GetDialogueResponse>("GET", path, { query: q, init });
  }

  /** List dialogues (paged) */
  async listDialogues(req: ListDialoguesRequest = {}, init?: RequestInit): Promise<Page<Dialogue>> {
    const q = {
      page_size: req.page_size,
      page_token: req.page_token,
      status: req.status,
      query: req.query,
      ...prefixed("label.", req.label_filter),
    };
    const resp = await this.request<ListDialoguesResponse>("GET", "/api/v1/dialogues", { query: q, init });
    return {
      items: resp.dialogues ?? [],
      nextPageToken: resp.next_page_token ?? null,
    };
  }

  /** Async iterator over all dialogues */
  async *listDialoguesIter(req: Omit<ListDialoguesRequest, "page_token"> = {}, init?: RequestInit) {
    let pageToken: string | undefined = undefined;
    do {
      const page = await this.listDialogues({ ...req, page_token: pageToken }, init);
      for (const d of page.items) yield d;
      pageToken = page.nextPageToken ?? undefined;
    } while (pageToken);
  }

  /**
   * Stream dialogue events as AsyncIterable via SSE.
   * Falls back to long-lived HTTP stream; consumer can `for await (const ev of client.streamDialogue(id))`.
   */
  async *streamDialogue(dialogueId: UUID, opts?: { fromEventId?: UUID; signal?: AbortSignal }): AsyncIterable<DialogueEvent> {
    const q = { from_event_id: opts?.fromEventId };
    const url = this.makeUrl("/api/v1/dialogues/" + encodeURIComponent(dialogueId) + "/events", q);
    const { controller, signal } = this.abortWith(opts?.signal, undefined); // no timeout for streams; manage via signal
    const id = genRequestId();
    const init: RequestInit = {
      method: "GET",
      headers: await this.buildHeaders("GET", url, undefined, id),
      signal,
    };
    this.onRequest?.({ id, method: "GET", url, init });
    const startedAt = Date.now();
    const res = await this.fetchFn(url, init);
    const dur = Date.now() - startedAt;
    this.onResponse?.({ id, method: "GET", url, status: res.status, headers: res.headers, durationMs: dur });
    if (!res.ok || !/^text\/event-stream/i.test(res.headers.get("content-type") || "")) {
      controller.abort();
      let body: any = undefined;
      try {
        body = await safeJson(res);
      } catch {
        body = await res.text().catch(() => undefined);
      }
      throw new MythosHttpError({
        message: `SSE handshake failed (${res.status})`,
        status: res.status,
        method: "GET",
        url,
        headers: res.headers,
        body,
      });
    }

    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let idx: number;
        while ((idx = buffer.indexOf("\n\n")) >= 0) {
          const chunk = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          const evt = parseSSEEvent(chunk);
          if (evt?.event === "message" || !evt?.event) {
            if (evt.data) {
              try {
                const obj: DialogueEvent = JSON.parse(evt.data);
                yield obj;
              } catch {
                // ignore malformed
              }
            }
          }
        }
      }
    } finally {
      controller.abort();
    }
  }

  // ------------- Core HTTP -------------

  private async request<T>(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    opts?: {
      query?: Record<string, any>;
      body?: any;
      init?: RequestInit;
      timeoutMs?: number;
      idempotent?: boolean; // adds Idempotency-Key for non-GET
    },
  ): Promise<T> {
    const url = this.makeUrl(path, opts?.query);
    const id = genRequestId();
    const headers = await this.buildHeaders(method, url, opts?.body, id, opts?.idempotent);
    const retry = this.retry;
    let attempt = 0;
    let lastErr: any;

    while (attempt <= retry.retries) {
      const timeoutMs = opts?.timeoutMs ?? this.timeoutMs;
      const { controller, signal, clearTimeoutFn } = this.abortWith(undefined, timeoutMs);

      const init: RequestInit = {
        method,
        headers,
        signal,
        body: bodyToPayload(opts?.body),
        ...opts?.init,
      };

      this.onRequest?.({ id, method, url, init });

      const startedAt = Date.now();
      try {
        const res = await this.fetchFn(url, init);
        const duration = Date.now() - startedAt;
        this.onResponse?.({ id, method, url, status: res.status, headers: res.headers, durationMs: duration });

        if (res.ok) {
          clearTimeoutFn();
          return (await safeJson(res)) as T;
        }

        // Non-OK
        const status = res.status;
        const body = await safeJson(res).catch(() => undefined);

        // Retry logic
        if (retry.retryOn?.(status)) {
          attempt++;
          clearTimeoutFn();

          let delay = expoDelay(attempt, retry);
          if (retry.respectRetryAfter) {
            const ra = parseRetryAfter(res.headers.get("retry-after"));
            if (ra !== null) delay = Math.max(delay, ra);
          }
          await sleep(delay);
          continue;
        }

        // No retry -> throw
        clearTimeoutFn();
        throw new MythosHttpError({
          message: `HTTP ${status} for ${method} ${url}`,
          status,
          method,
          url,
          headers: res.headers,
          body,
        });
      } catch (err: any) {
        clearTimeoutFn();

        // AbortError or network error -> retry if attempts remain
        const isAbort = err?.name === "AbortError";
        const isNetwork = err?.name === "TypeError" || err?.code === "ECONNRESET";
        if ((isAbort || isNetwork) && attempt < retry.retries) {
          attempt++;
          await sleep(expoDelay(attempt, retry));
          lastErr = err;
          continue;
        }
        throw err;
      }
    }
    throw lastErr ?? new Error("Unknown request failure");
  }

  private async buildHeaders(
    method: string,
    url: string,
    body?: any,
    requestId?: string,
    idempotent?: boolean,
  ): Promise<Record<string, string>> {
    const h: Record<string, string> = {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-Request-Id": requestId ?? genRequestId(),
      "X-Client-Version": "mythos-ts-sdk/1.0.0",
      ...this.defaultHeaders,
    };
    if (this.userAgent && typeof (globalThis as any).process !== "undefined") {
      h["User-Agent"] = this.userAgent;
    }

    // Auth
    if (this.auth?.apiKey) {
      h[this.auth.headerName || "X-API-Key"] = this.auth.apiKey;
    }
    const t = await resolveMaybePromise(this.auth?.getToken?.());
    if (t) h["Authorization"] = `Bearer ${t}`;

    // Idempotency for non-GET if requested
    if (idempotent && method !== "GET") {
      h["Idempotency-Key"] = genRequestId();
    }

    return h;
  }

  private makeUrl(path: string, query?: Record<string, any>): string {
    const url = path.startsWith("http") ? path : `${this.base}${path}`;
    return withQuery(url, query as any);
  }

  private abortWith(external?: AbortSignal, timeoutMs?: number): {
    controller: AbortController;
    signal: AbortSignal;
    clearTimeoutFn: () => void;
  } {
    const controller = new AbortController();
    const signals: AbortSignal[] = [controller.signal];
    let timeoutHandle: any = undefined;

    if (external) {
      external.addEventListener("abort", () => controller.abort(external.reason), { once: true });
      signals.push(external);
    }
    if (timeoutMs && timeoutMs > 0) {
      timeoutHandle = setTimeout(() => controller.abort(new Error("Request timed out")), timeoutMs);
    }
    const clearTimeoutFn = () => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
    };

    // NOTE: composing signals is handled by aborting controller on external abort/timeout
    return { controller, signal: controller.signal, clearTimeoutFn };
  }
}

// -------------------------------
// Utilities
// -------------------------------

function bodyToPayload(body: any): BodyInit | null | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string" || body instanceof ArrayBuffer || body instanceof Blob) return body as any;
  return JSON.stringify(body);
}

async function safeJson(res: Response): Promise<any> {
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("json")) {
    const txt = await res.text();
    try {
      return JSON.parse(txt);
    } catch {
      return txt;
    }
  }
  return res.json();
}

function parseRetryAfter(v: string | null): number | null {
  if (!v) return null;
  const secs = Number(v);
  if (!Number.isNaN(secs)) return secs * 1000;
  const date = Date.parse(v);
  if (!Number.isNaN(date)) {
    const ms = date - Date.now();
    return ms > 0 ? ms : 0;
  }
  return null;
}

function prefixed(prefix: string, obj?: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  if (!obj) return out;
  for (const [k, v] of Object.entries(obj)) out[`${prefix}${k}`] = v;
  return out;
}

async function resolveMaybePromise<T>(v: Promise<T> | T | undefined | null): Promise<T | undefined> {
  if (v && typeof (v as any).then === "function") {
    return await (v as Promise<T>);
  }
  return (v as T) ?? undefined;
}

// ---------- SSE parser (minimal) ----------
function parseSSEEvent(chunk: string): { event?: string; data?: string; id?: string } | null {
  const lines = chunk.split(/\r?\n/);
  const out: any = {};
  for (const ln of lines) {
    if (!ln || ln.startsWith(":")) continue;
    const idx = ln.indexOf(":");
    const field = idx >= 0 ? ln.slice(0, idx) : ln;
    const value = idx >= 0 ? ln.slice(idx + 1).trimStart() : "";
    if (field === "event") out.event = value;
    else if (field === "data") out.data = (out.data ? out.data + "\n" : "") + value;
    else if (field === "id") out.id = value;
  }
  return Object.keys(out).length ? out : null;
}

// -------------------------------
// End of Mythos TS SDK client
// -------------------------------
