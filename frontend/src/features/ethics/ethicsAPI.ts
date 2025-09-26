// frontend/src/features/ethics/ethicsAPI.ts
// Industrial-grade Ethics API client for a Vite/React codebase.
// Features:
// - Zod schemas for runtime validation
// - Exponential backoff with jitter and retry budget
// - Timeout & cancellation via AbortController
// - Idempotency and correlation headers (X-Idempotency-Key, X-Request-ID)
// - ETag caching (If-None-Match / 304 handling)
// - Minimal side effects; pluggable telemetry hooks
// - Safe bearer token injection via provided getter
// - Narrow, composable API surface with strict input/output types

import { z } from "zod";

// -------------------------------
// Environment / configuration
// -------------------------------
const BASE_URL =
  (typeof import.meta !== "undefined" &&
    (import.meta as any).env &&
    (import.meta as any).env.VITE_API_URL) ||
  process.env.VITE_API_URL ||
  "/api"; // sensible default behind reverse-proxy

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_RETRIES = 2; // total attempts = 1 + retries
const RETRY_BASE_MS = 300;

// Optional token source (inject from auth slice)
type TokenGetter = () => string | null | undefined;

// Telemetry hooks for observability
export type TelemetryHook = (event: {
  op: string;
  method: string;
  url: string;
  status?: number;
  durationMs?: number;
  requestId?: string;
  error?: unknown;
}) => void;

interface EthicsApiOptions {
  getToken?: TokenGetter;
  onEvent?: TelemetryHook;
  baseUrl?: string;
  timeoutMs?: number;
  retries?: number;
}

// -------------------------------
// Shared utilities
// -------------------------------
const uuid = (): string =>
  (crypto?.randomUUID?.() ??
    "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    })) as string;

const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

const calcBackoff = (attempt: number) => {
  const base = RETRY_BASE_MS * 2 ** attempt;
  const jitter = Math.floor(Math.random() * 0.25 * base);
  return base + jitter;
};

const isRetryable = (status?: number, error?: unknown) => {
  if (error instanceof DOMException && error.name === "AbortError") return false;
  if (status && [502, 503, 504, 429].includes(status)) return true;
  return false;
};

// In-memory ETag cache
const etagCache = new Map<string, { etag: string; payload: unknown; ts: number }>();

// -------------------------------
// Zod schemas and types
// -------------------------------
const MetaSchema = z.object({
  request_id: z.string(),
  idempotency_key: z.string().optional().nullable(),
  timestamp: z.string(), // ISO
});

const PolicySchema = z.object({
  id: z.string(),
  name: z.string(),
  version: z.string(),
  updated_at: z.string(),
  description: z.string().optional(),
  rules: z
    .array(
      z.object({
        code: z.string(),
        title: z.string(),
        severity: z.enum(["low", "medium", "high", "critical"]),
        description: z.string().optional(),
      })
    )
    .default([]),
});

const PolicyListSchema = z.object({
  items: z.array(PolicySchema),
  meta: MetaSchema,
});

const EvaluateTextRequestSchema = z.object({
  text: z.string().min(1).max(50_000),
  context: z.object({ lang: z.string().optional(), source: z.string().optional() }).optional(),
  policy_id: z.string().optional(),
});

const EvaluationSchema = z.object({
  score: z.number().min(0).max(1),
  label: z.enum(["allow", "review", "block"]),
  reasons: z.array(z.string()).default([]),
});

const EvaluateTextResponseSchema = z.object({
  evaluation: EvaluationSchema,
  policy: PolicySchema.optional(),
  meta: MetaSchema,
});

const AssessmentRequestSchema = z.object({
  subject_id: z.string(),
  subject_type: z.enum(["text", "image", "user", "post", "transaction"]),
  evidence: z.record(z.any()).default({}),
  policy_id: z.string().optional(),
  idempotency_key: z.string().optional(),
});

const AssessmentResponseSchema = z.object({
  assessment_id: z.string(),
  decision: z.enum(["allow", "review", "block"]),
  evaluation: EvaluationSchema,
  meta: MetaSchema,
});

const DecisionSchema = z.object({
  assessment_id: z.string(),
  decision: z.enum(["allow", "review", "block"]),
  updated_at: z.string(),
  notes: z.string().optional(),
  meta: MetaSchema,
});

const IncidentLogRequestSchema = z.object({
  category: z.enum(["policy_violation", "appeal", "false_positive", "false_negative", "system"]),
  subject_id: z.string(),
  details: z.string().min(1).max(10_000),
  severity: z.enum(["low", "medium", "high", "critical"]).default("medium"),
  attachments: z.array(z.string().url()).optional(),
});

const IncidentLogResponseSchema = z.object({
  incident_id: z.string(),
  created_at: z.string(),
  meta: MetaSchema,
});

const AuditQuerySchema = z.object({
  page: z.number().int().min(1).default(1),
  size: z.number().int().min(1).max(200).default(20),
  subject_id: z.string().optional(),
  decision: z.enum(["allow", "review", "block"]).optional(),
});

const AuditEntrySchema = z.object({
  assessment_id: z.string(),
  subject_id: z.string(),
  decision: z.enum(["allow", "review", "block"]),
  created_at: z.string(),
});

const AuditResponseSchema = z.object({
  items: z.array(AuditEntrySchema),
  page: z.number().int(),
  size: z.number().int(),
  total: z.number().int().nonnegative(),
  meta: MetaSchema,
});

// Exported TS types
export type Policy = z.infer<typeof PolicySchema>;
export type PolicyList = z.infer<typeof PolicyListSchema>;
export type EvaluateTextRequest = z.infer<typeof EvaluateTextRequestSchema>;
export type EvaluateTextResponse = z.infer<typeof EvaluateTextResponseSchema>;
export type AssessmentRequest = z.infer<typeof AssessmentRequestSchema>;
export type AssessmentResponse = z.infer<typeof AssessmentResponseSchema>;
export type Decision = z.infer<typeof DecisionSchema>;
export type IncidentLogRequest = z.infer<typeof IncidentLogRequestSchema>;
export type IncidentLogResponse = z.infer<typeof IncidentLogResponseSchema>;
export type AuditQuery = z.infer<typeof AuditQuerySchema>;
export type AuditResponse = z.infer<typeof AuditResponseSchema>;

// -------------------------------
// Core HTTP layer
// -------------------------------
class Http {
  constructor(
    private readonly opts: Required<Pick<EthicsApiOptions, "onEvent">> &
      Pick<EthicsApiOptions, "getToken" | "timeoutMs" | "retries"> & { baseUrl: string }
  ) {}

  private makeHeaders(extra?: HeadersInit, idemKey?: string, reqId?: string) {
    const h = new Headers(extra ?? {});
    h.set("Accept", "application/json");
    if (!h.has("Content-Type")) h.set("Content-Type", "application/json");
    h.set("X-Request-ID", reqId ?? uuid());
    if (idemKey) h.set("X-Idempotency-Key", idemKey);
    const token = this.opts.getToken?.();
    if (token) h.set("Authorization", `Bearer ${token}`);
    return h;
  }

  private etagKey(method: string, url: string, body?: unknown) {
    // Cache only GET
    if (method.toUpperCase() !== "GET") return null;
    return `${method}:${url}`;
  }

  async request<T>({
    op,
    method,
    path,
    query,
    body,
    schema,
    idempotencyKey,
    headers,
    signal,
  }: {
    op: string;
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
    path: string;
    query?: Record<string, string | number | boolean | undefined>;
    body?: unknown;
    schema: z.ZodType<T>;
    idempotencyKey?: string;
    headers?: HeadersInit;
    signal?: AbortSignal;
  }): Promise<{ data: T; requestId?: string; status: number }> {
    const url = new URL(path, this.opts.baseUrl);
    if (query) {
      Object.entries(query).forEach(([k, v]) => {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      });
    }

    const reqId = uuid();
    const start = performance.now();
    const maxAttempts = 1 + (this.opts.retries ?? DEFAULT_RETRIES);

    // ETag preflight
    const etagKey = this.etagKey(method, url.toString(), body);
    const cached = etagKey ? etagCache.get(etagKey) : null;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const ac = new AbortController();
      const timeout = setTimeout(() => ac.abort(), this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
      const combined = signal
        ? new AbortController()
        : ac; // If external signal provided, we cascade aborts
      if (signal) {
        signal.addEventListener("abort", () => ac.abort(), { once: true });
      }

      try {
        const h = this.makeHeaders(headers, idempotencyKey, reqId);
        if (cached?.etag) h.set("If-None-Match", cached.etag);

        const res = await fetch(url.toString(), {
          method,
          headers: h,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: ac.signal,
          cache: "no-store",
          redirect: "follow",
        });

        const durationMs = Math.round(performance.now() - start);
        const status = res.status;
        const resReqId = res.headers.get("x-request-id") ?? reqId;

        // 304 Not Modified → serve cache
        if (status === 304 && cached) {
          this.opts.onEvent({
            op,
            method,
            url: url.toString(),
            status,
            durationMs,
            requestId: resReqId,
          });
          const data = schema.parse(cached.payload);
          return { data, requestId: resReqId, status };
        }

        const text = await res.text();
        const json = text ? (JSON.parse(text) as unknown) : ({} as unknown);

        if (!res.ok) {
          if (isRetryable(status)) {
            if (attempt + 1 < maxAttempts) {
              const backoff = calcBackoff(attempt);
              await sleep(backoff);
              continue;
            }
          }
          // Normalize error payloads
          let detail: unknown;
          try {
            detail = (json as any)?.detail ?? json;
          } catch {
            detail = text;
          }
          this.opts.onEvent({
            op,
            method,
            url: url.toString(),
            status,
            durationMs,
            requestId: resReqId,
            error: detail,
          });
          throw new Error(
            `HTTP ${status} for ${method} ${url.toString()} — ${typeof detail === "string" ? detail : JSON.stringify(detail)}`
          );
        }

        // Validate and cache ETag for GET
        const data = schema.parse(json);
        const etag = res.headers.get("etag");
        if (etagKey && etag) {
          etagCache.set(etagKey, { etag, payload: data as unknown, ts: Date.now() });
        }

        this.opts.onEvent({
          op,
          method,
          url: url.toString(),
          status,
          durationMs,
          requestId: resReqId,
        });

        return { data, requestId: resReqId, status };
      } catch (err: any) {
        if (isRetryable(undefined, err) && attempt + 1 < maxAttempts) {
          const backoff = calcBackoff(attempt);
          await sleep(backoff);
          continue;
        }
        this.opts.onEvent({
          op,
          method,
          url: url.toString(),
          error: err,
          requestId: reqId,
        });
        throw err;
      } finally {
        clearTimeout(timeout);
      }
    }
    // Should be unreachable
    throw new Error(`Exhausted retries for ${method} ${path}`);
  }
}

// -------------------------------
// Ethics API client
// -------------------------------
export class EthicsAPI {
  private http: Http;

  constructor(opts: EthicsApiOptions = {}) {
    this.http = new Http({
      baseUrl: (opts.baseUrl ?? BASE_URL).replace(/\/+$/, "") + "/ethics",
      getToken: opts.getToken,
      onEvent: opts.onEvent ?? (() => {}),
      timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      retries: opts.retries ?? DEFAULT_RETRIES,
    });
  }

  // GET /ethics/policies
  async listPolicies(): Promise<PolicyList> {
    const { data } = await this.http.request({
      op: "listPolicies",
      method: "GET",
      path: "/policies",
      schema: PolicyListSchema,
    });
    return data;
  }

  // GET /ethics/policies/:id
  async getPolicy(id: string): Promise<Policy> {
    const { data } = await this.http.request({
      op: "getPolicy",
      method: "GET",
      path: `/policies/${encodeURIComponent(id)}`,
      schema: PolicySchema.extend({ meta: MetaSchema }).transform((v) => {
        // strip meta for consumer convenience
        // @ts-expect-error meta is intentionally dropped
        const { meta, ...rest } = v;
        return rest as Policy;
      }),
    });
    return data;
  }

  // POST /ethics/evaluate/text
  async evaluateText(payload: EvaluateTextRequest, signal?: AbortSignal): Promise<EvaluateTextResponse> {
    const body = EvaluateTextRequestSchema.parse(payload);
    const { data } = await this.http.request({
      op: "evaluateText",
      method: "POST",
      path: "/evaluate/text",
      body,
      schema: EvaluateTextResponseSchema,
      signal,
    });
    return data;
  }

  // POST /ethics/assessments
  async submitAssessment(req: AssessmentRequest): Promise<AssessmentResponse> {
    const parsed = AssessmentRequestSchema.parse(req);
    // If caller didn't provide idempotency key — generate one
    const idem = parsed.idempotency_key ?? uuid();
    const { data } = await this.http.request({
      op: "submitAssessment",
      method: "POST",
      path: "/assessments",
      body: parsed,
      idempotencyKey: idem,
      schema: AssessmentResponseSchema,
    });
    return data;
  }

  // GET /ethics/assessments/:id/decision
  async getDecision(assessmentId: string): Promise<Decision> {
    const { data } = await this.http.request({
      op: "getDecision",
      method: "GET",
      path: `/assessments/${encodeURIComponent(assessmentId)}/decision`,
      schema: DecisionSchema,
    });
    return data;
  }

  // POST /ethics/incidents
  async logIncident(req: IncidentLogRequest): Promise<IncidentLogResponse> {
    const body = IncidentLogRequestSchema.parse(req);
    const { data } = await this.http.request({
      op: "logIncident",
      method: "POST",
      path: "/incidents",
      body,
      schema: IncidentLogResponseSchema,
      idempotencyKey: uuid(),
    });
    return data;
  }

  // GET /ethics/audit
  async getAudit(query: AuditQuery): Promise<AuditResponse> {
    const q = AuditQuerySchema.parse(query);
    const { data } = await this.http.request({
      op: "getAudit",
      method: "GET",
      path: "/audit",
      query: q as Record<string, any>,
      schema: AuditResponseSchema,
    });
    return data;
  }
}

// -------------------------------
// Singleton export
// -------------------------------
let _singleton: EthicsAPI | null = null;

/**
 * Returns a shared singleton configured with default env and no telemetry.
 * Prefer explicit instantiation when you need custom hooks or baseUrl.
 */
export const ethicsAPI = () => {
  if (_singleton) return _singleton;
  _singleton = new EthicsAPI();
  return _singleton;
};

// -------------------------------
// Non-throwing helper wrappers
// -------------------------------
export async function safeEvaluateText(
  payload: EvaluateTextRequest,
  signal?: AbortSignal
): Promise<{ ok: true; data: EvaluateTextResponse } | { ok: false; error: Error }> {
  try {
    const data = await ethicsAPI().evaluateText(payload, signal);
    return { ok: true, data };
  } catch (e: any) {
    return { ok: false, error: e instanceof Error ? e : new Error(String(e)) };
  }
}
