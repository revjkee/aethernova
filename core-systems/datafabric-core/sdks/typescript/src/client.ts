/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * datafabric-core TypeScript SDK — industrial grade client
 * Coverage: health, metrics, policies, rules, schemas/validate, audit/logs, events
 * Features: OAuth2 client-credentials, API Key, retries, backoff, timeout, AbortController,
 *           idempotency keys, ETag/If-Match, pagination iterators, strict types, RFC7807 errors.
 */

export type UUID = string; // v4
export type ISODateTime = string; // ISO 8601

// ------------------------------- Domain Types (aligned with OpenAPI) -------------------------------

export type PolicyStatus = 'active' | 'inactive' | 'deprecated' | 'archived';
export type RuleType =
  | 'access_control'
  | 'data_retention'
  | 'encryption'
  | 'masking'
  | 'validation'
  | 'custom';
export type RuleEffect = 'allow' | 'deny' | 'log' | 'alert';

export interface Rule {
  id: UUID;
  type: RuleType;
  parameters: Record<string, any>;
  effect: RuleEffect;
  priority?: number; // 1..100, default 50
}

export interface RuleCreate {
  type: RuleType;
  parameters: Record<string, any>;
  effect: RuleEffect;
  priority?: number;
}

export type RuleUpdate = RuleCreate;

export interface Policy {
  id: UUID;
  version: string; // semver
  name: string;
  description: string;
  status: PolicyStatus;
  tags?: string[];
  rules: Rule[];
  owner?: string;
  createdAt: ISODateTime;
  updatedAt: ISODateTime;
  etag?: string;
}

export interface PolicyCreate {
  name: string;
  description: string;
  status: PolicyStatus;
  tags?: string[];
  version?: string; // default 1.0.0
  rules?: RuleCreate[];
}

export interface PolicyUpdate {
  name: string;
  description: string;
  status: PolicyStatus;
  tags?: string[];
  version?: string;
  rules?: RuleUpdate[];
}

export interface ValidationErrorItem {
  instancePath: string;
  schemaPath: string;
  message: string;
  params?: Record<string, any>;
}

export interface ValidationResult {
  valid: boolean;
  errors?: ValidationErrorItem[];
  schemaRef?: string;
  traceId?: string;
}

export interface AuditActor {
  type: 'user' | 'service';
  id: string;
}

export interface AuditLog {
  id: UUID;
  timestamp: ISODateTime;
  actor: AuditActor;
  action: string;
  subjectId: string;
  outcome: 'success' | 'failure';
  details?: Record<string, any>;
}

export interface EventEnvelope {
  id: UUID;
  type: string;
  source: string; // URI
  time: ISODateTime;
  subject?: string;
  data: Record<string, any>;
  datacontenttype?: string; // default application/json
}

export interface Ack {
  accepted: true;
  traceId: string;
}

export interface PageMeta {
  page: number;
  perPage: number;
  total: number;
}

export interface Page<T> {
  items: T[];
  meta: PageMeta;
}

export interface Health {
  status: 'ok' | 'degraded' | 'down';
  details?: Record<string, any>;
}

// RFC 7807
export interface ProblemDetails {
  type: string; // URI
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  traceId?: string;
  errors?: ValidationErrorItem[];
}

// ------------------------------- Errors -------------------------------

export class ApiError extends Error {
  public status: number;
  public problem?: ProblemDetails;
  public responseHeaders: Headers;
  public bodyText?: string;

  constructor(message: string, status: number, responseHeaders: Headers, problem?: ProblemDetails, bodyText?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.problem = problem;
    this.responseHeaders = responseHeaders;
    this.bodyText = bodyText;
  }
}

// ------------------------------- Config / Auth -------------------------------

export interface OAuth2ClientCredentials {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scopes?: string[];
  audience?: string;
  extraParams?: Record<string, string>;
}

export type AuthConfig =
  | { kind: 'none' }
  | { kind: 'apiKey'; apiKey: string; headerName?: string } // default X-API-Key
  | { kind: 'oauth2'; oauth2: OAuth2ClientCredentials };

export interface RetryPolicy {
  maxRetries: number; // e.g. 5
  baseDelayMs: number; // e.g. 200
  maxDelayMs: number;  // e.g. 5000
  retryOn: number[];   // default [429, 502, 503, 504]
}

export interface ClientOptions {
  baseUrl: string; // e.g. https://api.neurocity.ai/datafabric/v1
  auth?: AuthConfig;
  timeoutMs?: number; // request timeout
  defaultHeaders?: Record<string, string>;
  retry?: RetryPolicy;
  userAgent?: string; // appended to requests
  fetchImpl?: typeof fetch; // custom fetch (node ponyfill)
}

type TokenCache = { token: string; expiresAt: number };

// ------------------------------- Utilities -------------------------------

const defaultRetry: RetryPolicy = {
  maxRetries: 5,
  baseDelayMs: 200,
  maxDelayMs: 5000,
  retryOn: [429, 502, 503, 504],
};

// random UUID v4 (fallback if crypto.randomUUID not available)
function uuidv4(): string {
  const g: any = (globalThis as any);
  if (g.crypto && typeof g.crypto.randomUUID === 'function') {
    return g.crypto.randomUUID();
  }
  // Minimal fallback
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const toHex = (n: number) => n.toString(16).padStart(2, '0');
  const hex = Array.from(bytes).map(toHex).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function computeBackoff(attempt: number, base: number, max: number): number {
  const jitter = Math.random() * base;
  const delay = Math.min(max, Math.round((2 ** (attempt - 1)) * base + jitter));
  return delay;
}

function isJsonContent(headers: Headers): boolean {
  const ct = headers.get('content-type') || '';
  return ct.includes('application/json') || ct.includes('+json');
}

// ------------------------------- HTTP Core -------------------------------

export class DataFabricClient {
  private readonly baseUrl: string;
  private readonly auth?: AuthConfig;
  private readonly timeoutMs: number;
  private readonly retry: RetryPolicy;
  private readonly defaultHeaders: Record<string, string>;
  private readonly fetchImpl: typeof fetch;
  private readonly userAgent?: string;
  private tokenCache?: TokenCache;

  constructor(opts: ClientOptions) {
    if (!opts?.baseUrl) throw new Error('baseUrl is required');
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.auth = opts.auth ?? { kind: 'none' };
    this.timeoutMs = opts.timeoutMs ?? 15000;
    this.retry = opts.retry ?? defaultRetry;
    this.defaultHeaders = { ...(opts.defaultHeaders ?? {}) };
    this.fetchImpl = opts.fetchImpl ?? (globalThis.fetch?.bind(globalThis) as typeof fetch);
    if (!this.fetchImpl) throw new Error('fetch implementation is required (provide fetchImpl in Node).');
    this.userAgent = opts.userAgent;
  }

  // --------------------------- Auth handling ---------------------------

  private async getAuthHeader(): Promise<Record<string, string>> {
    if (!this.auth || this.auth.kind === 'none') return {};
    if (this.auth.kind === 'apiKey') {
      const header = this.auth.headerName ?? 'X-API-Key';
      return { [header]: this.auth.apiKey };
    }
    // OAuth2 client-credentials
    const now = Date.now();
    if (this.tokenCache && this.tokenCache.expiresAt - 5000 > now) {
      return { Authorization: `Bearer ${this.tokenCache.token}` };
    }
    const token = await this.fetchOAuth2Token(this.auth.oauth2);
    const expiresAt = Date.now() + (token.expires_in ?? 3600) * 1000;
    this.tokenCache = { token: token.access_token, expiresAt };
    return { Authorization: `Bearer ${token.access_token}` };
  }

  private async fetchOAuth2Token(cfg: OAuth2ClientCredentials): Promise<{ access_token: string; expires_in?: number }> {
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
    });
    if (cfg.scopes?.length) body.set('scope', cfg.scopes.join(' '));
    if (cfg.audience) body.set('audience', cfg.audience);
    if (cfg.extraParams) for (const [k, v] of Object.entries(cfg.extraParams)) body.set(k, v);

    const resp = await this.fetchImpl(cfg.tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => undefined);
      throw new Error(`OAuth2 token request failed: ${resp.status} ${resp.statusText} ${text ?? ''}`);
    }
    return resp.json();
  }

  // --------------------------- Core request ---------------------------

  private async request<T>(
    path: string,
    init: RequestInit & {
      expectedStatus?: number | number[];
      idempotent?: boolean;
      traceId?: string;
      timeoutMs?: number;
    } = {},
  ): Promise<{ data: T; res: Response }> {
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`;
    const expected = Array.isArray(init.expectedStatus) ? init.expectedStatus : [init.expectedStatus ?? 200];
    const idempotent = init.idempotent ?? false;
    const timeoutMs = init.timeoutMs ?? this.timeoutMs;

    // Build headers
    const headers = new Headers({
      'accept': 'application/json',
      ...this.defaultHeaders,
      ...(init.headers as Record<string, string>),
    });

    // User-Agent (where allowed)
    if (this.userAgent && !headers.has('User-Agent')) {
      try { headers.set('User-Agent', this.userAgent); } catch { /* ignore in browsers */ }
    }

    // Auth
    const authHeader = await this.getAuthHeader();
    for (const [k, v] of Object.entries(authHeader)) headers.set(k, v);

    // Trace ID
    const traceId = init.traceId ?? headers.get('X-Trace-Id') ?? uuidv4();
    headers.set('X-Trace-Id', traceId);

    // Idempotency-Key
    if (idempotent && !headers.get('Idempotency-Key')) {
      headers.set('Idempotency-Key', uuidv4());
    }

    // Content-type defaults
    const method = (init.method ?? 'GET').toUpperCase();
    const hasBody = init.body !== undefined && init.body !== null;
    if (hasBody && typeof init.body === 'object' && !(init.body instanceof FormData)) {
      headers.set('content-type', headers.get('content-type') ?? 'application/json');
    }

    // Timeout with AbortController
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(new Error(`Request timeout after ${timeoutMs}ms`)), timeoutMs);

    let attempt = 0;
    let lastError: any;

    try {
      while (attempt <= this.retry.maxRetries) {
        attempt += 1;
        let bodyToSend: BodyInit | undefined;
        if (hasBody) {
          const ct = headers.get('content-type') ?? '';
          if (ct.includes('application/json')) {
            bodyToSend = JSON.stringify(init.body);
          } else if (init.body instanceof FormData) {
            bodyToSend = init.body as any;
            headers.delete('content-type'); // let fetch set boundary
          } else {
            bodyToSend = init.body as any;
          }
        }

        let res: Response;
        try {
          res = await this.fetchImpl(url, {
            ...init,
            method,
            headers,
            body: bodyToSend,
            signal: ac.signal,
          });
        } catch (err: any) {
          lastError = err;
          // network error: retry if attempts remain
          if (attempt <= this.retry.maxRetries) {
            await sleep(computeBackoff(attempt, this.retry.baseDelayMs, this.retry.maxDelayMs));
            continue;
          }
          throw err;
        }

        // Handle expected success
        if (expected.includes(res.status)) {
          let data: any;
          if (method === 'GET' && (isJsonContent(res.headers) || res.headers.get('content-type')?.includes('text/plain'))) {
            data = isJsonContent(res.headers) ? await res.json().catch(async () => await res.text()) : await res.text();
          } else if (isJsonContent(res.headers)) {
            data = await res.json().catch(async () => await res.text());
          } else {
            // for metrics/text endpoints
            const text = await res.text();
            data = (text as any);
          }
          return { data: data as T, res };
        }

        // Retry on configured status
        if (this.retry.retryOn.includes(res.status) && attempt <= this.retry.maxRetries) {
          const retryAfter = parseInt(res.headers.get('Retry-After') ?? '', 10);
          const delay = Number.isFinite(retryAfter) ? retryAfter * 1000 : computeBackoff(attempt, this.retry.baseDelayMs, this.retry.maxDelayMs);
          await sleep(delay);
          continue;
        }

        // Build ApiError with ProblemDetails if JSON
        let problem: ProblemDetails | undefined;
        let bodyText: string | undefined;
        if (isJsonContent(res.headers)) {
          try { problem = await res.json(); } catch { /* ignore */ }
        }
        if (!problem) {
          try { bodyText = await res.text(); } catch { /* ignore */ }
        }
        const title = problem?.title ?? res.statusText ?? 'HTTP Error';
        throw new ApiError(title, res.status, res.headers, problem, bodyText);
      }

      // If loop exits without return
      if (lastError) throw lastError;
      throw new Error('Unexpected request loop termination');
    } finally {
      clearTimeout(t);
    }
  }

  // ------------------------------- Helpers: pagination -------------------------------

  /**
   * Async iterator over paginated resources.
   */
  private async *paginate<T>(fetchPage: (page: number) => Promise<Page<T>>): AsyncGenerator<T, void, unknown> {
    let page = 1;
    while (true) {
      const p = await fetchPage(page);
      for (const item of p.items) yield item;
      const totalPages = Math.max(1, Math.ceil(p.meta.total / p.meta.perPage));
      if (page >= totalPages) break;
      page += 1;
    }
  }

  // ------------------------------- Public API Methods -------------------------------

  // ops
  async health(): Promise<Health> {
    const { data } = await this.request<Health>('/health', { method: 'GET', expectedStatus: 200, timeoutMs: 5000 });
    return data;
  }

  async metrics(): Promise<string> {
    const { data } = await this.request<string>('/metrics', {
      method: 'GET',
      expectedStatus: 200,
      timeoutMs: 5000,
      // Accept text/plain
      headers: { accept: 'text/plain' },
    });
    return data;
  }

  // policies
  async listPolicies(params?: {
    page?: number; perPage?: number; sort?: string; status?: PolicyStatus; q?: string;
  }): Promise<Page<Policy>> {
    const search = new URLSearchParams();
    if (params?.page) search.set('page', String(params.page));
    if (params?.perPage) search.set('perPage', String(params.perPage));
    if (params?.sort) search.set('sort', params.sort);
    if (params?.status) search.set('status', params.status);
    if (params?.q) search.set('q', params.q);
    const qs = search.toString() ? `?${search.toString()}` : '';
    const { data } = await this.request<Page<Policy>>(`/policies${qs}`, { method: 'GET', expectedStatus: 200 });
    return data;
  }

  iteratePolicies(params?: { perPage?: number; sort?: string; status?: PolicyStatus; q?: string; }): AsyncGenerator<Policy, void, unknown> {
    return this.paginate<Policy>(async (page) => this.listPolicies({ page, perPage: params?.perPage, sort: params?.sort, status: params?.status, q: params?.q }));
  }

  async createPolicy(body: PolicyCreate, opts?: { idempotent?: boolean }): Promise<Policy> {
    const { data, res } = await this.request<Policy>('/policies', {
      method: 'POST',
      body,
      idempotent: opts?.idempotent ?? true,
      expectedStatus: 201,
    });
    // attach ETag if present
    const etag = res.headers.get('ETag') ?? undefined;
    return { ...data, etag };
  }

  async getPolicy(policyId: UUID): Promise<Policy> {
    const { data, res } = await this.request<Policy>(`/policies/${encodeURIComponent(policyId)}`, { method: 'GET', expectedStatus: 200 });
    const etag = res.headers.get('ETag') ?? data.etag;
    return { ...data, etag };
  }

  async replacePolicy(policyId: UUID, body: PolicyUpdate, opts?: { ifMatch?: string; idempotent?: boolean }): Promise<Policy> {
    const headers: Record<string, string> = {};
    if (opts?.ifMatch) headers['If-Match'] = opts.ifMatch;
    const { data, res } = await this.request<Policy>(`/policies/${encodeURIComponent(policyId)}`, {
      method: 'PUT',
      body,
      headers,
      idempotent: opts?.idempotent ?? true,
      expectedStatus: 200,
    });
    const etag = res.headers.get('ETag') ?? data.etag;
    return { ...data, etag };
  }

  async patchPolicy(
    policyId: UUID,
    patch: Partial<PolicyUpdate>,
    opts?: { ifMatch?: string; idempotent?: boolean }
  ): Promise<Policy> {
    const headers: Record<string, string> = { 'content-type': 'application/merge-patch+json' };
    if (opts?.ifMatch) headers['If-Match'] = opts.ifMatch;
    const { data, res } = await this.request<Policy>(`/policies/${encodeURIComponent(policyId)}`, {
      method: 'PATCH',
      body: patch,
      headers,
      idempotent: opts?.idempotent ?? true,
      expectedStatus: 200,
    });
    const etag = res.headers.get('ETag') ?? data.etag;
    return { ...data, etag };
  }

  async deletePolicy(policyId: UUID): Promise<void> {
    await this.request<void>(`/policies/${encodeURIComponent(policyId)}`, { method: 'DELETE', expectedStatus: 204 });
  }

  // rules
  async listRules(policyId: UUID, params?: { page?: number; perPage?: number; sort?: string; type?: RuleType; }): Promise<Page<Rule>> {
    const search = new URLSearchParams();
    if (params?.page) search.set('page', String(params.page));
    if (params?.perPage) search.set('perPage', String(params.perPage));
    if (params?.sort) search.set('sort', params.sort);
    if (params?.type) search.set('type', params.type);
    const qs = search.toString() ? `?${search.toString()}` : '';
    const { data } = await this.request<Page<Rule>>(
      `/policies/${encodeURIComponent(policyId)}/rules${qs}`,
      { method: 'GET', expectedStatus: 200 },
    );
    return data;
  }

  iterateRules(policyId: UUID, params?: { perPage?: number; sort?: string; type?: RuleType; }): AsyncGenerator<Rule, void, unknown> {
    return this.paginate<Rule>(async (page) => this.listRules(policyId, { page, perPage: params?.perPage, sort: params?.sort, type: params?.type }));
  }

  async createRule(policyId: UUID, body: RuleCreate, opts?: { idempotent?: boolean }): Promise<Rule> {
    const { data } = await this.request<Rule>(
      `/policies/${encodeURIComponent(policyId)}/rules`,
      { method: 'POST', body, idempotent: opts?.idempotent ?? true, expectedStatus: 201 },
    );
    return data;
  }

  async getRule(policyId: UUID, ruleId: UUID): Promise<Rule> {
    const { data } = await this.request<Rule>(
      `/policies/${encodeURIComponent(policyId)}/rules/${encodeURIComponent(ruleId)}`,
      { method: 'GET', expectedStatus: 200 },
    );
    return data;
  }

  async replaceRule(policyId: UUID, ruleId: UUID, body: RuleUpdate, opts?: { ifMatch?: string; idempotent?: boolean }): Promise<Rule> {
    const headers: Record<string, string> = {};
    if (opts?.ifMatch) headers['If-Match'] = opts.ifMatch;
    const { data } = await this.request<Rule>(
      `/policies/${encodeURIComponent(policyId)}/rules/${encodeURIComponent(ruleId)}`,
      { method: 'PUT', body, headers, idempotent: opts?.idempotent ?? true, expectedStatus: 200 },
    );
    return data;
  }

  async deleteRule(policyId: UUID, ruleId: UUID): Promise<void> {
    await this.request<void>(
      `/policies/${encodeURIComponent(policyId)}/rules/${encodeURIComponent(ruleId)}`,
      { method: 'DELETE', expectedStatus: 204 },
    );
  }

  // schemas/validate
  async validateDocument(schemaId: string, document: Record<string, any>): Promise<ValidationResult> {
    const { data } = await this.request<ValidationResult>(
      `/schemas/validate`,
      {
        method: 'POST',
        body: { schemaId, document },
        expectedStatus: 200,
        idempotent: true,
      },
    );
    return data;
  }

  // audit/logs
  async listAuditLogs(params?: {
    page?: number; perPage?: number; sort?: string;
    subjectId?: UUID; action?: string; from?: ISODateTime; to?: ISODateTime;
  }): Promise<Page<AuditLog>> {
    const search = new URLSearchParams();
    if (params?.page) search.set('page', String(params.page));
    if (params?.perPage) search.set('perPage', String(params.perPage));
    if (params?.sort) search.set('sort', params.sort);
    if (params?.subjectId) search.set('subjectId', params.subjectId);
    if (params?.action) search.set('action', params.action);
    if (params?.from) search.set('from', params.from);
    if (params?.to) search.set('to', params.to);
    const qs = search.toString() ? `?${search.toString()}` : '';
    const { data } = await this.request<Page<AuditLog>>(`/audit/logs${qs}`, { method: 'GET', expectedStatus: 200 });
    return data;
  }

  iterateAuditLogs(params?: {
    perPage?: number; sort?: string; subjectId?: UUID; action?: string; from?: ISODateTime; to?: ISODateTime;
  }): AsyncGenerator<AuditLog, void, unknown> {
    return this.paginate<AuditLog>(async (page) => this.listAuditLogs({ page, perPage: params?.perPage, sort: params?.sort, subjectId: params?.subjectId, action: params?.action, from: params?.from, to: params?.to }));
  }

  // events
  async ingestEvent(event: EventEnvelope, opts?: { idempotent?: boolean }): Promise<Ack> {
    const { data } = await this.request<Ack>('/events', {
      method: 'POST',
      body: event,
      idempotent: opts?.idempotent ?? true,
      expectedStatus: 202,
    });
    return data;
  }

  async ingestEventsBatch(events: EventEnvelope[], opts?: { idempotent?: boolean }): Promise<Ack> {
    const { data } = await this.request<Ack>('/events', {
      method: 'PUT',
      body: events,
      idempotent: opts?.idempotent ?? true,
      expectedStatus: 202,
    });
    return data;
  }
}

// ------------------------------- Example Usage (commented) -------------------------------
/*
const client = new DataFabricClient({
  baseUrl: 'https://api.neurocity.ai/datafabric/v1',
  auth: {
    kind: 'oauth2',
    oauth2: {
      tokenUrl: 'https://auth.neurocity.ai/oauth2/token',
      clientId: process.env.CLIENT_ID!,
      clientSecret: process.env.CLIENT_SECRET!,
      scopes: ['policy:read', 'policy:write'],
    }
  },
  timeoutMs: 15000,
  retry: { maxRetries: 5, baseDelayMs: 200, maxDelayMs: 5000, retryOn: [429, 502, 503, 504] },
  userAgent: 'datafabric-sdk-ts/1.0.0',
  fetchImpl: fetch, // supply in Node if needed
});

(async () => {
  const health = await client.health();
  const p = await client.createPolicy({ name: 'Policy A', description: '...', status: 'active' });
  const updated = await client.patchPolicy(p.id, { description: 'Updated' }, { ifMatch: p.etag });
})();
*/
