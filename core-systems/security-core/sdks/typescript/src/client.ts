// File: security-core/sdks/typescript/src/client.ts
/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Aethernova Security SDK (TypeScript)
 * Industrial-grade client for AuthenticationService.
 * - Browser/Node compatible (requires fetch in runtime; can inject custom fetch)
 * - Safe logging with redaction
 * - Timeout + retry with decorrelated jitter, backoff on 429/5xx
 * - Token manager (access/refresh/id) with concurrency guard for refresh
 * - EventEmitter for auth state
 * - Storage adapters (Memory, LocalStorage) with namespacing
 * - WebAuthn helpers (create/get) with base64url utils
 * - Strong typing aligned with security-core/schemas/proto/v1/security/authn.proto
 */

///////////////////////////
// Minimal environment utils
///////////////////////////

const isBrowser = typeof window !== "undefined" && typeof window.document !== "undefined";
const nowEpochMs = () => Date.now();

function redact(value: string | undefined | null): string {
  if (!value) return "";
  if (value.length <= 8) return "****";
  return value.slice(0, 4) + "…" + value.slice(-3);
}

///////////////////////////
// Base64url utils for WebAuthn
///////////////////////////

const b64u = {
  encode: (data: ArrayBuffer): string => {
    const bytes = new Uint8Array(data);
    let str = "";
    for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    const b64 = (typeof btoa !== "undefined" ? btoa(str) : Buffer.from(str, "binary").toString("base64"))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
    return b64;
  },
  decode: (input: string): ArrayBuffer => {
    const b64 = input.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((input.length + 3) % 4);
    const bin = (typeof atob !== "undefined" ? atob(b64) : Buffer.from(b64, "base64").toString("binary"));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  },
};

///////////////////////////
// Types (mirroring authn.proto semantics)
///////////////////////////

export enum AuthMethod {
  PASSWORD = "PASSWORD",
  TOTP = "TOTP",
  WEBAUTHN = "WEBAUTHN",
  SMS_OTP = "SMS_OTP",
  EMAIL_OTP = "EMAIL_OTP",
  MAGIC_LINK = "MAGIC_LINK",
  OAUTH2_OIDC = "OAUTH2_OIDC",
  SAML2 = "SAML2",
  RECOVERY = "RECOVERY",
}

export enum TokenType {
  ACCESS = "ACCESS",
  REFRESH = "REFRESH",
  ID = "ID",
  SESSION = "SESSION",
}

export enum RiskLevel {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

export interface Principal {
  id: string;
  tenant_id?: string | null;
  external_id?: string | null;
  username?: string | null;
  email?: string | null;
  phone_e164?: string | null;
  display_name?: string | null;
  roles?: string[];
  disabled?: boolean;
  created_at?: string; // ISO
  updated_at?: string; // ISO
  attributes?: Record<string, string>;
}

export interface Device {
  id?: string | null;
  platform?:
    | "WEB"
    | "WINDOWS"
    | "MACOS"
    | "LINUX"
    | "ANDROID"
    | "IOS"
    | "IPADOS"
    | "OTHER"
    | null;
  os_version?: string | null;
  model?: string | null;
  user_agent?: string | null;
  fingerprint?: string | null;
  trusted?: boolean | null;
  compliant?: boolean | null;
  attested?: boolean | null;
  attestation_provider?: string | null;
  created_at?: string;
  last_seen_at?: string;
}

export interface RiskSignals {
  level?: RiskLevel;
  score?: number | null;
  reason?: string | null;
  anomalies?: string[];
  ip_address?: string | null;
  geoip_country?: string | null;
  geoip_city?: string | null;
  via_proxy?: boolean | null;
  via_tor?: boolean | null;
  velocity_exceeded?: boolean | null;
  historical_ips?: string[];
}

export interface ClientContext {
  request_id?: string | null;
  ip_address?: string | null;
  user_agent?: string | null;
  locale?: string | null;
  timezone?: string | null;
  device?: Device;
  headers?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

export interface Token {
  id?: string;
  type: TokenType;
  alg?: "ED25519" | "ES256" | "ES384" | "RS256" | "RS512";
  key_id?: string | null;
  issuer?: string | null;
  subject?: string | null;
  audience?: string[];
  issued_at?: string; // ISO
  expires_at?: string; // ISO
  not_before?: string; // ISO
  scopes?: string[];
  client_id?: string | null;
  session_id?: string | null;
  claims?: Record<string, unknown>;
  jwt_compact?: string; // when JWT
  paseto?: string; // opaque base64 if needed
  opaque?: string; // opaque reference
}

export interface Session {
  id: string;
  principal_id: string;
  methods?: AuthMethod[];
  device?: Device;
  ip_address?: string | null;
  user_agent?: string | null;
  location?: string | null;
  risk?: RiskSignals;
  revoked?: boolean;
  revoke_reason?: string | null;
  created_at?: string;
  last_seen_at?: string;
  expires_at?: string;
  access_token_id?: string | null;
  refresh_token_id?: string | null;
}

export interface ApiErrorWire {
  code?: string; // keep string for forward-compat
  message: string;
  correlation_id?: string;
}

export type AuthSuccess = {
  principal: Principal;
  session: Session;
  access_token: Token;
  refresh_token: Token;
  id_token_issued?: boolean;
  id_token?: Token;
};

// Requests / Responses (subset for brevity but covering all public API)

export type BeginPasswordAuthRequest = {
  identifier: string;
  password: string;
  context?: ClientContext;
};
export type BeginPasswordAuthResponse =
  | { success: AuthSuccess; has_error?: false; error?: undefined }
  | { mfa: MfaChallengeRequired; has_error?: false; error?: undefined }
  | { success?: undefined; mfa?: undefined; has_error: true; error: ApiErrorWire };

export type MfaChallengeRequired = {
  challenge_id: string;
  allowed_methods: AuthMethod[];
  expires_at?: string;
  risk?: RiskSignals;
  webauthn?: WebAuthnAuthChallenge;
  otp?: OtpChallenge;
};

export type CompleteMfaRequest = {
  challenge_id: string;
  context?: ClientContext;
  totp_code?: string;
  sms_code?: string;
  email_code?: string;
  recovery_code?: string;
  webauthn?: WebAuthnAssertion;
};
export type CompleteMfaResponse =
  | { success: AuthSuccess; has_error?: false; error?: undefined }
  | { has_error: true; error: ApiErrorWire };

export type WebAuthnAuthChallenge = {
  challenge_b64url: string;
  rp_id: string;
  allow_credentials?: string[];
  user_verification_required?: boolean;
  expires_at?: string;
};

export type WebAuthnRegisterOptions = {
  challenge_b64url: string;
  rp_id: string;
  rp_name: string;
  user_id_b64url: string;
  user_name: string;
  user_display_name?: string;
  exclude_credentials?: string[];
  resident_key_required?: boolean;
  user_verification_required?: boolean;
  expires_at?: string;
};

export type WebAuthnAssertion = {
  credential_id_b64url: string;
  client_data_json: string; // base64url
  authenticator_data: string; // base64url
  signature: string; // base64url
  user_handle?: string; // base64url
};

export type WebAuthnAttestation = {
  credential_id_b64url: string;
  client_data_json: string; // base64url
  attestation_object: string; // base64url
};

export type OtpChannel = "SMS" | "EMAIL";
export type OtpChallenge = {
  challenge_id: string;
  channel: OtpChannel;
  masked_destination: string;
  code_length: number;
  ttl_ms?: number;
  expires_at?: string;
};

export type PasswordlessMethod =
  | "EMAIL_LINK"
  | "EMAIL_OTP"
  | "SMS_OTP"
  | "WEBAUTHN";

export type StartPasswordlessRequest = {
  identifier: string;
  method: PasswordlessMethod;
  context?: ClientContext;
};
export type StartPasswordlessResponse = {
  otp?: OtpChallenge;
  info?: string | null;
  webauthn?: WebAuthnAuthChallenge;
};

export type CompletePasswordlessRequest = {
  identifier: string;
  context?: ClientContext;
  email_link_token?: string;
  sms_code?: string;
  email_code?: string;
  webauthn?: WebAuthnAssertion;
};
export type CompletePasswordlessResponse =
  | { success: AuthSuccess; has_error?: false; error?: undefined }
  | { has_error: true; error: ApiErrorWire };

export type RefreshAccessTokenResponse = { success: AuthSuccess };

export type IntrospectTokenResponse = {
  active: boolean;
  token?: Token;
  principal?: Principal;
  session?: Session;
  risk?: RiskSignals;
  evaluated_at?: string;
};

export type RevokeTokenResponse = { revoked: boolean };
export type LogoutResponse = { revoked: boolean };
export type GetSessionResponse = { session: Session };
export type ListSessionsResponse = { sessions: Session[]; next_page_token?: string | null };

///////////////////////////
// Errors
///////////////////////////

export class SecurityError extends Error {
  public readonly causeRaw?: any;
  public readonly status?: number;
  public readonly code?: string;
  public readonly correlationId?: string;

  constructor(message: string, opts?: { status?: number; code?: string; correlationId?: string; cause?: any }) {
    super(message);
    this.name = "SecurityError";
    this.status = opts?.status;
    this.code = opts?.code;
    this.correlationId = opts?.correlationId;
    this.causeRaw = opts?.cause;
  }
}

///////////////////////////
// Logger
///////////////////////////

export interface Logger {
  debug(msg: string, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
}

const noopLogger: Logger = {
  debug: () => void 0,
  info: () => void 0,
  warn: () => void 0,
  error: () => void 0,
};

///////////////////////////
// Storage adapters
///////////////////////////

export interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

export class MemoryStorage implements StorageAdapter {
  private map = new Map<string, string>();
  async get(key: string) { return this.map.has(key) ? this.map.get(key)! : null; }
  async set(key: string, value: string) { this.map.set(key, value); }
  async remove(key: string) { this.map.delete(key); }
}

export class LocalStorageAdapter implements StorageAdapter {
  constructor(private readonly namespace = "aethernova:sec") {
    if (!isBrowser) throw new Error("LocalStorageAdapter is browser-only");
    if (!window.localStorage) throw new Error("localStorage unavailable");
  }
  private k(key: string) { return `${this.namespace}:${key}`; }
  async get(key: string) { return window.localStorage.getItem(this.k(key)); }
  async set(key: string, value: string) { window.localStorage.setItem(this.k(key), value); }
  async remove(key: string) { window.localStorage.removeItem(this.k(key)); }
}

///////////////////////////
// Retry & backoff
///////////////////////////

export interface RetryOptions {
  retries: number;          // max attempts (not counting the first)
  minDelayMs: number;       // minimal backoff
  maxDelayMs: number;       // cap
}

function sleep(ms: number) { return new Promise(res => setTimeout(res, ms)); }

// Decorrelated jitter backoff (AWS Architecture Blog pattern)
function nextDelay(prev: number, opts: RetryOptions): number {
  const base = Math.max(opts.minDelayMs, 1);
  const cap = Math.max(opts.maxDelayMs, base);
  const rnd = Math.random();
  const candidate = Math.min(cap, Math.max(base, prev * 3 * rnd));
  return Math.floor(candidate);
}

///////////////////////////
// HTTP client with timeout & retry
///////////////////////////

export interface HttpClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  retry?: RetryOptions;
  logger?: Logger;
  defaultHeaders?: Record<string, string>;
}

class HttpClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly retry: RetryOptions;
  private readonly logger: Logger;
  private readonly defaultHeaders: Record<string, string>;

  constructor(opts: HttpClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl ?? (globalThis as any).fetch;
    if (!this.fetchImpl) throw new Error("fetch not available; inject fetchImpl");
    this.timeoutMs = opts.timeoutMs ?? 15000;
    this.retry = opts.retry ?? { retries: 3, minDelayMs: 100, maxDelayMs: 2000 };
    this.logger = opts.logger ?? noopLogger;
    this.defaultHeaders = { Accept: "application/json", ...opts.defaultHeaders };
  }

  async request<T>(path: string, init: RequestInit & { query?: Record<string, string | number | boolean | undefined> } = {}): Promise<T> {
    const url = new URL(this.baseUrl + path);
    if (init.query) {
      for (const [k, v] of Object.entries(init.query)) {
        if (v === undefined) continue;
        url.searchParams.set(k, String(v));
      }
    }

    const headers: Record<string, string> = {
      ...this.defaultHeaders,
      ...(init.headers as Record<string, string> | undefined),
    };

    let attempt = 0;
    let delay = this.retry.minDelayMs;
    // retry on 429, 502, 503, 504 and network errors
    // never retry on non-idempotent POST by default unless opted-in (here we do limited retries even for POST as auth endpoints are safe to retry on net errors).
    for (;;) {
      attempt++;
      const controller = new AbortController();
      const to = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        this.logger.debug("http:request", { method: init.method ?? "GET", url: url.toString(), attempt });
        const res = await this.fetchImpl(url.toString(), { ...init, headers, signal: controller.signal });

        if (res.status === 204) {
          clearTimeout(to);
          return undefined as unknown as T;
        }

        const text = await res.text();
        const ct = res.headers.get("content-type") || "";
        const data = ct.includes("application/json") ? JSON.parse(text || "{}") : (text as unknown as T);

        if (res.ok) {
          clearTimeout(to);
          return data as T;
        }

        // Retryable statuses
        if ([429, 502, 503, 504].includes(res.status) && attempt <= this.retry.retries + 1) {
          this.logger.warn("http:retryable", { status: res.status, attempt, url: url.toString() });
          const retryAfter = Number(res.headers.get("retry-after"));
          if (!Number.isNaN(retryAfter) && retryAfter > 0) {
            await sleep(retryAfter * 1000);
          } else {
            await sleep(delay);
            delay = nextDelay(delay, this.retry);
          }
          continue;
        }

        // Non-retryable error
        const apiErr = data && typeof data === "object" && "message" in (data as any) ? (data as ApiErrorWire) : undefined;
        throw new SecurityError(apiErr?.message || `HTTP ${res.status}`, {
          status: res.status,
          code: apiErr?.code,
          correlationId: apiErr?.correlation_id,
          cause: data,
        });
      } catch (err: any) {
        clearTimeout(to);
        // AbortError or network
        if ((err?.name === "AbortError" || err?.code === "ECONNRESET" || err?.name === "FetchError") && attempt <= this.retry.retries + 1) {
          this.logger.warn("http:network-retry", { attempt, url: url.toString() });
          await sleep(delay);
          delay = nextDelay(delay, this.retry);
          continue;
        }
        if (err instanceof SecurityError) throw err;
        throw new SecurityError(err?.message || "Network error", { cause: err });
      }
    }
  }
}

///////////////////////////
// Token manager with refresh guard
///////////////////////////

type StoredTokens = {
  access?: string | null;
  refresh?: string | null;
  id?: string | null;
  // expiry as epoch ms (best-effort to avoid skew); if absent, fall back to server
  access_expires_at?: number | null;
  refresh_expires_at?: number | null;
  id_expires_at?: number | null;
};

class TokenManager {
  private readonly storage: StorageAdapter;
  private readonly ns: string;
  private refreshing: Promise<void> | null = null;

  constructor(storage: StorageAdapter, namespace = "auth") {
    this.storage = storage;
    this.ns = namespace;
  }

  private key(k: string) { return `${this.ns}:${k}`; }

  async read(): Promise<StoredTokens> {
    const raw = await this.storage.get(this.key("tokens"));
    if (!raw) return {};
    try { return JSON.parse(raw) as StoredTokens; } catch { return {}; }
  }

  async write(tokens: StoredTokens): Promise<void> {
    await this.storage.set(this.key("tokens"), JSON.stringify(tokens));
  }

  async clear(): Promise<void> { await this.storage.remove(this.key("tokens")); }

  // Set from AuthSuccess
  async setFromSuccess(s: AuthSuccess): Promise<void> {
    const toEpoch = (iso?: string) => (iso ? new Date(iso).getTime() : null);
    await this.write({
      access: s.access_token.jwt_compact || s.access_token.paseto || s.access_token.opaque || null,
      refresh: s.refresh_token.jwt_compact || s.refresh_token.paseto || s.refresh_token.opaque || null,
      id: s.id_token?.jwt_compact || s.id_token?.paseto || s.id_token?.opaque || null,
      access_expires_at: toEpoch(s.access_token.expires_at),
      refresh_expires_at: toEpoch(s.refresh_token.expires_at),
      id_expires_at: toEpoch(s.id_token?.expires_at),
    });
  }

  async getAccessToken(): Promise<string | null> {
    const t = await this.read();
    if (!t.access) return null;
    const graceMs = 30_000; // refresh slightly before expiry
    if (t.access_expires_at && t.access_expires_at - nowEpochMs() <= graceMs) return null;
    return t.access;
  }

  async getRefreshToken(): Promise<string | null> {
    const t = await this.read();
    if (!t.refresh) return null;
    return t.refresh;
  }

  // Ensures only one concurrent refresh happens
  async withRefreshLock<T>(fn: () => Promise<T>): Promise<T> {
    if (!this.refreshing) {
      this.refreshing = (async () => {
        try { await fn(); } finally { this.refreshing = null; }
      })();
    }
    await this.refreshing;
    return undefined as unknown as T;
  }
}

///////////////////////////
// Events
///////////////////////////

type AuthEvent = "auth:state_changed" | "auth:signed_in" | "auth:signed_out" | "auth:token_refreshed" | "auth:token_revoked";

class Emitter {
  private handlers = new Map<AuthEvent, Set<(...args: any[]) => void>>();
  on(evt: AuthEvent, cb: (...args: any[]) => void) {
    if (!this.handlers.has(evt)) this.handlers.set(evt, new Set());
    this.handlers.get(evt)!.add(cb);
  }
  off(evt: AuthEvent, cb: (...args: any[]) => void) {
    this.handlers.get(evt)?.delete(cb);
  }
  emit(evt: AuthEvent, ...args: any[]) {
    this.handlers.get(evt)?.forEach(cb => { try { cb(...args); } catch { /* swallow */ } });
  }
}

///////////////////////////
// Public Client
///////////////////////////

export interface SecurityClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  retry?: RetryOptions;
  clientId?: string;
  tenantId?: string;
  storage?: StorageAdapter;
  storageNamespace?: string;
  logger?: Logger;
  defaultHeaders?: Record<string, string>;
}

export class SecurityClient {
  private readonly http: HttpClient;
  private readonly tokens: TokenManager;
  private readonly log: Logger;
  private readonly clientId?: string;
  private readonly tenantId?: string;
  private readonly events = new Emitter();

  constructor(opts: SecurityClientOptions) {
    this.log = opts.logger ?? noopLogger;
    this.http = new HttpClient({
      baseUrl: opts.baseUrl,
      fetchImpl: opts.fetchImpl,
      timeoutMs: opts.timeoutMs ?? 15000,
      retry: opts.retry ?? { retries: 3, minDelayMs: 150, maxDelayMs: 2500 },
      logger: this.log,
      defaultHeaders: { ...(opts.defaultHeaders ?? {}), "X-SDK-Name": "aethernova-security-ts", "X-SDK-Version": "1.0.0" },
    });
    const storage = opts.storage ?? new MemoryStorage();
    this.tokens = new TokenManager(storage, opts.storageNamespace ?? "aethernova:sec");
    this.clientId = opts.clientId;
    this.tenantId = opts.tenantId;
  }

  ///////////////////////////
  // Events
  ///////////////////////////
  onAuthStateChanged(cb: (state: { signedIn: boolean; session?: Session | null; principal?: Principal | null }) => void) {
    this.events.on("auth:state_changed", cb);
  }
  removeAuthStateChanged(cb: (state: any) => void) {
    this.events.off("auth:state_changed", cb);
  }

  ///////////////////////////
  // Helpers
  ///////////////////////////

  private async authHeaders(): Promise<Record<string, string>> {
    const token = await this.tokens.getAccessToken();
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (token) h.Authorization = `Bearer ${token}`;
    if (this.clientId) h["X-Client-Id"] = this.clientId;
    if (this.tenantId) h["X-Tenant-Id"] = this.tenantId;
    return h;
  }

  private buildClientContext(): ClientContext {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const ua = isBrowser ? navigator.userAgent : `node/${process.version}`;
    return {
      request_id: cryptoRandomId(),
      user_agent: ua,
      timezone: tz,
      device: {
        platform: isBrowser ? "WEB" : "OTHER",
        user_agent: ua,
        model: isBrowser ? (navigator as any).platform ?? "unknown" : "node",
      },
    };
  }

  ///////////////////////////
  // Sign-in flows
  ///////////////////////////

  async beginPasswordAuth(identifier: string, password: string): Promise<BeginPasswordAuthResponse> {
    const body: BeginPasswordAuthRequest = { identifier, password, context: this.buildClientContext() };
    const res = await this.http.request<BeginPasswordAuthResponse>("/auth/v1/password:begin", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify(body),
    });

    if ("success" in res && res.success) {
      await this.tokens.setFromSuccess(res.success);
      this.events.emit("auth:signed_in");
      this.events.emit("auth:state_changed", { signedIn: true, session: res.success.session, principal: res.success.principal });
    }
    return res;
  }

  async completeMfa(req: CompleteMfaRequest): Promise<CompleteMfaResponse> {
    const body = { ...req, context: req.context ?? this.buildClientContext() };
    const res = await this.http.request<CompleteMfaResponse>("/auth/v1/mfa:complete", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify(body),
    });
    if ("success" in res && res.success) {
      await this.tokens.setFromSuccess(res.success);
      this.events.emit("auth:signed_in");
      this.events.emit("auth:state_changed", { signedIn: true, session: res.success.session, principal: res.success.principal });
    }
    return res;
  }

  ///////////////////////////
  // Passwordless
  ///////////////////////////

  async startPasswordless(identifier: string, method: PasswordlessMethod): Promise<StartPasswordlessResponse> {
    const body: StartPasswordlessRequest = { identifier, method, context: this.buildClientContext() };
    return await this.http.request<StartPasswordlessResponse>("/auth/v1/passwordless:start", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify(body),
    });
  }

  async completePasswordless(req: CompletePasswordlessRequest): Promise<CompletePasswordlessResponse> {
    const body = { ...req, context: req.context ?? this.buildClientContext() };
    const res = await this.http.request<CompletePasswordlessResponse>("/auth/v1/passwordless:complete", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify(body),
    });
    if ("success" in res && res.success) {
      await this.tokens.setFromSuccess(res.success);
      this.events.emit("auth:signed_in");
      this.events.emit("auth:state_changed", { signedIn: true, session: res.success.session, principal: res.success.principal });
    }
    return res;
  }

  ///////////////////////////
  // WebAuthn / Passkeys
  ///////////////////////////

  async startWebAuthnRegistration(principalId: string): Promise<WebAuthnRegisterOptions> {
    const body = { principal_id: principalId, context: this.buildClientContext() };
    return await this.http.request<WebAuthnRegisterOptions>("/auth/v1/webauthn:register:start", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify(body),
    });
  }

  async finishWebAuthnRegistration(principalId: string, att: WebAuthnAttestation): Promise<{ credential: any }> {
    const body = { principal_id: principalId, attestation: att, context: this.buildClientContext() };
    return await this.http.request<{ credential: any }>("/auth/v1/webauthn:register:finish", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify(body),
    });
  }

  async startWebAuthnAuthentication(identifier?: string): Promise<WebAuthnAuthChallenge> {
    const body = { identifier, context: this.buildClientContext() };
    return await this.http.request<WebAuthnAuthChallenge>("/auth/v1/webauthn:auth:start", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify(body),
    });
  }

  async finishWebAuthnAuthentication(identifier: string | undefined, assertion: WebAuthnAssertion):
    Promise<{ success?: AuthSuccess; mfa?: MfaChallengeRequired; has_error?: boolean; error?: ApiErrorWire }> {
    const body = { identifier, assertion, context: this.buildClientContext() };
    const res = await this.http.request<{ success?: AuthSuccess; mfa?: MfaChallengeRequired; has_error?: boolean; error?: ApiErrorWire }>("/auth/v1/webauthn:auth:finish", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify(body),
    });
    if (res?.success) {
      await this.tokens.setFromSuccess(res.success);
      this.events.emit("auth:signed_in");
      this.events.emit("auth:state_changed", { signedIn: true, session: res.success.session, principal: res.success.principal });
    }
    return res;
  }

  // Browser helpers for WebAuthn
  async browserCreatePublicKeyCredential(opts: WebAuthnRegisterOptions): Promise<WebAuthnAttestation> {
    if (!isBrowser || !("credentials" in navigator)) throw new SecurityError("WebAuthn not available in this environment");
    const pubKey: PublicKeyCredentialCreationOptions = {
      challenge: b64u.decode(opts.challenge_b64url),
      rp: { id: opts.rp_id, name: opts.rp_name },
      user: {
        id: b64u.decode(opts.user_id_b64url),
        name: opts.user_name,
        displayName: opts.user_display_name ?? opts.user_name,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      timeout: 60_000,
      attestation: "none",
      excludeCredentials: (opts.exclude_credentials ?? []).map(id => ({ type: "public-key", id: b64u.decode(id) })),
      authenticatorSelection: {
        residentKey: opts.resident_key_required ? "required" : "preferred",
        userVerification: opts.user_verification_required ? "required" : "preferred",
      },
    };
    const cred = (await navigator.credentials.create({ publicKey: pubKey })) as PublicKeyCredential;
    const response = cred.response as AuthenticatorAttestationResponse;
    return {
      credential_id_b64url: b64u.encode(cred.rawId),
      client_data_json: b64u.encode(response.clientDataJSON),
      attestation_object: b64u.encode(response.attestationObject),
    };
  }

  async browserGetPublicKeyCredential(ch: WebAuthnAuthChallenge): Promise<WebAuthnAssertion> {
    if (!isBrowser || !("credentials" in navigator)) throw new SecurityError("WebAuthn not available in this environment");
    const allow: PublicKeyCredentialDescriptor[] = (ch.allow_credentials ?? []).map(id => ({ type: "public-key", id: b64u.decode(id) }));
    const options: PublicKeyCredentialRequestOptions = {
      challenge: b64u.decode(ch.challenge_b64url),
      rpId: ch.rp_id,
      timeout: 60_000,
      allowCredentials: allow.length ? allow : undefined,
      userVerification: ch.user_verification_required ? "required" : "preferred",
    };
    const cred = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential;
    const resp = cred.response as AuthenticatorAssertionResponse;
    return {
      credential_id_b64url: b64u.encode(cred.rawId),
      client_data_json: b64u.encode(resp.clientDataJSON),
      authenticator_data: b64u.encode(resp.authenticatorData),
      signature: b64u.encode(resp.signature),
      user_handle: resp.userHandle ? b64u.encode(resp.userHandle) : undefined,
    };
  }

  ///////////////////////////
  // Token lifecycle
  ///////////////////////////

  // Automatically ensures only one refresh in-flight
  async ensureAccessToken(): Promise<string | null> {
    const existing = await this.tokens.getAccessToken();
    if (existing) return existing;

    const refresh = await this.tokens.getRefreshToken();
    if (!refresh) return null;

    await this.tokens.withRefreshLock(async () => {
      // Check again after acquiring the lock
      const secondCheck = await this.tokens.getAccessToken();
      if (secondCheck) return;

      const res = await this.http.request<RefreshAccessTokenResponse>("/auth/v1/token:refresh", {
        method: "POST",
        headers: await this.authHeaders(),
        body: JSON.stringify({ refresh_token: refresh, context: this.buildClientContext() }),
      });
      await this.tokens.setFromSuccess(res.success);
      this.events.emit("auth:token_refreshed", { session: res.success.session });
      this.events.emit("auth:state_changed", { signedIn: true, session: res.success.session, principal: res.success.principal });
    });

    return await this.tokens.getAccessToken();
  }

  async introspectToken(token?: string): Promise<IntrospectTokenResponse> {
    const t = token ?? (await this.tokens.getAccessToken());
    if (!t) throw new SecurityError("No token to introspect");
    return await this.http.request<IntrospectTokenResponse>("/auth/v1/token:introspect", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify({ token: t, context: this.buildClientContext() }),
    });
  }

  async revokeToken(token?: string, type: TokenType = TokenType.REFRESH, reason?: string): Promise<RevokeTokenResponse> {
    const t = token ?? (await this.tokens.getRefreshToken());
    if (!t) throw new SecurityError("No token to revoke");
    const res = await this.http.request<RevokeTokenResponse>("/auth/v1/token:revoke", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify({ token: t, type, reason, context: this.buildClientContext() }),
    });
    if (res.revoked) {
      await this.tokens.clear();
      this.events.emit("auth:token_revoked");
      this.events.emit("auth:signed_out");
      this.events.emit("auth:state_changed", { signedIn: false, session: null, principal: null });
    }
    return res;
  }

  ///////////////////////////
  // Sessions
  ///////////////////////////

  async logout(sessionId?: string): Promise<LogoutResponse> {
    const res = await this.http.request<LogoutResponse>("/auth/v1/session:logout", {
      method: "POST",
      headers: await this.authHeaders(),
      body: JSON.stringify({ session_id: sessionId, context: this.buildClientContext() }),
    });
    if (res.revoked) {
      await this.tokens.clear();
      this.events.emit("auth:signed_out");
      this.events.emit("auth:state_changed", { signedIn: false, session: null, principal: null });
    }
    return res;
  }

  async getSession(sessionId: string): Promise<GetSessionResponse> {
    return await this.http.request<GetSessionResponse>("/auth/v1/session:get", {
      method: "GET",
      headers: await this.authHeaders(),
      query: { session_id: sessionId },
    });
  }

  async listSessions(principalId: string, pageSize = 20, pageToken?: string, activeOnly = true): Promise<ListSessionsResponse> {
    return await this.http.request<ListSessionsResponse>("/auth/v1/session:list", {
      method: "GET",
      headers: await this.authHeaders(),
      query: { principal_id: principalId, page_size: pageSize, page_token: pageToken ?? "", active_only: activeOnly },
    });
  }

  ///////////////////////////
  // Convenience API
  ///////////////////////////

  async signInWithPassword(identifier: string, password: string): Promise<AuthSuccess | MfaChallengeRequired> {
    const r = await this.beginPasswordAuth(identifier, password);
    if ("has_error" in r && r.has_error) throw new SecurityError(r.error.message, { code: r.error.code });
    if ("mfa" in r && r.mfa) return r.mfa;
    return r.success;
  }

  async completeTotpMfa(challengeId: string, totpCode: string): Promise<AuthSuccess> {
    const r = await this.completeMfa({ challenge_id: challengeId, totp_code: totpCode });
    if ("has_error" in r && r.has_error) throw new SecurityError(r.error.message, { code: r.error.code });
    return r.success;
  }

  async signOut(): Promise<void> {
    try { await this.logout(); } finally { await this.tokens.clear(); }
  }

  async getAuthorizationHeader(): Promise<string | null> {
    const token = await this.ensureAccessToken();
    return token ? `Bearer ${token}` : null;
  }
}

///////////////////////////
// Utilities
///////////////////////////

function cryptoRandomId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return (crypto as any).randomUUID();
  // RFC4122 v4 fallback
  const rnd = new Uint8Array(16);
  if (typeof crypto !== "undefined" && "getRandomValues" in crypto) (crypto as any).getRandomValues(rnd);
  else for (let i = 0; i < 16; i++) rnd[i] = Math.floor(Math.random() * 256);
  rnd[6] = (rnd[6] & 0x0f) | 0x40;
  rnd[8] = (rnd[8] & 0x3f) | 0x80;
  const hex = [...rnd].map(b => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Safe log meta builder that redacts tokens.
 */
export function safeAuthMeta(success: AuthSuccess): Record<string, unknown> {
  return {
    principal_id: success.principal.id,
    session_id: success.session.id,
    access_token: success.access_token ? redact(success.access_token.jwt_compact || success.access_token.paseto || success.access_token.opaque || "") : "",
    refresh_token: success.refresh_token ? redact(success.refresh_token.jwt_compact || success.refresh_token.paseto || success.refresh_token.opaque || "") : "",
    id_token: success.id_token ? redact(success.id_token.jwt_compact || success.id_token.paseto || success.id_token.opaque || "") : "",
    access_expires_at: success.access_token?.expires_at,
    refresh_expires_at: success.refresh_token?.expires_at,
  };
}
