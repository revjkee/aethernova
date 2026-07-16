/**
 * OmniMind Core — Provider Types (industrial edition)
 * Path: core-systems/omnimind-core/dashboard/src/app/providers/types.ts
 *
 * Design goals:
 * - Strongly-typed provider contracts (Auth, OTEL, Theme, Feature Flags)
 * - Framework-agnostic domain types + React-friendly context value shapes
 * - Zero runtime deps in this file (import type only for OTEL/React)
 * - JSDoc for IDE discoverability; readonly where possible
 *
 * References:
 * - Vite public/src separation: https://vite.dev/guide/assets            (publicDir vs src)  [docs]
 * - React createContext typing: https://react.dev/reference/react/createContext              [docs]
 * - React + TS guide: https://react.dev/learn/typescript                                    [docs]
 * - TS Handbook (Everyday Types): https://www.typescriptlang.org/docs/handbook/2/everyday-types.html
 * - OpenTelemetry JS API/Context: https://opentelemetry.io/docs/languages/js/ , https://opentelemetry.io/docs/languages/js/context/
 */

//////////////////////////////
// Utility & Base Primitives //
//////////////////////////////

/** Branded primitive to prevent accidental mixing of ids/tokens. */
export type Brand<T, B extends string> = T & { readonly __brand: B };

/** Result<T> functional helper for side-effect free provider operations. */
export type Ok<T> = { readonly ok: true; readonly value: T };
export type Err<E = unknown> = { readonly ok: false; readonly error: E };
export type Result<T, E = unknown> = Ok<T> | Err<E>;

/** Nullable and DeepReadonly helpers. */
export type Nullable<T> = T | null;
export type DeepReadonly<T> =
  T extends (...args: any[]) => any ? T :
  T extends object ? { readonly [K in keyof T]: DeepReadonly<T[K]> } :
  T;

//////////////////////
// Security & Auth  //
//////////////////////

export type UserId = Brand<string, "UserId">;
export type SessionId = Brand<string, "SessionId">;
export type AccessToken = Brand<string, "AccessToken">;
export type RefreshToken = Brand<string, "RefreshToken">;

export interface UserProfile {
  readonly id: UserId;
  readonly email: string;
  readonly displayName?: string;
  readonly avatarUrl?: string;
  /** ISO 3166-1 alpha-2 */
  readonly locale?: string;
  /** ISO 8601 */
  readonly createdAt?: string;
  readonly updatedAt?: string;
  /** Arbitrary immutable traits safe for client */
  readonly traits?: Record<string, unknown>;
}

export type RoleName = Brand<string, "Role">;
export type Permission = Brand<string, "Permission">;

export interface AccessModel {
  readonly roles: readonly RoleName[];
  readonly permissions: readonly Permission[];
}

export interface TokenPair {
  readonly accessToken: AccessToken;
  readonly refreshToken?: RefreshToken;
  /** UNIX seconds; used for proactive refresh */
  readonly expiresAt?: number;
}

export interface AuthSession {
  readonly sessionId: SessionId;
  readonly user: UserProfile;
  readonly tokens: TokenPair;
}

export type AuthStatus =
  | "unauthenticated"
  | "authenticating"
  | "authenticated"
  | "refreshing"
  | "error";

export interface AuthState {
  readonly status: AuthStatus;
  readonly session: Nullable<AuthSession>;
  readonly access: DeepReadonly<AccessModel>;
  /** last error (transport/validation/server) */
  readonly error?: unknown;
}

export interface AuthCredentials {
  readonly username: string;
  readonly password: string;
  /** optional 2FA/OTP */
  readonly otpCode?: string;
}

export interface AuthProviderConfig {
  readonly endpoint: string;        // e.g., /api/auth
  readonly refreshEndpoint?: string;// e.g., /api/auth/refresh
  readonly leewaySeconds?: number;  // token refresh skew
  readonly storageKey?: string;     // where to persist session
  readonly pkce?: boolean;          // if using OAuth/OIDC + PKCE
}

export interface AuthEvents {
  onLogin?(session: AuthSession): void;
  onLogout?(reason?: "user" | "expired" | "revoked" | "error"): void;
  onTokenRefresh?(tokens: TokenPair): void;
  onAuthError?(err: unknown): void;
}

/** Public API that AuthProvider exposes to consumers. */
export interface AuthAPI {
  /** Immutable snapshot of current state. */
  readonly state: AuthState;

  /** Derived helpers */
  readonly isAuthenticated: () => boolean;
  readonly hasRole: (role: RoleName) => boolean;
  readonly can: (perm: Permission) => boolean;

  /** Actions */
  readonly login: (creds: AuthCredentials) => Promise<Result<AuthSession>>;
  readonly logout: (reason?: AuthEventsParameters["logoutReason"]) => Promise<void>;
  readonly refresh: () => Promise<Result<TokenPair>>;
  readonly updateProfile: (partial: Partial<UserProfile>) => Promise<Result<UserProfile>>;
}

/** Narrow type for event parameters to keep AuthAPI surface minimal. */
export interface AuthEventsParameters {
  readonly logoutReason?: "user" | "expired" | "revoked" | "error";
}

/////////////////////////
// Telemetry (OTEL/RUM) //
/////////////////////////

// We avoid runtime deps; consumers can install @opentelemetry/api and get strong types.
export interface TelemetryConfig {
  readonly serviceName: string;
  readonly serviceVersion?: string;
  readonly environment?: "dev" | "staging" | "prod" | string;
  /**
   * OTLP/gRPC/HTTP exporter endpoints for traces/metrics/logs.
   * Example: { traces: "/v1/traces", metrics: "/v1/metrics" }
   */
  readonly exporter?: Partial<Record<"traces" | "metrics" | "logs", string>>;
  /** W3C traceparent/baggage propagation; true = enable defaults. */
  readonly propagation?: boolean;
  /** Sample rate [0..1]; defaults may be tied to SDK. */
  readonly traceSampleRatio?: number;
  /** Optional resource attributes */
  readonly resource?: Record<string, string | number | boolean>;
}

export interface WebVitalsSample {
  readonly name: "LCP" | "CLS" | "FID" | "INP" | "TTFB";
  readonly value: number;
  readonly id?: string; // web-vitals unique id
  /** Milliseconds since navigation start, if available */
  readonly startTime?: number;
  readonly attribution?: Record<string, unknown>;
}

export interface TelemetryAPI {
  /** Record business or UI event as span/metric/log (implementation-dependent). */
  emitEvent: (name: string, attrs?: Record<string, unknown>) => void;
  recordWebVital: (sample: WebVitalsSample) => void;
  /** Attach common attributes to subsequent signals. */
  setAttributes: (attrs: Record<string, string | number | boolean>) => void;
  /** Link auth and telemetry (e.g., user.id for RUM correlation) */
  identifyUser: (user: Pick<UserProfile, "id" | "email" | "displayName"> | null) => void;
}

/////////////////////
// Theming (UI)    //
/////////////////////

export type ThemeName = "system" | "light" | "dark";
export interface ThemeConfig {
  readonly defaultTheme?: ThemeName;
  /** Optional CSS variables namespace, e.g., --omni- */
  readonly cssVarPrefix?: string;
  /** Persist choice (e.g., localStorage key) */
  readonly storageKey?: string;
}

export interface ThemeAPI {
  readonly theme: ThemeName;
  setTheme: (t: ThemeName) => void;
  /** Resolves system preference to effective theme */
  readonly resolved: () => "light" | "dark";
}

//////////////////////////////
// Feature Flags (FF/Rollout) //
//////////////////////////////

export type FlagKey = Brand<string, "FlagKey">;
export type VariantKey = Brand<string, "VariantKey">;
export type FlagValue = string | number | boolean | null;

export interface FlagDescriptor {
  readonly key: FlagKey;
  readonly description?: string;
  readonly defaultValue: FlagValue;
  readonly variants?: readonly VariantKey[];
  /** Optional targeting rules descriptor (opaque to client) */
  readonly targeting?: unknown;
}

export interface FlagEvaluation<T extends FlagValue = FlagValue> {
  readonly key: FlagKey;
  readonly value: T;
  /** variant id if multivariate rollout is used */
  readonly variant?: VariantKey;
  /** source of evaluation (sdk/local/remote/cache) */
  readonly source: "sdk" | "local" | "remote" | "cache";
  /** for debugging: rule id / reason */
  readonly reason?: string;
}

export interface FlagsConfig {
  /** static bootstrap to avoid blank states at app start */
  readonly bootstrap?: ReadonlyArray<FlagDescriptor>;
  /** periodic refresh in ms; 0 disables auto-refresh */
  readonly refreshMs?: number;
  /** remote endpoint to fetch evaluations */
  readonly endpoint?: string;
  /** storage key for cached flags */
  readonly storageKey?: string;
}

export interface FlagsAPI {
  get<T extends FlagValue = FlagValue>(key: FlagKey): FlagEvaluation<T>;
  /** Simple sugar returning raw value with fallback */
  value<T extends FlagValue = FlagValue>(key: FlagKey, fallback: T): T;
  /** Update local cache (e.g., after remote fetch) */
  update: (evaluations: ReadonlyArray<FlagEvaluation>) => void;
  /** Subscribe to change events for live UI toggling */
  subscribe: (keys: ReadonlyArray<FlagKey>, cb: () => void) => () => void;
}

////////////////////////////////////
// Aggregated Provider Composition //
////////////////////////////////////

/** High-level provider config used at app bootstrap. */
export interface ProvidersConfig {
  readonly auth?: AuthProviderConfig;
  readonly telemetry?: TelemetryConfig;
  readonly theme?: ThemeConfig;
  readonly flags?: FlagsConfig;
}

/** What we expose through root providers context. */
export interface AppServices {
  readonly auth: AuthAPI;
  readonly telemetry: TelemetryAPI;
  readonly theme: ThemeAPI;
  readonly flags: FlagsAPI;
}

/** Utility guard to narrow unknowns to Err<T> quickly. */
export const toErr = <E = unknown>(e: unknown): Err<E> => ({ ok: false, error: e as E });
export const toOk = <T>(value: T): Ok<T> => ({ ok: true, value });

/////////////////////////////
// React-friendly Typings  //
/////////////////////////////

// Import types only to avoid hard runtime dependency.
import type { ReactNode } from "react";

/** Props signature for concrete Provider components. */
export interface ProviderProps<TConfig = unknown> {
  readonly children: ReactNode;
  readonly config?: DeepReadonly<TConfig>;
}

/** Specialized props per provider kind */
export type AuthProviderProps = ProviderProps<AuthProviderConfig> & Partial<AuthEvents>;
export type TelemetryProviderProps = ProviderProps<TelemetryConfig>;
export type ThemeProviderProps = ProviderProps<ThemeConfig>;
export type FlagsProviderProps = ProviderProps<FlagsConfig>;

/** Optional: shape for a combined RootProviders component. */
export interface RootProvidersProps extends ProviderProps<ProvidersConfig> {}
