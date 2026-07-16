// core-systems/omnimind-core/dashboard/src/app/router/loaders/meLoader.ts
import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import type { LoaderFunctionArgs } from "react-router-dom";

/**
 * Конфигурация окружения (Vite/Node)
 */
const isBrowser = typeof window !== "undefined";
const APP_NAME = "omnimind-core";
const NS = `${APP_NAME}:auth`;

const CONFIG = {
  baseURL:
    (isBrowser && (import.meta as any)?.env?.VITE_API_BASE_URL) ||
    process.env.VITE_API_BASE_URL ||
    process.env.API_BASE_URL ||
    "/api",
  meEndpoint:
    (isBrowser && (import.meta as any)?.env?.VITE_API_ME_ENDPOINT) ||
    process.env.VITE_API_ME_ENDPOINT ||
    "/auth/me",
  refreshEndpoint:
    (isBrowser && (import.meta as any)?.env?.VITE_API_REFRESH_ENDPOINT) ||
    process.env.VITE_API_REFRESH_ENDPOINT ||
    "/auth/refresh",
  accessSkewMs: Number(process.env.VITE_AUTH_ACCESS_SKEW_MS || 30_000),
  timeoutMs: Number(process.env.VITE_API_TIMEOUT_MS || 30_000),
  retryBaseDelayMs: Number(process.env.VITE_API_RETRY_BASE_MS || 250),
  retryMaxAttempts: Number(process.env.VITE_API_RETRY_MAX || 3),
};

export type Role = string;
export type Permission = string;

export interface User {
  id: string;
  email: string;
  name?: string;
  roles?: Role[];
  permissions?: Permission[];
  [k: string]: unknown;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string | null;
  accessExp?: number | null; // unix seconds
}

type PersistedPayload = {
  tokens: AuthTokens | null;
  user: User | null;
  rememberMe: boolean;
};

type MeCache = {
  etag?: string | null;
  user?: User | null;
  ts?: number; // ms
};

const storageKeys = {
  bundle: `${NS}:bundle`,
  me: `${NS}:meCache`,
};

function safeParse<T>(raw: string | null): T | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function persistLoad(): PersistedPayload {
  if (!isBrowser) {
    return { tokens: null, user: null, rememberMe: false };
  }
  // приоритет sessionStorage (актуальная короткая сессия), затем localStorage
  const ss = safeParse<PersistedPayload>(window.sessionStorage.getItem(storageKeys.bundle));
  const ls = safeParse<PersistedPayload>(window.localStorage.getItem(storageKeys.bundle));
  return ss ?? ls ?? { tokens: null, user: null, rememberMe: false };
}

function persistSaveBundle(payload: PersistedPayload) {
  if (!isBrowser) return;
  const s = JSON.stringify(payload);
  window.sessionStorage.setItem(storageKeys.bundle, s);
  window.localStorage.setItem(storageKeys.bundle, s);
}

function persistClearBundle() {
  if (!isBrowser) return;
  window.sessionStorage.removeItem(storageKeys.bundle);
  window.localStorage.removeItem(storageKeys.bundle);
}

function loadMeCache(): MeCache {
  if (!isBrowser) return {};
  return safeParse<MeCache>(window.sessionStorage.getItem(storageKeys.me)) ?? {};
}

function saveMeCache(cache: MeCache) {
  if (!isBrowser) return;
  window.sessionStorage.setItem(storageKeys.me, JSON.stringify(cache));
}

function decodeJwtExp(token?: string | null): number | null {
  if (!token) return null;
  try {
    const [, payloadB64] = token.split(".");
    if (!payloadB64) return null;
    const json = JSON.parse(isBrowser ? atob(payloadB64) : Buffer.from(payloadB64, "base64").toString("utf8"));
    return typeof json?.exp === "number" ? json.exp : null;
  } catch {
    return null;
  }
}

function willExpireSoon(expSec: number | null | undefined, skewMs: number): boolean {
  if (!expSec) return false;
  return expSec * 1000 - Date.now() <= skewMs;
}

function bcPost(type: "refresh" | "logout" | "login", payload?: PersistedPayload) {
  if (!isBrowser || typeof BroadcastChannel === "undefined") return;
  const ch = new BroadcastChannel(`${NS}:bc`);
  try {
    ch.postMessage({ type, payload });
  } finally {
    ch.close();
  }
}

function buildAxios(tokens?: AuthTokens | null, signal?: AbortSignal): AxiosInstance {
  const instance = axios.create({
    baseURL: CONFIG.baseURL,
    withCredentials: true,
    timeout: CONFIG.timeoutMs,
    signal,
  });
  instance.interceptors.request.use((cfg: AxiosRequestConfig) => {
    const at = tokens?.accessToken;
    if (at) {
      cfg.headers = cfg.headers ?? {};
      (cfg.headers as any).Authorization = `Bearer ${at}`;
    }
    return cfg;
  });
  return instance;
}

async function tryRefresh(prev: PersistedPayload, signal?: AbortSignal): Promise<PersistedPayload | null> {
  const rt = prev.tokens?.refreshToken;
  if (!rt) return null;
  try {
    const res: AxiosResponse<{ accessToken: string; refreshToken?: string | null }> = await axios.post(
      CONFIG.refreshEndpoint,
      { refreshToken: rt },
      { baseURL: CONFIG.baseURL, withCredentials: true, timeout: CONFIG.timeoutMs, signal }
    );
    const accessExp = decodeJwtExp(res.data.accessToken);
    const next: PersistedPayload = {
      rememberMe: prev.rememberMe,
      user: prev.user,
      tokens: {
        accessToken: res.data.accessToken,
        refreshToken: res.data.refreshToken ?? rt,
        accessExp,
      },
    };
    persistSaveBundle(next);
    bcPost("refresh", next);
    return next;
  } catch {
    persistClearBundle();
    bcPost("logout");
    return null;
  }
}

async function backoff(attempt: number) {
  const jitter = Math.random() * 0.2 + 0.9; // 90–110%
  const ms = Math.min(CONFIG.retryBaseDelayMs * 2 ** (attempt - 1), 2000) * jitter;
  await new Promise((r) => setTimeout(r, ms));
}

/**
 * Основной loader: пытается вернуть актуального пользователя.
 * Возвращает:
 *  - User объект при успехе
 *  - null при неавторизованном состоянии или окончательном фейле
 */
export async function meLoader(args?: LoaderFunctionArgs): Promise<User | null> {
  const signal = args?.request?.signal;
  let bundle = persistLoad();
  let tokens = bundle.tokens;

  const api = buildAxios(tokens, signal);
  const cache = loadMeCache();

  // Если access почти истёк — попробовать проактивный refresh
  if (willExpireSoon(tokens?.accessExp ?? decodeJwtExp(tokens?.accessToken ?? null), CONFIG.accessSkewMs)) {
    const refreshed = await tryRefresh(bundle, signal);
    if (refreshed) {
      bundle = refreshed;
      tokens = refreshed.tokens;
    } else {
      return null;
    }
  }

  // Подготовим заголовки для ETag-кэша
  const headers: Record<string, string> = {};
  if (cache.etag) headers["If-None-Match"] = cache.etag;

  // Выполняем запрос с ограниченным числом ретраев на сетевые сбои
  let attempt = 0;
  for (;;) {
    attempt += 1;
    try {
      const res: AxiosResponse<User> = await api.get(CONFIG.meEndpoint, { headers, signal });
      const etag = (res.headers?.etag as string | undefined) ?? null;

      // Обновим кэш пользователя и, при необходимости, bundle.user
      saveMeCache({ etag, user: res.data, ts: Date.now() });
      const nextBundle: PersistedPayload = { ...bundle, user: res.data };
      persistSaveBundle(nextBundle);

      return res.data;
    } catch (e) {
      const err = e as AxiosError;
      // Прерывание по AbortSignal
      if (axios.isCancel(err) || (err.name === "CanceledError" && String(err.message).includes("canceled"))) {
        throw err;
      }

      const status = err.response?.status;

      // 304 — взять из кэша
      if (status === 304 && cache.user) {
        return cache.user;
      }

      // 401 — попытка одного refresh и повтор
      if (status === 401) {
        const refreshed = await tryRefresh(bundle, signal);
        if (!refreshed) {
          return null;
        }
        bundle = refreshed;
        tokens = refreshed.tokens;
        // Пересоздадим axios с новым токеном
        const api2 = buildAxios(tokens, signal);
        try {
          const res2: AxiosResponse<User> = await api2.get(CONFIG.meEndpoint, { headers, signal });
          const etag2 = (res2.headers?.etag as string | undefined) ?? null;
          saveMeCache({ etag: etag2, user: res2.data, ts: Date.now() });
          const nextBundle: PersistedPayload = { ...bundle, user: res2.data };
          persistSaveBundle(nextBundle);
          return res2.data;
        } catch (e2) {
          // Если снова 401/403 — считаем сессию недействительной
          const s2 = (e2 as AxiosError).response?.status;
          if (s2 === 401 || s2 === 403) {
            persistClearBundle();
            bcPost("logout");
            return null;
          }
          // Иначе — упадём ниже на общую обработку ретраев
          if (attempt >= CONFIG.retryMaxAttempts) throw e2;
        }
      }

      // На прочие 5xx/сетевые — ограниченный экспоненциальный retry
      if (
        !status || // сеть
        (status >= 500 && status <= 599)
      ) {
        if (attempt >= CONFIG.retryMaxAttempts) {
          // Последняя ошибка — если есть кэш, можно отдать stale (opt-in политика)
          if (cache.user) return cache.user;
          throw err;
        }
        await backoff(attempt);
        continue;
      }

      // 403 — доступ запрещён (но токен валиден): возвращаем null, чтобы роутер мог редиректить на /access-denied
      if (status === 403) return null;

      // Прочие клиентские — нет смысла ретраить
      if (cache.user && (status === 404 || (status ?? 0) >= 400)) {
        // допустимо вернуть кэш как graceful degradation
        return cache.user;
      }
      return null;
    }
  }
}

/**
 * Фабрика под конкретный эндпоинт (если требуется альтернативный вариант)
 */
export function createMeLoader(options?: Partial<typeof CONFIG>) {
  const cfg = { ...CONFIG, ...(options ?? {}) };
  return (args?: LoaderFunctionArgs) => meLoader(args);
}

export default meLoader;
