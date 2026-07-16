// core-systems/omnimind-core/dashboard/src/app/providers/AuthProvider.tsx
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  PropsWithChildren,
} from "react";
import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";

/**
 * ===========================
 * Конфигурация окружения
 * ===========================
 * Все значения читаются один раз при инициализации.
 * При необходимости адаптируйте под ваш рантайм (Vite/Next).
 */
const APP_NAME = "omnimind-core";
const NS = `${APP_NAME}:auth`;
const isBrowser = typeof window !== "undefined";

const CONFIG = {
  baseURL:
    (isBrowser && (import.meta as any)?.env?.VITE_API_BASE_URL) ||
    process.env.VITE_API_BASE_URL ||
    process.env.API_BASE_URL ||
    "/api",
  tokenRefreshEndpoint:
    (isBrowser && (import.meta as any)?.env?.VITE_API_REFRESH_ENDPOINT) ||
    process.env.VITE_API_REFRESH_ENDPOINT ||
    "/auth/refresh",
  loginEndpoint:
    (isBrowser && (import.meta as any)?.env?.VITE_API_LOGIN_ENDPOINT) ||
    process.env.VITE_API_LOGIN_ENDPOINT ||
    "/auth/login",
  meEndpoint:
    (isBrowser && (import.meta as any)?.env?.VITE_API_ME_ENDPOINT) ||
    process.env.VITE_API_ME_ENDPOINT ||
    "/auth/me",
  logoutEndpoint:
    (isBrowser && (import.meta as any)?.env?.VITE_API_LOGOUT_ENDPOINT) ||
    process.env.VITE_API_LOGOUT_ENDPOINT ||
    "/auth/logout",
  // За сколько миллисекунд до истечения access-токена делаем preemptive refresh
  accessSkewMs: Number(process.env.VITE_AUTH_ACCESS_SKEW_MS || 30_000),
  // Idle-logout при отсутствии пользовательской активности
  idleTimeoutMs: Number(process.env.VITE_AUTH_IDLE_TIMEOUT_MS || 60 * 60 * 1000), // 60 минут
  // Максимум параллельных попыток авто-рефреша одновременно (защита от штормов)
  maxConcurrentRefresh: 1,
};

/**
 * ===========================
 * Типы домена
 * ===========================
 */
export type Role = string;
export type Permission = string;

export interface User {
  id: string;
  email: string;
  name?: string;
  roles?: Role[];
  permissions?: Permission[];
  [key: string]: unknown;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string | null;
  // unix timestamp в секундах
  accessExp?: number | null;
}

interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  tokens: AuthTokens | null;
  error?: string | null;
  rememberMe: boolean;
  lastActiveAt: number; // ms
}

type AuthAction =
  | { type: "INIT_START" }
  | { type: "INIT_SUCCESS"; payload: { user: User | null; tokens: AuthTokens | null; rememberMe: boolean } }
  | { type: "INIT_FAILURE"; payload: { error?: string | null } }
  | { type: "LOGIN_SUCCESS"; payload: { user: User; tokens: AuthTokens; rememberMe: boolean } }
  | { type: "LOGIN_FAILURE"; payload: { error?: string | null } }
  | { type: "LOGOUT" }
  | { type: "REFRESH_SUCCESS"; payload: { tokens: AuthTokens } }
  | { type: "REFRESH_FAILURE"; payload: { error?: string | null } }
  | { type: "SET_USER"; payload: { user: Partial<User> } }
  | { type: "SET_REMEMBER"; payload: { rememberMe: boolean } }
  | { type: "PING" };

export interface LoginCredentials {
  email: string;
  password: string;
  // Дополнительные поля по необходимости
  [key: string]: unknown;
}

/**
 * ===========================
 * Абстракция Storage
 * ===========================
 * Ин-мемори + localStorage/sessionStorage с неймспейсом.
 */
type PersistedPayload = {
  tokens: AuthTokens | null;
  user: User | null;
  rememberMe: boolean;
};

const memoryVault: PersistedPayload = {
  tokens: null,
  user: null,
  rememberMe: false,
};

const storageKeys = {
  bundle: `${NS}:bundle`,
};

function safeParse<T>(raw: string | null): T | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function getStorage(remember: boolean): Storage | { getItem: any; setItem: any; removeItem: any } {
  if (!isBrowser) {
    return {
      getItem: () => null,
      setItem: () => undefined,
      removeItem: () => undefined,
    };
  }
  return remember ? window.localStorage : window.sessionStorage;
}

function persistLoad(): PersistedPayload {
  if (!isBrowser) return { ...memoryVault };
  const fromLS = safeParse<PersistedPayload>(window.localStorage.getItem(storageKeys.bundle));
  const fromSS = safeParse<PersistedPayload>(window.sessionStorage.getItem(storageKeys.bundle));

  // Приоритет sessionStorage (актуальная короткая сессия), иначе fallback на LS
  const data = fromSS ?? fromLS ?? null;
  if (data) return data;
  return { ...memoryVault };
}

function persistSave(payload: PersistedPayload) {
  if (!isBrowser) {
    memoryVault.tokens = payload.tokens;
    memoryVault.user = payload.user;
    memoryVault.rememberMe = payload.rememberMe;
    return;
  }
  // Сохраняем в оба для консистентности, но активным считается rememberMe-хранилище
  window.localStorage.setItem(storageKeys.bundle, JSON.stringify(payload));
  window.sessionStorage.setItem(storageKeys.bundle, JSON.stringify(payload));
}

function persistClear() {
  if (!isBrowser) {
    memoryVault.tokens = null;
    memoryVault.user = null;
    memoryVault.rememberMe = false;
    return;
  }
  window.localStorage.removeItem(storageKeys.bundle);
  window.sessionStorage.removeItem(storageKeys.bundle);
}

/**
 * ===========================
 * Редюсер состояния
 * ===========================
 */
const initialState: AuthState = {
  isAuthenticated: false,
  isLoading: true,
  user: null,
  tokens: null,
  error: null,
  rememberMe: false,
  lastActiveAt: Date.now(),
};

function reducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case "INIT_START":
      return { ...state, isLoading: true, error: null };
    case "INIT_SUCCESS":
      return {
        ...state,
        isLoading: false,
        error: null,
        user: action.payload.user,
        tokens: action.payload.tokens,
        isAuthenticated: Boolean(action.payload.tokens?.accessToken),
        rememberMe: action.payload.rememberMe,
      };
    case "INIT_FAILURE":
      return { ...state, isLoading: false, error: action.payload.error ?? "init_failed", user: null, tokens: null, isAuthenticated: false };
    case "LOGIN_SUCCESS":
      return {
        ...state,
        isLoading: false,
        isAuthenticated: true,
        error: null,
        user: action.payload.user,
        tokens: action.payload.tokens,
        rememberMe: action.payload.rememberMe,
        lastActiveAt: Date.now(),
      };
    case "LOGIN_FAILURE":
      return { ...state, isLoading: false, isAuthenticated: false, error: action.payload.error ?? "login_failed", user: null, tokens: null };
    case "LOGOUT":
      return { ...initialState, isLoading: false };
    case "REFRESH_SUCCESS":
      return { ...state, tokens: action.payload.tokens, isAuthenticated: true };
    case "REFRESH_FAILURE":
      return { ...state, isAuthenticated: false, tokens: null, error: action.payload.error ?? "refresh_failed" };
    case "SET_USER":
      return { ...state, user: { ...(state.user ?? {}), ...action.payload.user } as User };
    case "SET_REMEMBER":
      return { ...state, rememberMe: action.payload.rememberMe };
    case "PING":
      return { ...state, lastActiveAt: Date.now() };
    default:
      return state;
  }
}

/**
 * ===========================
 * Служебные утилиты
 * ===========================
 */
function decodeJwtExp(token?: string | null): number | null {
  if (!token) return null;
  try {
    const [, payloadB64] = token.split(".");
    if (!payloadB64) return null;
    const json = JSON.parse(isBrowser ? atob(payloadB64) : Buffer.from(payloadB64, "base64").toString("utf8"));
    if (typeof json?.exp === "number") return json.exp;
    return null;
  } catch {
    return null;
  }
}

function willExpireSoon(expSec: number | null | undefined, skewMs: number): boolean {
  if (!expSec) return false;
  const nowMs = Date.now();
  const expMs = expSec * 1000;
  return expMs - nowMs <= skewMs;
}

/**
 * ===========================
 * Очередь на время refresh (анти-шторм)
 * ===========================
 */
type Waiter = { resolve: (t: AuthTokens | null) => void; reject: (e: any) => void };
class RefreshGate {
  private inFlight = 0;
  private queue: Waiter[] = [];
  constructor(private maxConcurrent: number) {}
  async enter<T>(fn: () => Promise<T>): Promise<T> {
    if (this.inFlight >= this.maxConcurrent) {
      // ждём текущий refresh
      return new Promise<T>((resolve, reject) => this.queue.push({ resolve: resolve as any, reject }));
    }
    this.inFlight++;
    try {
      const result = await fn();
      this.flush(null);
      return result;
    } catch (e) {
      this.flush(e);
      throw e;
    } finally {
      this.inFlight--;
    }
  }
  private flush(err: any) {
    while (this.queue.length) {
      const w = this.queue.shift()!;
      if (err) w.reject(err);
      else w.resolve(null);
    }
  }
}

/**
 * ===========================
 * Контекст и контракт
 * ===========================
 */
type AuthContextValue = {
  state: AuthState;
  api: AxiosInstance;
  login: (credentials: LoginCredentials, rememberMe?: boolean) => Promise<void>;
  logout: (broadcast?: boolean) => Promise<void>;
  refresh: () => Promise<boolean>;
  hasRole: (role: Role) => boolean;
  hasAnyRole: (roles: Role[]) => boolean;
  hasPermission: (perm: Permission) => boolean;
  setRememberMe: (remember: boolean) => void;
  updateUser: (patch: Partial<User>) => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * ===========================
 * Провайдер
 * ===========================
 */
export function AuthProvider({ children }: PropsWithChildren<{}>) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const refreshGateRef = useRef(new RefreshGate(CONFIG.maxConcurrentRefresh));

  // BroadcastChannel для межвкладочной синхронизации
  const channelRef = useRef<BroadcastChannel | null>(null);
  useEffect(() => {
    if (!isBrowser || typeof BroadcastChannel === "undefined") return;
    const ch = new BroadcastChannel(`${NS}:bc`);
    channelRef.current = ch;
    const onMsg = (ev: MessageEvent) => {
      const { type, payload } = ev.data || {};
      if (type === "logout") {
        persistClear();
        dispatch({ type: "LOGOUT" });
      }
      if (type === "login" && payload) {
        persistSave(payload);
        dispatch({
          type: "LOGIN_SUCCESS",
          payload: {
            user: payload.user,
            tokens: payload.tokens,
            rememberMe: payload.rememberMe,
          },
        });
      }
      if (type === "refresh" && payload) {
        persistSave(payload);
        dispatch({ type: "REFRESH_SUCCESS", payload: { tokens: payload.tokens } });
      }
    };
    ch.addEventListener("message", onMsg);
    return () => {
      ch.removeEventListener("message", onMsg);
      ch.close();
    };
  }, []);

  // Инициализация из стораджа
  useEffect(() => {
    let cancelled = false;
    (async () => {
      dispatch({ type: "INIT_START" });
      const persisted = persistLoad();
      const tokens = persisted.tokens
        ? {
            ...persisted.tokens,
            accessExp: persisted.tokens.accessExp ?? decodeJwtExp(persisted.tokens.accessToken),
          }
        : null;
      if (cancelled) return;
      dispatch({
        type: "INIT_SUCCESS",
        payload: {
          user: persisted.user,
          tokens,
          rememberMe: persisted.rememberMe,
        },
      });
    })().catch((e) => {
      if (!cancelled) dispatch({ type: "INIT_FAILURE", payload: { error: e?.message || "init_error" } });
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // axios инстанс со всеми перехватчиками
  const api = useMemo(() => {
    const instance = axios.create({
      baseURL: CONFIG.baseURL,
      withCredentials: true, // если нужен httpOnly cookie-бекенд
      timeout: 30_000,
    });

    // Request: подставляем accessToken
    instance.interceptors.request.use((config: AxiosRequestConfig) => {
      const at = state.tokens?.accessToken;
      if (at) {
        config.headers = config.headers ?? {};
        (config.headers as any).Authorization = `Bearer ${at}`;
      }
      return config;
    });

    // Response: авто-refresh на 401 один раз
    const interceptor = instance.interceptors.response.use(
      (res) => res,
      async (error: AxiosError) => {
        const original = error.config as AxiosRequestConfig & { _retry?: boolean };
        const status = error.response?.status;

        // Не рефрешим на эндпоинтах логина/рефреша, и не пытаемся повторно
        const url = (original?.url || "").toString();
        const isAuthUrl =
          url.includes(CONFIG.loginEndpoint) || url.includes(CONFIG.tokenRefreshEndpoint) || url.includes(CONFIG.logoutEndpoint);

        if (status === 401 && !original?._retry && !isAuthUrl) {
          original._retry = true;
          const ok = await doRefresh();
          if (ok) {
            // после успешного refresh – повторяем запрос с новым accessToken
            const newAt = state.tokens?.accessToken || persistLoad().tokens?.accessToken;
            original.headers = original.headers ?? {};
            if (newAt) (original.headers as any).Authorization = `Bearer ${newAt}`;
            return instance(original);
          }
        }
        return Promise.reject(error);
      }
    );

    // Очистка на анмаунт (теоретически в провайдере не требуется, но оставим)
    return instance;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.tokens?.accessToken]);

  // Функция рефреша с анти-шторм очередью
  const doRefresh = useCallback(async (): Promise<boolean> => {
    const persisted = persistLoad();
    const tokens = state.tokens ?? persisted.tokens;
    if (!tokens?.refreshToken) {
      // Нечего рефрешить
      return false;
    }
    try {
      await refreshGateRef.current.enter(async () => {
        // При повторном входе параллельные ждут
        const res: AxiosResponse<{
          accessToken: string;
          refreshToken?: string | null;
        }> = await axios.post(
          CONFIG.tokenRefreshEndpoint,
          { refreshToken: tokens.refreshToken },
          { baseURL: CONFIG.baseURL, withCredentials: true }
        );

        const accessExp = decodeJwtExp(res.data.accessToken);
        const newTokens: AuthTokens = {
          accessToken: res.data.accessToken,
          refreshToken: res.data.refreshToken ?? tokens.refreshToken ?? null,
          accessExp,
        };

        const bundle: PersistedPayload = {
          tokens: newTokens,
          user: state.user ?? persisted.user ?? null,
          rememberMe: state.rememberMe ?? persisted.rememberMe ?? false,
        };
        persistSave(bundle);
        dispatch({ type: "REFRESH_SUCCESS", payload: { tokens: newTokens } });
        channelRef.current?.postMessage({ type: "refresh", payload: bundle });
      });
      return true;
    } catch (e: any) {
      dispatch({ type: "REFRESH_FAILURE", payload: { error: e?.message || "refresh_error" } });
      persistClear();
      channelRef.current?.postMessage({ type: "logout" });
      return false;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.tokens, state.user, state.rememberMe]);

  // Preemptive refresh по таймеру и idle-logout
  useEffect(() => {
    if (!state.tokens?.accessToken) return;
    const expSec = state.tokens.accessExp ?? decodeJwtExp(state.tokens.accessToken);
    const tick = setInterval(() => {
      // Idle-logout
      if (CONFIG.idleTimeoutMs > 0 && Date.now() - state.lastActiveAt > CONFIG.idleTimeoutMs) {
        // не использовали интерфейс — выходим
        void logout(true);
        return;
      }
      // Preemptive refresh
      if (willExpireSoon(expSec, CONFIG.accessSkewMs)) {
        void doRefresh();
      }
    }, 5_000);
    return () => clearInterval(tick);
  }, [state.tokens?.accessToken, state.tokens?.accessExp, state.lastActiveAt, doRefresh]);

  // Слежение за пользовательской активностью
  useEffect(() => {
    if (!isBrowser) return;
    const ping = () => dispatch({ type: "PING" });
    const events = ["click", "keydown", "mousemove", "scroll", "touchstart", "visibilitychange"];
    events.forEach((e) => window.addEventListener(e, ping, { passive: true }));
    return () => {
      events.forEach((e) => window.removeEventListener(e, ping));
    };
  }, []);

  // Методы API контекста
  const login = useCallback(
    async (credentials: LoginCredentials, rememberMe = false) => {
      dispatch({ type: "INIT_START" });
      try {
        const res: AxiosResponse<{
          user: User;
          accessToken: string;
          refreshToken?: string | null;
        }> = await axios.post(CONFIG.loginEndpoint, credentials, {
          baseURL: CONFIG.baseURL,
          withCredentials: true,
        });

        const accessExp = decodeJwtExp(res.data.accessToken);
        const tokens: AuthTokens = {
          accessToken: res.data.accessToken,
          refreshToken: res.data.refreshToken ?? null,
          accessExp,
        };

        const bundle: PersistedPayload = { user: res.data.user, tokens, rememberMe };
        persistSave(bundle);

        dispatch({ type: "LOGIN_SUCCESS", payload: { user: res.data.user, tokens, rememberMe } });
        channelRef.current?.postMessage({ type: "login", payload: bundle });
      } catch (e: any) {
        const msg = (e as AxiosError)?.response?.data ?? e?.message ?? "login_error";
        dispatch({ type: "LOGIN_FAILURE", payload: { error: typeof msg === "string" ? msg : "login_error" } });
        throw e;
      }
    },
    []
  );

  const logout = useCallback(
    async (broadcast = false) => {
      try {
        // Не блокируем UI: уведомление бэкенда "best effort"
        await axios.post(
          CONFIG.logoutEndpoint,
          {},
          { baseURL: CONFIG.baseURL, withCredentials: true }
        ).catch(() => {});
      } finally {
        persistClear();
        dispatch({ type: "LOGOUT" });
        if (broadcast) channelRef.current?.postMessage({ type: "logout" });
      }
    },
    []
  );

  const refresh = useCallback(async () => doRefresh(), [doRefresh]);

  const setRememberMe = useCallback((remember: boolean) => {
    dispatch({ type: "SET_REMEMBER", payload: { rememberMe: remember } });
    const cur = persistLoad();
    persistSave({ ...cur, rememberMe: remember });
  }, []);

  const updateUser = useCallback((patch: Partial<User>) => {
    dispatch({ type: "SET_USER", payload: { user: patch } });
    const cur = persistLoad();
    persistSave({ ...cur, user: { ...(cur.user ?? {}), ...patch } as User });
  }, []);

  const hasRole = useCallback(
    (role: Role) => Boolean(state.user?.roles?.includes(role)),
    [state.user?.roles]
  );

  const hasAnyRole = useCallback(
    (roles: Role[]) => {
      const set = new Set(state.user?.roles ?? []);
      return roles.some((r) => set.has(r));
    },
    [state.user?.roles]
  );

  const hasPermission = useCallback(
    (perm: Permission) => Boolean(state.user?.permissions?.includes(perm)),
    [state.user?.permissions]
  );

  const value: AuthContextValue = useMemo(
    () => ({
      state,
      api,
      login,
      logout,
      refresh,
      hasRole,
      hasAnyRole,
      hasPermission,
      setRememberMe,
      updateUser,
    }),
    [state, api, login, logout, refresh, hasRole, hasAnyRole, hasPermission, setRememberMe, updateUser]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * Хук доступа к контексту
 */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider />");
  return ctx;
}
