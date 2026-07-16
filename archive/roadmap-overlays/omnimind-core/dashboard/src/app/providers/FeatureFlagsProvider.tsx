'use client';

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  PropsWithChildren,
} from 'react';

/**
 * FeatureFlagsProvider.tsx
 * Индустриальный провайдер фичефлагов для React/Next.js (App Router).
 *
 * Возможности:
 * - Источники значений: initialFlags (из SSR/props) → envOverrides → remote (HTTP JSON).
 * - Кэширование: localStorage с ETag/Last-Modified (согласно HTTP Semantics, RFC 9110).
 * - SSR-безопасность: не обращается к window при рендеринге на сервере.
 * - Детерминированный bucketing (A/B) по userId/feature: stable 32-bit hash.
 * - Лог экспозиций: onExposure(key, value, variant, meta).
 * - Авто-периодическое обновление (pollIntervalMs), AbortController.
 * - Строгие API-хуки: useFeatureFlags(), useFeatureFlag(key,...).
 * - Ошибки/статусы: ready/error/lastUpdated; ручной refresh().
 */

/** Базовый тип значения флага */
export type FlagValue = boolean | number | string | null;

/** Словарь флагов */
export type FeatureFlagsMap = Record<string, FlagValue>;

/** Метаданные ответа удалённого источника */
type RemoteMeta = {
  etag?: string;
  lastModified?: string;
};

/** Конфигурация удалённого источника */
export type RemoteSource = {
  url: string;
  headers?: Record<string, string>;
  /** Ключ в ответе, где лежит объект флагов. Если пусто — ожидается плоский объект. */
  jsonPath?: string; // например: "data.flags"
};

/** Колбэки телеметрии */
export type FlagsTelemetry = {
  onExposure?: (payload: {
    key: string;
    value: FlagValue;
    variant?: string | null;
    userId?: string | null;
    source: 'initial' | 'env' | 'remote' | 'cache';
    now: number;
    meta?: Record<string, unknown>;
  }) => void;
  onUpdate?: (payload: {
    previous: FeatureFlagsMap;
    next: FeatureFlagsMap;
    now: number;
    source: 'remote' | 'cache';
  }) => void;
  onError?: (err: unknown) => void;
};

export type FeatureFlagsProviderProps = PropsWithChildren<{
  /** Начальные флаги (SSR или build-time) */
  initialFlags?: FeatureFlagsMap;
  /** Принудительные переопределения из env (например, process.env.NEXT_PUBLIC_FF__*) */
  envOverrides?: FeatureFlagsMap;
  /** Удалённый источник правды (JSON endpoint) */
  remoteSource?: RemoteSource;
  /** Пользовательский идентификатор для детерминированного bucketing */
  userId?: string | null;
  /** Интервал авто-опроса удалённого источника, мс (0/undefined — отключить) */
  pollIntervalMs?: number;
  /** Неймспейс для ключей localStorage */
  storageNamespace?: string; // по умолчанию: "ff:core"
  /** Таймаут HTTP-запроса, мс */
  fetchTimeoutMs?: number; // по умолчанию: 5000
  /** Телеметрия */
  telemetry?: FlagsTelemetry;
}>;

export type FeatureFlagsContextShape = {
  /** Все флаги после слияния источников */
  all: FeatureFlagsMap;
  /** Источник конкретного ключа */
  getSourceOf: (key: string) => 'initial' | 'env' | 'remote' | 'cache' | 'unknown';
  /** Возвращает значение флага с типобезопасным дефолтом */
  getFlag: <T extends FlagValue = FlagValue>(key: string, fallback?: T) => T;
  /** Быстрая проверка включённости (для boolean) */
  isEnabled: (key: string, fallback?: boolean) => boolean;
  /** Вариант (bucket) для A/B — строка-метка, детерминированно от userId+key */
  variantOf: (key: string, variants: string[], fallback?: string) => string;
  /** Лог экспозиции (ручной) */
  expose: (key: string, meta?: Record<string, unknown>) => void;
  /** Принудительное обновление из удалённого источника */
  refresh: () => Promise<void>;
  /** Готовность/ошибки */
  ready: boolean;
  error: unknown | null;
  lastUpdated: number | null;
};

const FeatureFlagsContext = createContext<FeatureFlagsContextShape | null>(null);

/** Безопасная проверка среды исполнения */
const isBrowser = typeof window !== 'undefined' && typeof document !== 'undefined';

/** Stable 32-bit hash (FNV-1a) для bucketing */
function hash32(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  // to unsigned 32
  return h >>> 0;
}

function pickVariant(key: string, userId: string | null | undefined, variants: string[], fallback?: string) {
  if (!variants || variants.length === 0) return fallback ?? 'control';
  const base = `${key}::${userId ?? 'anon'}`;
  const idx = hash32(base) % variants.length;
  return variants[idx];
}

/** Парс JSON c произвольным jsonPath вида "a.b.c" */
function pickByPath(obj: any, path?: string): any {
  if (!path) return obj;
  return path.split('.').reduce((acc, seg) => (acc && typeof acc === 'object' ? acc[seg] : undefined), obj);
}

/** Ключи для localStorage */
function makeStorageKeys(ns: string) {
  const base = ns || 'ff:core';
  return {
    flags: `${base}:flags`,
    meta: `${base}:meta`,
  };
}

/** Попытаться прочитать JSON из localStorage */
function readLS<T>(key: string): T | null {
  if (!isBrowser) return null;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

/** Записать JSON в localStorage */
function writeLS(key: string, value: unknown) {
  if (!isBrowser) return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // игнорируем кворум/квоту
  }
}

/** Объединить источники: initial → env → cache/remote (последний приоритет) */
function mergeFlags(a?: FeatureFlagsMap, b?: FeatureFlagsMap, c?: FeatureFlagsMap): FeatureFlagsMap {
  return Object.freeze({
    ...(a || {}),
    ...(b || {}),
    ...(c || {}),
  });
}

/** Abortable fetch с таймаутом */
async function fetchWithTimeout(input: RequestInfo, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

/** Провайдер */
export function FeatureFlagsProvider({
  children,
  initialFlags,
  envOverrides,
  remoteSource,
  userId,
  pollIntervalMs,
  storageNamespace = 'ff:core',
  fetchTimeoutMs = 5000,
  telemetry,
}: FeatureFlagsProviderProps) {
  const storageKeys = useMemo(() => makeStorageKeys(storageNamespace), [storageNamespace]);

  const [ready, setReady] = useState<boolean>(!remoteSource); // если нет удалённого — готовы сразу
  const [error, setError] = useState<unknown | null>(null);
  const [all, setAll] = useState<FeatureFlagsMap>(() => {
    // начальная сборка без обращения к window на сервере
    const initial = mergeFlags(initialFlags, envOverrides, undefined);
    return initial;
  });
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);

  const sourceOfRef = useRef<Record<string, FeatureFlagsContextShape['getSourceOf']>>({});
  const remoteMetaRef = useRef<RemoteMeta>({});
  const lastEmittedRef = useRef<string>(''); // для onUpdate de-dupe

  // Инициализация из localStorage (если есть кэш)
  useEffect(() => {
    if (!isBrowser) return;
    const cachedFlags = readLS<FeatureFlagsMap>(storageKeys.flags);
    const cachedMeta = readLS<RemoteMeta>(storageKeys.meta);
    if (cachedFlags) {
      const merged = mergeFlags(initialFlags, envOverrides, cachedFlags);
      setAll(merged);
      setLastUpdated(Date.now());
      sourceOfRef.current = Object.fromEntries(Object.keys(merged).map((k) => [k, 'cache']));
    }
    if (cachedMeta) {
      remoteMetaRef.current = cachedMeta;
    }
    // Если нет удалённого источника — считаем готовым.
    if (!remoteSource) setReady(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storageKeys.flags, storageKeys.meta]);

  // Загрузка из удалённого источника
  const loadRemote = useCallback(
    async (reason: 'initial' | 'poll' | 'manual' = 'initial') => {
      if (!remoteSource?.url) return;

      try {
        setError(null);
        const headers: Record<string, string> = {
          Accept: 'application/json',
          ...(remoteSource.headers || {}),
        };

        // RFC 9110: Conditional Requests — отправляем If-None-Match/If-Modified-Since при наличии.
        if (remoteMetaRef.current.etag) headers['If-None-Match'] = remoteMetaRef.current.etag;
        if (remoteMetaRef.current.lastModified) headers['If-Modified-Since'] = remoteMetaRef.current.lastModified;

        const res = await fetchWithTimeout(
          remoteSource.url,
          {
            method: 'GET',
            headers,
            cache: 'no-cache',
          },
          fetchTimeoutMs,
        );

        if (res.status === 304) {
          // не изменилось
          setReady(true);
          return;
        }

        if (!res.ok) {
          throw new Error(`Remote flags HTTP ${res.status}`);
        }

        const etag = res.headers.get('ETag') || undefined;
        const lastModified = res.headers.get('Last-Modified') || undefined;

        const json = await res.json();
        const body = pickByPath(json, remoteSource.jsonPath);
        if (!body || typeof body !== 'object') {
          throw new Error('Remote flags: invalid JSON shape');
        }

        const remoteFlags = body as FeatureFlagsMap;
        const next = mergeFlags(initialFlags, envOverrides, remoteFlags);

        // Источники: помечаем ключи как 'remote'
        sourceOfRef.current = Object.fromEntries(Object.keys(next).map((k) => [k, 'remote']));

        // Обновление состояния
        setAll((prev) => {
          const prevSer = JSON.stringify(prev);
          const nextSer = JSON.stringify(next);
          if (prevSer !== nextSer) {
            // локальный кэш
            writeLS(storageKeys.flags, remoteFlags);
            writeLS(storageKeys.meta, { etag, lastModified });
            remoteMetaRef.current = { etag, lastModified };

            setLastUpdated(Date.now());

            if (telemetry?.onUpdate && lastEmittedRef.current !== nextSer) {
              telemetry.onUpdate({
                previous: prev,
                next,
                now: Date.now(),
                source: 'remote',
              });
              lastEmittedRef.current = nextSer;
            }

            return next;
          }
          return prev;
        });

        setReady(true);
      } catch (e) {
        setError(e);
        telemetry?.onError?.(e);
        // Не сбрасываем текущие флаги; работаем деградированно.
        setReady(true);
      }
    },
    [envOverrides, fetchTimeoutMs, initialFlags, remoteSource, storageKeys.flags, storageKeys.meta, telemetry],
  );

  // Первая загрузка удалённых флагов
  useEffect(() => {
    if (!remoteSource?.url) return;
    void loadRemote('initial');
  }, [loadRemote, remoteSource?.url]);

  // Авто-поллинг
  useEffect(() => {
    if (!remoteSource?.url || !pollIntervalMs || pollIntervalMs <= 0) return;
    const id = setInterval(() => void loadRemote('poll'), pollIntervalMs);
    return () => clearInterval(id);
  }, [loadRemote, pollIntervalMs, remoteSource?.url]);

  // API контекста
  const getFlag = useCallback(
    <T extends FlagValue = FlagValue>(key: string, fallback?: T): T => {
      const v = all[key];
      return (v === undefined ? (fallback as T) : (v as T));
    },
    [all],
  );

  const isEnabled = useCallback(
    (key: string, fallback = false) => {
      const v = all[key];
      if (typeof v === 'boolean') return v;
      if (typeof v === 'string') {
        const s = v.toLowerCase().trim();
        if (s === 'true' || s === '1' || s === 'on' || s === 'enabled') return true;
        if (s === 'false' || s === '0' || s === 'off' || s === 'disabled') return false;
      }
      if (typeof v === 'number') return v !== 0;
      return fallback;
    },
    [all],
  );

  const getSourceOf: FeatureFlagsContextShape['getSourceOf'] = useCallback(
    (key) => sourceOfRef.current[key] || 'unknown',
    [],
  );

  const variantOf = useCallback(
    (key: string, variants: string[], fallback?: string) => pickVariant(key, userId, variants, fallback),
    [userId],
  );

  const expose = useCallback(
    (key: string, meta?: Record<string, unknown>) => {
      const value = all[key] ?? null;
      telemetry?.onExposure?.({
        key,
        value,
        variant: typeof value === 'string' ? (value as string) : null,
        userId: userId ?? null,
        source: getSourceOf(key) === 'unknown' ? 'cache' : (getSourceOf(key) as any),
        now: Date.now(),
        meta,
      });
    },
    [all, getSourceOf, telemetry, userId],
  );

  const refresh = useCallback(async () => {
    await loadRemote('manual');
  }, [loadRemote]);

  const ctx = useMemo<FeatureFlagsContextShape>(
    () => ({
      all,
      getSourceOf,
      getFlag,
      isEnabled,
      variantOf,
      expose,
      refresh,
      ready,
      error,
      lastUpdated,
    }),
    [all, error, expose, getFlag, getSourceOf, isEnabled, lastUpdated, ready, refresh, variantOf],
  );

  return <FeatureFlagsContext.Provider value={ctx}>{children}</FeatureFlagsContext.Provider>;
}

/** Хук доступа к контексту фичефлагов */
export function useFeatureFlags(): FeatureFlagsContextShape {
  const ctx = useContext(FeatureFlagsContext);
  if (!ctx) {
    throw new Error('useFeatureFlags must be used within <FeatureFlagsProvider>');
  }
  return ctx;
}

/** Удобный хук для одного флага с авто-экспозицией */
export function useFeatureFlag<T extends FlagValue = FlagValue>(
  key: string,
  options?: {
    defaultValue?: T;
    /** Автоматически отправить экспозицию при первом монтировании */
    trackExposure?: boolean;
    /** Варианты A/B для bucketing. Если передано — вернётся выбранный вариант как string. */
    variants?: string[];
    /** Доп. метаданные экспозиции */
    exposureMeta?: Record<string, unknown>;
  },
): T extends string ? string : T {
  const { getFlag, expose, ready, variantOf } = useFeatureFlags();

  const value = useMemo(() => {
    if (options?.variants && options.variants.length > 0) {
      // если задан список вариантов — вернём выбранный вариант
      return variantOf(key, options.variants) as unknown as T;
    }
    return getFlag<T>(key, options?.defaultValue as T);
  }, [getFlag, key, options?.defaultValue, options?.variants, variantOf]);

  const exposedRef = useRef<boolean>(false);
  useEffect(() => {
    if (!ready) return;
    if (options?.trackExposure && !exposedRef.current) {
      expose(key, options?.exposureMeta);
      exposedRef.current = true;
    }
  }, [expose, key, options?.exposureMeta, options?.trackExposure, ready]);

  return value as any;
}

/**
 * Пример использования (Next.js App Router):
 *
 * <FeatureFlagsProvider
 *   initialFlags={{ ui_dark_mode: true }}
 *   envOverrides={{ /* из process.env.NEXT_PUBLIC_*  *\/ }}
 *   remoteSource={{ url: '/api/feature-flags', jsonPath: 'data' }}
 *   userId={user?.id}
 *   pollIntervalMs={30000}
 *   telemetry={{ onExposure: (e) => console.log('exposure', e) }}
 * >
 *   {children}
 * </FeatureFlagsProvider>
 *
 * const isNewHeader = useFeatureFlag<boolean>('ui_new_header', { defaultValue: false, trackExposure: true });
 * const bucket = useFeatureFlag<string>('experiment_checkout', { variants: ['A','B','C'], trackExposure: true });
 */
