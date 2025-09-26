// frontend/src/features/monitoring/hooks/useSystemStatus.ts
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

/**
 * Типы домена
 */
export type Severity = "ok" | "degraded" | "minor" | "major" | "critical" | "unknown";

export interface ServiceStatus {
  id: string;
  name: string;
  severity: Severity;
  message?: string;
  updatedAt?: string; // ISO
  meta?: Record<string, unknown>;
}

export interface SystemStatus {
  overall: Severity;
  services: ServiceStatus[];
  version?: string;
  generatedAt?: string; // ISO
  meta?: Record<string, unknown>;
}

export type ValidationResult =
  | { ok: true; value: SystemStatus }
  | { ok: false; error: Error };

export interface UseSystemStatusOptions {
  /**
   * REST endpoint для статуса. Должен возвращать JSON совместимый с SystemStatus.
   * Пример: /api/monitoring/status
   */
  endpoint: string;

  /**
   * Интервал опроса в мс (по умолчанию 15000)
   */
  pollIntervalMs?: number;

  /**
   * Максимальный интервал при бэкоффе (по умолчанию 120000)
   */
  maxPollIntervalMs?: number;

  /**
   * Функция валидации ответа (рекомендуется использовать zod или io-ts).
   * Если не задана — применяется мягкая структурная проверка.
   */
  validate?: (data: unknown) => ValidationResult;

  /**
   * Включить SWR: моментально возвращать кэш и параллельно ревалидировать (по умолчанию true)
   */
  swr?: boolean;

  /**
   * Стратегия синхронизации между вкладками (BroadcastChannel). По умолчанию true
   */
  syncAcrossTabs?: boolean;

  /**
   * Останавливать опрос при скрытом табе (visibilitychange). По умолчанию true
   */
  pauseOnHidden?: boolean;

  /**
   * Останавливать опрос при offline. По умолчанию true
   */
  pauseOnOffline?: boolean;

  /**
   * Автозапуск опроса. По умолчанию true
   */
  autoStart?: boolean;

  /**
   * Подписка на WebSocket пуш-событий (частичные апдейты или полные снапшоты)
   */
  websocket?: {
    url: string;
    /** Ключи протокола/заголовки и т.п. */
    protocols?: string | string[];
    /**
     * Если true — сообщения считаются полным снапшотом SystemStatus.
     * Иначе ожидаем объект { type: "partial"|"full", payload: ... }.
     */
    messagesAreFullSnapshot?: boolean;
  };

  /**
   * Таймаут запроса в мс (по умолчанию 8000)
   */
  requestTimeoutMs?: number;

  /**
   * Пользовательский fetch (для изоморфного окружения / тестов)
   */
  fetcher?: typeof fetch;

  /**
   * Колбэк на каждое обновление валидных данных
   */
  onUpdate?: (status: SystemStatus) => void;

  /**
   * Ключ кэша. Если не задан — используется endpoint
   */
  cacheKey?: string;
}

export interface UseSystemStatusApi {
  data: SystemStatus | null;
  error: Error | null;
  loading: boolean;
  stale: boolean;
  lastUpdatedAt: number | null;
  isOnline: boolean;
  isActive: boolean;
  etag: string | null;

  refetch: (opts?: { force?: boolean }) => Promise<void>;
  start: () => void;
  stop: () => void;
  setIntervalMs: (ms: number) => void;

  /**
   * Локальные подписчики изменений (внутриклиентские)
   */
  subscribe: (fn: (s: SystemStatus) => void) => () => void;
}

/**
 * Внутренний in-memory кэш и подписки
 */
type CacheEntry = {
  data: SystemStatus | null;
  etag: string | null;
  lastUpdatedAt: number | null;
  stale: boolean;
  subs: Set<(s: SystemStatus) => void>;
};
const MEMORY_CACHE = new Map<string, CacheEntry>();

/**
 * Безопасная структурная проверка, если валидатор не предоставлен.
 * НЕ гарантирует полную типобезопасность, но отсекает самые грубые несоответствия.
 */
function softValidate(data: unknown): ValidationResult {
  try {
    if (
      typeof data === "object" &&
      data !== null &&
      "overall" in data &&
      "services" in data &&
      Array.isArray((data as any).services)
    ) {
      const d = data as any;
      const servicesOk = d.services.every(
        (s: any) =>
          s &&
          typeof s === "object" &&
          typeof s.id === "string" &&
          typeof s.name === "string" &&
          typeof s.severity === "string"
      );
      if (!servicesOk) throw new Error("Invalid services structure");
      const result: SystemStatus = {
        overall: typeof d.overall === "string" ? d.overall : "unknown",
        services: d.services as ServiceStatus[],
        version: typeof d.version === "string" ? d.version : undefined,
        generatedAt: typeof d.generatedAt === "string" ? d.generatedAt : undefined,
        meta: typeof d.meta === "object" && d.meta !== null ? d.meta : undefined,
      };
      return { ok: true, value: result };
    }
    throw new Error("Unexpected shape");
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e : new Error("Validation error") };
  }
}

/**
 * Определение минимальной "тяжести" статуса
 */
function combineSeverity(a: Severity, b: Severity): Severity {
  const order: Severity[] = ["ok", "degraded", "minor", "major", "critical", "unknown"];
  const idxA = order.indexOf(a);
  const idxB = order.indexOf(b);
  if (idxA === -1 || idxB === -1) return "unknown";
  return order[Math.max(idxA, idxB)];
}

/**
 * Хук мониторинга системного статуса с поддержкой SWR, ETag, WS и т.д.
 */
export function useSystemStatus(options: UseSystemStatusOptions): UseSystemStatusApi {
  const {
    endpoint,
    pollIntervalMs = 15_000,
    maxPollIntervalMs = 120_000,
    validate = softValidate,
    swr = true,
    syncAcrossTabs = true,
    pauseOnHidden = true,
    pauseOnOffline = true,
    autoStart = true,
    websocket,
    requestTimeoutMs = 8_000,
    fetcher = fetch,
    onUpdate,
    cacheKey,
  } = options;

  const key = cacheKey ?? endpoint;
  // Инициализация кэша по ключу
  if (!MEMORY_CACHE.has(key)) {
    MEMORY_CACHE.set(key, {
      data: null,
      etag: null,
      lastUpdatedAt: null,
      stale: true,
      subs: new Set(),
    });
  }
  const entry = MEMORY_CACHE.get(key)!;

  // Локальные состояния
  const [data, setData] = useState<SystemStatus | null>(entry.data);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(!entry.data);
  const [stale, setStale] = useState<boolean>(entry.stale);
  const [intervalMs, setIntervalMsState] = useState<number>(pollIntervalMs);
  const [isActive, setIsActive] = useState<boolean>(autoStart);
  const [etag, setEtag] = useState<string | null>(entry.etag);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(entry.lastUpdatedAt);
  const [isOnline, setIsOnline] = useState<boolean>(
    typeof navigator !== "undefined" ? navigator.onLine : true
  );

  const bcRef = useRef<BroadcastChannel | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const backoffRef = useRef<number>(intervalMs);
  const visibleRef = useRef<boolean>(
    typeof document !== "undefined" ? document.visibilityState !== "hidden" : true
  );

  /**
   * Утилита обновления кэша и подписчиков
   */
  const commit = useCallback(
    (next: SystemStatus, nextEtag: string | null) => {
      const now = Date.now();
      entry.data = next;
      entry.stale = false;
      entry.etag = nextEtag;
      entry.lastUpdatedAt = now;

      setData(next);
      setStale(false);
      setEtag(nextEtag);
      setLastUpdatedAt(now);
      setLoading(false);
      setError(null);

      // Внутренние подписчики
      entry.subs.forEach((fn) => {
        try {
          fn(next);
        } catch {
          // не прерываем рассылку
        }
      });

      // BroadcastChannel для межвкладочной синхронизации
      if (bcRef.current) {
        bcRef.current.postMessage({
          type: "SYSTEM_STATUS_UPDATE",
          key,
          payload: { next, etag: nextEtag, ts: now },
        });
      }

      // Колбэк клиента
      onUpdate?.(next);
    },
    [entry, key, onUpdate]
  );

  /**
   * Применить частичный патч от WS-сообщения
   */
  const applyPartial = useCallback(
    (patch: Partial<SystemStatus>) => {
      const base = entry.data;
      const merged: SystemStatus = {
        overall: patch.overall ?? base?.overall ?? "unknown",
        services: patch.services ?? base?.services ?? [],
        version: patch.version ?? base?.version,
        generatedAt: patch.generatedAt ?? base?.generatedAt,
        meta: { ...(base?.meta ?? {}), ...(patch.meta ?? {}) },
      };
      // Пересобрать overall от сервисов, если не пришёл явный
      if (!patch.overall && merged.services.length > 0) {
        const overal = merged.services.reduce<Severity>(
          (acc, s) => combineSeverity(acc, s.severity),
          "ok"
        );
        merged.overall = overal;
      }
      commit(merged, etag);
    },
    [commit, entry.data, etag]
  );

  /**
   * Запрос с поддержкой Abort, таймаута и ETag
   */
  const doRequest = useCallback(
    async (force = false) => {
      if (!isActive) return;
      if (pauseOnOffline && !isOnline) return;
      if (pauseOnHidden && !visibleRef.current) return;

      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;

      // Таймаут запроса
      const timeout = setTimeout(() => ac.abort(), requestTimeoutMs);

      try {
        const headers: Record<string, string> = {
          Accept: "application/json",
          "Cache-Control": "no-cache",
        };
        if (etag && !force) {
          headers["If-None-Match"] = etag;
        }

        const res = await fetcher(endpoint, {
          method: "GET",
          headers,
          signal: ac.signal,
        });

        // 304 Not Modified — оставляем кэш, помечаем как свежий
        if (res.status === 304) {
          entry.stale = false;
          setStale(false);
          setLoading(false);
          setError(null);
          backoffRef.current = intervalMs; // успешный ответ — сброс бэкоффа
          return;
        }

        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${await safeText(res)}`);
        }

        const nextEtag = res.headers.get("ETag");
        const json = (await res.json()) as unknown;

        const validated = validate(json);
        if (!validated.ok) {
          throw validated.error;
        }

        commit(validated.value, nextEtag);
        backoffRef.current = intervalMs; // сброс бэкоффа
      } catch (e) {
        const err = e instanceof Error ? e : new Error("Unknown error");
        setError(err);
        setLoading(false);
        entry.stale = true;
        setStale(true);

        // экспоненциальный бэкофф
        backoffRef.current = Math.min(
          Math.max(1_000, Math.round(backoffRef.current * 1.7)),
          maxPollIntervalMs
        );
      } finally {
        clearTimeout(timeout);
      }
    },
    [
      endpoint,
      fetcher,
      intervalMs,
      isActive,
      isOnline,
      pauseOnOffline,
      pauseOnHidden,
      requestTimeoutMs,
      validate,
      commit,
      maxPollIntervalMs,
      etag,
      entry,
    ]
  );

  /**
   * SWR старт: мгновенно отдать кэш и ревалидировать
   */
  const initialKick = useCallback(async () => {
    if (swr && entry.data) {
      setData(entry.data);
      setStale(entry.stale);
      setEtag(entry.etag);
      setLastUpdatedAt(entry.lastUpdatedAt);
      setLoading(false);
    } else {
      setLoading(true);
    }
    await doRequest(false);
  }, [doRequest, entry.data, entry.etag, entry.lastUpdatedAt, entry.stale, swr]);

  /**
   * Планировщик повторов
   */
  const schedule = useCallback(() => {
    if (!isActive) return;
    if (timerRef.current) window.clearTimeout(timerRef.current);
    const delay = backoffRef.current;
    timerRef.current = window.setTimeout(async () => {
      await doRequest(false);
      schedule(); // планируем следующий цикл
    }, delay) as unknown as number;
  }, [doRequest, isActive]);

  /**
   * Управление жизненным циклом: старт/стоп
   */
  const start = useCallback(() => {
    if (isActive) return;
    setIsActive(true);
  }, [isActive]);

  const stop = useCallback(() => {
    if (!isActive) return;
    setIsActive(false);
    if (timerRef.current) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    abortRef.current?.abort();
  }, [isActive]);

  const refetch = useCallback(
    async (opts?: { force?: boolean }) => {
      await doRequest(Boolean(opts?.force));
    },
    [doRequest]
  );

  const setIntervalMs = useCallback((ms: number) => {
    const next = Math.max(1_000, Math.floor(ms));
    setIntervalMsState(next);
    backoffRef.current = next;
  }, []);

  /**
   * Вкладочная синхронизация через BroadcastChannel
   */
  useEffect(() => {
    if (!syncAcrossTabs || typeof BroadcastChannel === "undefined") return;
    const bc = new BroadcastChannel(`SYSTEM_STATUS:${key}`);
    bcRef.current = bc;

    bc.onmessage = (evt) => {
      const msg = evt.data as
        | { type: "SYSTEM_STATUS_UPDATE"; key: string; payload: { next: SystemStatus; etag: string | null; ts: number } }
        | { type: "SYSTEM_STATUS_REFETCH"; key: string }
        | undefined;
      if (!msg || msg.key !== key) return;

      if (msg.type === "SYSTEM_STATUS_UPDATE") {
        commit(msg.payload.next, msg.payload.etag);
      }
      if (msg.type === "SYSTEM_STATUS_REFETCH") {
        // получено извне — мягкая реалидация
        doRequest(false);
      }
    };

    return () => {
      bc.close();
      bcRef.current = null;
    };
  }, [commit, doRequest, key, syncAcrossTabs]);

  /**
   * Подписка на локальные изменения
   */
  const subscribe = useCallback(
    (fn: (s: SystemStatus) => void) => {
      entry.subs.add(fn);
      return () => entry.subs.delete(fn);
    },
    [entry]
  );

  /**
   * Видимость вкладки и онлайн/офлайн
   */
  useEffect(() => {
    const onVis = () => {
      const visible = document.visibilityState !== "hidden";
      visibleRef.current = visible;
      if (visible && isActive) {
        // мгновенная ревалидция при возвращении
        doRequest(false);
      }
    };
    const onOnline = () => {
      setIsOnline(true);
      if (isActive) doRequest(false);
    };
    const onOffline = () => setIsOnline(false);

    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", onVis);
    }
    if (typeof window !== "undefined") {
      window.addEventListener("online", onOnline);
      window.addEventListener("offline", onOffline);
    }
    return () => {
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", onVis);
      }
      if (typeof window !== "undefined") {
        window.removeEventListener("online", onOnline);
        window.removeEventListener("offline", onOffline);
      }
    };
  }, [doRequest, isActive]);

  /**
   * Управление WS-подключением
   */
  useEffect(() => {
    if (!websocket || !isActive) return;

    try {
      const ws = new WebSocket(websocket.url, websocket.protocols);
      wsRef.current = ws;

      ws.onopen = () => {
        // при открытии — мягкая ревалидция
        doRequest(false);
      };
      ws.onmessage = (ev) => {
        try {
          const payload = JSON.parse(ev.data as string);
          if (websocket.messagesAreFullSnapshot) {
            const v = validate(payload);
            if (v.ok) commit(v.value, etag);
          } else {
            // ожидаем { type, payload }
            if (payload?.type === "full") {
              const v = validate(payload.payload);
              if (v.ok) commit(v.value, etag);
            } else if (payload?.type === "partial") {
              applyPartial(payload.payload as Partial<SystemStatus>);
            }
          }
        } catch {
          // игнорируем невалидные сообщения
        }
      };
      ws.onerror = () => {
        // ошибки WS не должны ломать polling
      };
      ws.onclose = () => {
        wsRef.current = null;
      };

      return () => {
        try {
          ws.close();
        } catch {
          // ignore
        }
        wsRef.current = null;
      };
    } catch {
      // Если конструктор WebSocket бросил — игнорируем
      return;
    }
  }, [applyPartial, commit, doRequest, etag, isActive, validate, websocket]);

  /**
   * Основной цикл запуска/остановки и расписания
   */
  useEffect(() => {
    if (!isActive) return;

    let cancelled = false;

    (async () => {
      await initialKick();
      if (!cancelled) schedule();
    })();

    return () => {
      cancelled = true;
      if (timerRef.current) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      abortRef.current?.abort();
    };
  }, [initialKick, isActive, schedule]);

  /**
   * Автозапуск при монтировании
   */
  useEffect(() => {
    setIsActive(autoStart);
    backoffRef.current = intervalMs;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // однократно

  /**
   * Изменение базового интервала — перезапускаем расписание
   */
  useEffect(() => {
    if (!isActive) return;
    backoffRef.current = intervalMs;
    // Перепланировать
    if (timerRef.current) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    schedule();
  }, [intervalMs, isActive, schedule]);

  const api: UseSystemStatusApi = useMemo(
    () => ({
      data,
      error,
      loading,
      stale,
      lastUpdatedAt,
      isOnline,
      isActive,
      etag,
      refetch,
      start,
      stop,
      setIntervalMs,
      subscribe,
    }),
    [
      data,
      error,
      loading,
      stale,
      lastUpdatedAt,
      isOnline,
      isActive,
      etag,
      refetch,
      start,
      stop,
      setIntervalMs,
      subscribe,
    ]
  );

  return api;
}

/**
 * Безопасное чтение тела как текст для сообщений об ошибке
 */
async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}
