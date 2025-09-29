// frontend/src/lib/utils.ts
/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Универсальные, индустриальные утилиты без внешних зависимостей.
 * Подходят для браузера и SSR (Node). Аккуратно работают с AbortController.
 *
 * ВНИМАНИЕ: файл не импортирует сторонние библиотеки.
 */

/* ────────────────────────────────────────────────────────────────────────── */
/*                                        Types                              */
/* ────────────────────────────────────────────────────────────────────────── */

export type Nullable<T> = T | null | undefined;
export type NonEmptyArray<T> = [T, ...T[]];

export type Result<T, E = Error> =
  | { ok: true;  value: T }
  | { ok: false; error: E };

export const Ok = <T, E = Error>(value: T): Result<T, E> => ({ ok: true, value });
export const Err = <E>(error: E): Result<never, E> => ({ ok: false, error });

export const isOk = <T, E>(r: Result<T, E>): r is { ok: true; value: T } => r.ok;
export const isErr = <T, E>(r: Result<T, E>): r is { ok: false; error: E } => !r.ok;

export function unwrap<T, E extends Error = Error>(r: Result<T, E>): T {
  if (r.ok) return r.value;
  throw r.error;
}

export function mapOk<T, U, E>(r: Result<T, E>, fn: (v: T) => U): Result<U, E> {
  return r.ok ? Ok(fn(r.value)) : { ok: false, error: r.error };
}

export function mapErr<T, E, F>(r: Result<T, E>, fn: (e: E) => F): Result<T, F> {
  return r.ok ? r : Err(fn(r.error));
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                 Environment                               */
/* ────────────────────────────────────────────────────────────────────────── */

export const isBrowser = typeof window !== "undefined" && typeof document !== "undefined";
export const isNode = typeof process !== "undefined" && !!(process.versions as any)?.node;
export const isSSR = !isBrowser;

/* ────────────────────────────────────────────────────────────────────────── */
/*                                  Classnames                               */
/* ────────────────────────────────────────────────────────────────────────── */

/**
 * Минималистичный classnames без зависимостей.
 * Поддерживает: строку, массив, объект { cls: boolean }.
 * Дубликаты удаляются, пробелы нормализуются.
 */
export type ClassValue =
  | string
  | number
  | null
  | undefined
  | Record<string, boolean | null | undefined>
  | ClassValue[];

export function cn(...inputs: ClassValue[]): string {
  const out = new Set<string>();

  const push = (v: string) => {
    v.split(/\s+/).forEach((t) => {
      const trimmed = t.trim();
      if (trimmed) out.add(trimmed);
    });
  };

  const walk = (val: ClassValue): void => {
    if (!val && val !== 0) return;
    if (Array.isArray(val)) {
      val.forEach(walk);
      return;
    }
    if (typeof val === "object") {
      for (const [k, v] of Object.entries(val)) {
        if (v) push(k);
      }
      return;
    }
    push(String(val));
  };

  inputs.forEach(walk);
  return Array.from(out).join(" ");
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                 Assertions                                 */
/* ────────────────────────────────────────────────────────────────────────── */

export function invariant(cond: any, msg = "Invariant violation"): asserts cond {
  if (!cond) throw new Error(msg);
}

export function assertNever(x: never, msg = "Unexpected value:"): never {
  throw new Error(`${msg} ${String(x)}`);
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                               Random / UUID                                */
/* ────────────────────────────────────────────────────────────────────────── */

export function uuid(): string {
  // Используем crypto.randomUUID при наличии, иначе полифилл
  // В браузере/Node 19+ доступен глобальный crypto.randomUUID
  const g: any = globalThis as any;
  if (g?.crypto?.randomUUID) return g.crypto.randomUUID();

  // Полифилл RFC4122 v4
  const getRandomValues =
    g?.crypto?.getRandomValues?.bind(g.crypto) ??
    ((arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
      return arr;
    });

  const bytes = new Uint8Array(16);
  getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10

  const toHex = (n: number) => n.toString(16).padStart(2, "0");
  return (
    toHex(bytes[0]) + toHex(bytes[1]) + toHex(bytes[2]) + toHex(bytes[3]) + "-" +
    toHex(bytes[4]) + toHex(bytes[5]) + "-" +
    toHex(bytes[6]) + toHex(bytes[7]) + "-" +
    toHex(bytes[8]) + toHex(bytes[9]) + "-" +
    toHex(bytes[10]) + toHex(bytes[11]) + toHex(bytes[12]) + toHex(bytes[13]) + toHex(bytes[14]) + toHex(bytes[15])
  );
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                              Time / Scheduling                             */
/* ────────────────────────────────────────────────────────────────────────── */

export const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException("Aborted", "AbortError"));
    const id = setTimeout(resolve, Math.max(0, ms));
    const onAbort = () => {
      clearTimeout(id);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });

export async function withTimeout<T>(
  input: Promise<T> | (() => Promise<T>),
  ms: number,
  message = "Operation timed out",
  signal?: AbortSignal
): Promise<T> {
  const p = typeof input === "function" ? input() : input;
  let timer: any;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), Math.max(0, ms));
  });

  if (signal) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const abortPromise = new Promise<never>((_, reject) =>
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true })
    );
    try {
      const res = await Promise.race([p, timeoutPromise, abortPromise]);
      return res as T;
    } finally {
      clearTimeout(timer);
    }
  }

  try {
    const res = await Promise.race([p, timeoutPromise]);
    return res as T;
  } finally {
    clearTimeout(timer);
  }
}

export type RetryOptions = {
  retries?: number;           // попытки, по умолчанию 3
  delay?: number;             // базовая задержка, мс (по умолчанию 300)
  factor?: number;            // множитель backoff (по умолчанию 2)
  jitter?: boolean;           // случайный джиттер
  signal?: AbortSignal;       // для отмены
  onRetry?: (err: unknown, attempt: number) => void | Promise<void>;
};

export async function retryAsync<T>(fn: () => Promise<T>, opt: RetryOptions = {}): Promise<T> {
  const {
    retries = 3,
    delay = 300,
    factor = 2,
    jitter = true,
    signal,
    onRetry,
  } = opt;

  let attempt = 0;
  let nextDelay = delay;

  for (;;) {
    if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

    try {
      return await fn();
    } catch (err) {
      if (attempt >= retries) throw err;
      attempt += 1;
      await onRetry?.(err, attempt);
      let wait = nextDelay;
      if (jitter) {
        const r = Math.random() + 0.5; // 0.5..1.5
        wait = Math.floor(wait * r);
      }
      await sleep(wait, signal);
      nextDelay = Math.floor(nextDelay * factor);
    }
  }
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                               Debounce/Throttle                            */
/* ────────────────────────────────────────────────────────────────────────── */

export function debounce<T extends (...args: any[]) => any>(fn: T, ms = 300) {
  let id: any;
  let lastReject: ((reason?: any) => void) | null = null;

  const wrapped = (...args: Parameters<T>): Promise<ReturnType<T>> =>
    new Promise((resolve, reject) => {
      if (id) clearTimeout(id);
      if (lastReject) lastReject(new Error("Debounced"));
      lastReject = reject;
      id = setTimeout(async () => {
        try {
          const res = await fn(...args);
          resolve(res);
        } catch (e) {
          reject(e);
        } finally {
          lastReject = null;
        }
      }, Math.max(0, ms));
    });

  (wrapped as any).cancel = () => {
    if (id) clearTimeout(id);
    if (lastReject) lastReject(new Error("Debounced"));
    id = null;
    lastReject = null;
  };

  return wrapped as typeof wrapped & { cancel: () => void };
}

export function throttle<T extends (...args: any[]) => any>(fn: T, ms = 300) {
  let last = 0;
  let timer: any;
  let lastArgs: any[] | null = null;

  const invoke = () => {
    last = Date.now();
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    fn(...(lastArgs as any[]));
    lastArgs = null;
  };

  const wrapped = (...args: Parameters<T>) => {
    const now = Date.now();
    const remaining = ms - (now - last);
    lastArgs = args;

    if (remaining <= 0) {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      invoke();
    } else if (!timer) {
      timer = setTimeout(() => {
        timer = null;
        invoke();
      }, remaining);
    }
  };

  (wrapped as any).cancel = () => {
    if (timer) clearTimeout(timer);
    timer = null;
    lastArgs = null;
  };

  return wrapped as typeof wrapped & { cancel: () => void };
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                    Math                                    */
/* ────────────────────────────────────────────────────────────────────────── */

export const clamp = (n: number, min: number, max: number) => Math.min(Math.max(n, min), max);

export function range(start: number, end?: number, step = 1): number[] {
  const s = end === undefined ? 0 : start;
  const e = end === undefined ? start : end;
  const st = step || 1;
  const out: number[] = [];
  for (let i = s; st > 0 ? i < e : i > e; i += st) out.push(i);
  return out;
}

export function sum(arr: number[]): number {
  return arr.reduce((a, b) => a + b, 0);
}

export function average(arr: number[]): number {
  return arr.length ? sum(arr) / arr.length : 0;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                             Formatters / Parsers                           */
/* ────────────────────────────────────────────────────────────────────────── */

export function formatBytes(bytes: number, fractionDigits = 1): string {
  if (!Number.isFinite(bytes)) return "NaN";
  const thresh = 1024;
  if (Math.abs(bytes) < thresh) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let u = -1;
  let b = bytes;
  do {
    b /= thresh;
    ++u;
  } while (Math.abs(b) >= thresh && u < units.length - 1);
  return `${b.toFixed(fractionDigits)} ${units[u]}`;
}

export function formatNumber(n: number, locale?: string, options?: Intl.NumberFormatOptions): string {
  try {
    return new Intl.NumberFormat(locale || undefined, options).format(n);
  } catch {
    return String(n);
  }
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "0ms";
  const s = Math.floor(ms / 1000);
  const hh = Math.floor(s / 3600);
  const mm = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  const msLeft = ms % 1000;
  if (hh) return `${hh}h ${mm}m ${ss}s`;
  if (mm) return `${mm}m ${ss}s`;
  if (s) return `${s}s`;
  return `${msLeft}ms`;
}

export function parseJSONSafe<T = unknown>(text: string): Result<T, Error> {
  try {
    return Ok(JSON.parse(text) as T);
  } catch (e: any) {
    return Err(e instanceof Error ? e : new Error("Invalid JSON"));
  }
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                Collections                                 */
/* ────────────────────────────────────────────────────────────────────────── */

export const isDefined = <T>(v: T | null | undefined): v is T => v !== null && v !== undefined;
export const notEmpty = <T>(v: Nullable<T>): v is T => v !== null && v !== undefined;

export function uniqueBy<T, K>(arr: T[], by: (x: T) => K): T[] {
  const seen = new Set<K>();
  const res: T[] = [];
  for (const x of arr) {
    const k = by(x);
    if (!seen.has(k)) {
      seen.add(k);
      res.push(x);
    }
  }
  return res;
}

export function groupBy<T, K>(arr: T[], by: (x: T) => K): Map<K, T[]> {
  const map = new Map<K, T[]>();
  for (const x of arr) {
    const k = by(x);
    const bucket = map.get(k);
    if (bucket) bucket.push(x);
    else map.set(k, [x]);
  }
  return map;
}

export function pick<T extends object, K extends keyof T>(obj: T, keys: K[]): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const k of keys) {
    if (k in obj) out[k] = obj[k];
  }
  return out;
}

export function omit<T extends object, K extends keyof T>(obj: T, keys: K[]): Omit<T, K> {
  const out = { ...obj } as Omit<T, K>;
  for (const k of keys) {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete (out as any)[k];
  }
  return out;
}

export function deepMerge<T extends Record<string, any>, U extends Record<string, any>>(a: T, b: U): T & U {
  const res: any = { ...a };
  for (const [k, v] of Object.entries(b)) {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      res[k] = deepMerge(res[k] ?? {}, v);
    } else {
      res[k] = v;
    }
  }
  return res;
}

export function deepFreeze<T>(obj: T): T {
  if (obj && typeof obj === "object") {
    Object.freeze(obj);
    for (const key of Object.keys(obj as any)) {
      // Recursive freeze for nested objects
      deepFreeze((obj as any)[key]);
    }
  }
  return obj;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                Abort / Signals                             */
/* ────────────────────────────────────────────────────────────────────────── */

export function linkSignals(...signals: (AbortSignal | undefined)[]): AbortSignal | undefined {
  const real = signals.filter(Boolean) as AbortSignal[];
  if (!real.length) return undefined;
  const ctl = new AbortController();
  const onAbort = () => ctl.abort();
  real.forEach((s) => s.addEventListener("abort", onAbort, { once: true }));
  // Если уже абортнут один из сигналов — аборт сразу
  if (real.some((s) => s.aborted)) ctl.abort();
  return ctl.signal;
}

export function makeAbortable<T extends (...args: any[]) => Promise<any>>(
  fn: T
): (signal?: AbortSignal, ...args: Parameters<T>) => Promise<Awaited<ReturnType<T>>> {
  return async (signal?: AbortSignal, ...args: Parameters<T>) => {
    if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
    const p = fn(...args);
    if (!signal) return p;
    const abortPromise = new Promise<never>((_, reject) =>
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true })
    );
    return Promise.race([p, abortPromise]) as any;
  };
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                Storage Safe                                */
/* ────────────────────────────────────────────────────────────────────────── */

export type StorageLike = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  clear(): void;
};

const memoryStorage = (): StorageLike => {
  const map = new Map<string, string>();
  return {
    getItem: (k) => (map.has(k) ? (map.get(k) as string) : null),
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
    clear: () => void map.clear(),
  };
};

export function getSafeLocalStorage(): StorageLike {
  if (!isBrowser) return memoryStorage();
  try {
    const testKey = "__ls_test__";
    window.localStorage.setItem(testKey, "1");
    window.localStorage.removeItem(testKey);
    return window.localStorage;
  } catch {
    return memoryStorage();
  }
}

export function createNamespaceStorage(namespace: string, storage: StorageLike = getSafeLocalStorage()) {
  const prefix = `${namespace}::`;

  const k = (key: string) => `${prefix}${key}`;

  function set<T>(key: string, value: T): void {
    try {
      storage.setItem(k(key), JSON.stringify(value));
    } catch {
      // silent fallback
    }
  }

  function get<T>(key: string, fallback?: T): T | undefined {
    try {
      const raw = storage.getItem(k(key));
      if (raw === null) return fallback;
      return JSON.parse(raw) as T;
    } catch {
      return fallback;
    }
  }

  function remove(key: string): void {
    try {
      storage.removeItem(k(key));
    } catch {
      // silent
    }
  }

  function clearAll(): void {
    try {
      // Очистим только наш namespace
      if (!isBrowser) {
        storage.clear();
        return;
      }
      const keys: string[] = [];
      for (let i = 0; i < window.localStorage.length; i++) {
        const kk = window.localStorage.key(i);
        if (kk && kk.startsWith(prefix)) keys.push(kk);
      }
      keys.forEach((kk) => window.localStorage.removeItem(kk));
    } catch {
      // silent
    }
  }

  return { set, get, remove, clearAll };
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                   EventBus                                 */
/* ────────────────────────────────────────────────────────────────────────── */

type Handler<T> = (payload: T) => void | Promise<void>;

export function createEventBus<Events extends Record<string, any>>() {
  const map = new Map<keyof Events, Set<Handler<any>>>();

  function on<K extends keyof Events>(event: K, handler: Handler<Events[K]>): () => void {
    const set = map.get(event) ?? new Set();
    set.add(handler);
    map.set(event, set);
    return () => off(event, handler);
  }

  function off<K extends keyof Events>(event: K, handler: Handler<Events[K]>) {
    const set = map.get(event);
    if (!set) return;
    set.delete(handler as Handler<any>);
    if (!set.size) map.delete(event);
  }

  async function emit<K extends keyof Events>(event: K, payload: Events[K]) {
    const set = map.get(event);
    if (!set) return;
    for (const h of Array.from(set)) {
      await h(payload);
    }
  }

  return { on, off, emit };
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                 Networking                                 */
/* ────────────────────────────────────────────────────────────────────────── */

export async function fetchJSON<T = unknown>(
  input: RequestInfo | URL,
  init?: RequestInit & { timeoutMs?: number; signal?: AbortSignal }
): Promise<T> {
  const { timeoutMs, signal, ...rest } = init ?? {};
  const ctl = new AbortController();
  const linked = linkSignals(signal, ctl.signal);

  const timer = timeoutMs ? setTimeout(() => ctl.abort(), Math.max(0, timeoutMs)) : null;

  try {
    const res = await fetch(input, { ...rest, signal: linked });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as T;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                   Hashing                                  */
/* ────────────────────────────────────────────────────────────────────────── */

/**
 * Быстрый стабильный hash строки (не криптостойкий).
 * Подходит для ключей кеша, memo и т.п.
 */
export function hashString(s: string): number {
  let h = 2166136261 >>> 0; // FNV-1a 32-bit
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                  Memoize                                   */
/* ────────────────────────────────────────────────────────────────────────── */

export function memoize<A extends any[], R>(fn: (...args: A) => R) {
  const cache = new Map<string, R>();
  return (...args: A): R => {
    const key = String(args.length) + ":" + args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join("|");
    const hit = cache.get(key);
    if (hit !== undefined) return hit;
    const val = fn(...args);
    cache.set(key, val);
    return val;
  };
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                              Misc small helpers                            */
/* ────────────────────────────────────────────────────────────────────────── */

export const noop = () => {};
export const identity = <T>(x: T) => x;

export function safeAt<T>(arr: T[], index: number): T | undefined {
  return index < 0 || index >= arr.length ? undefined : arr[index];
}

export function capitalize(s: string): string {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function truncate(s: string, max = 120, tail = "…"): string {
  if (s.length <= max) return s;
  return s.slice(0, Math.max(0, max - tail.length)) + tail;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*                                 Public API                                 */
/* ────────────────────────────────────────────────────────────────────────── */

export default {
  // types/helpers
  isBrowser,
  isNode,
  isSSR,
  cn,
  invariant,
  assertNever,
  uuid,
  sleep,
  withTimeout,
  retryAsync,
  debounce,
  throttle,
  clamp,
  range,
  sum,
  average,
  formatBytes,
  formatNumber,
  formatDuration,
  parseJSONSafe,
  isDefined,
  notEmpty,
  uniqueBy,
  groupBy,
  pick,
  omit,
  deepMerge,
  deepFreeze,
  linkSignals,
  makeAbortable,
  getSafeLocalStorage,
  createNamespaceStorage,
  createEventBus,
  fetchJSON,
  hashString,
  memoize,
  noop,
  identity,
  safeAt,
  capitalize,
  truncate,
  // result type utils
  Ok,
  Err,
  isOk,
  isErr,
  unwrap,
  mapOk,
  mapErr,
};
