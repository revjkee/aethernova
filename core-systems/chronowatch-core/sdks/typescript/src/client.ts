// chronowatch-core/sdks/typescript/src/client.ts
// SPDX-License-Identifier: Apache-2.0
//
// Промышленный TypeScript SDK для Chronowatch Core (таймеры).
// Совместим с браузером и Node >= 18 (встроенный fetch/ReadableStream).
//
// Ключевые возможности:
// - Аутентификация: Bearer / API-Key (кастомное имя заголовка)
// - Корреляция: X-Request-ID (генерация) + optional traceparent
// - Таймауты: AbortController с auto-cancel
// - Ретраи: экспоненциальный backoff с джиттером, учёт Retry-After, маска статусов
// - Идемпотентность: Idempotency-Key для Create
// - Конкурентность: If-Match (ETag) для Update
// - Пагинация: асинхронный итератор listTimersIterator()
// - SSE: подписка на события через парсер text/event-stream без внешних зависимостей
// - Типизированные ошибки: ApiError со статусом/телом/заголовками/Request-ID
//
// Замечание: маршруты соответствуют HTTP-биндингам gRPC-Gateway контракта timer.proto.

//////////////////////////////
// Вспомогательные типы
//////////////////////////////

export type FetchLike = (
  input: RequestInfo | URL,
  init?: RequestInit
) => Promise<Response>;

export interface RetryPolicy {
  retries: number;            // максимум попыток (без первичного запроса)
  minDelayMs: number;         // старт задержки
  maxDelayMs: number;         // потолок задержки
  backoffMultiplier: number;  // мультипликатор роста
  jitter: boolean;            // случайный джиттер
  retryOnStatuses: number[];  // статусы, на которые ретраим
  respectRetryAfter: boolean; // учитывать Retry-After
}

export type AuthConfig =
  | { type: "bearer"; token: string }
  | { type: "apiKey"; value: string; headerName?: string }
  | { type: "none" };

export interface ClientOptions {
  baseUrl: string;                  // напр. "https://api.chronowatch.local"
  auth?: AuthConfig;
  defaultHeaders?: Record<string, string>;
  timeoutMs?: number;               // общий таймаут запроса
  retry?: Partial<RetryPolicy>;
  fetch?: FetchLike;                // внедряемый fetch (по умолчанию globalThis.fetch)
  userAgent?: string;               // добавляется как User-Agent (в Node) / X-User-Agent (в браузере)
  sdkName?: string;                 // для X-SDK-Name
  sdkVersion?: string;              // для X-SDK-Version
  traceparent?: string;             // если хотим пробрасывать трассировку
}

//////////////////////////////
// Типы домена (синхронизированы с timer.proto)
//////////////////////////////

export type TimerState =
  | "TIMER_STATE_UNSPECIFIED"
  | "TIMER_STATE_NEW"
  | "TIMER_STATE_SCHEDULED"
  | "TIMER_STATE_RUNNING"
  | "TIMER_STATE_PAUSED"
  | "TIMER_STATE_COMPLETED"
  | "TIMER_STATE_CANCELLED"
  | "TIMER_STATE_FAILED";

export
