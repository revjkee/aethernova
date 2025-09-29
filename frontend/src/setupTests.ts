/*
 * frontend/src/setupTests.ts
 * Универсальный тестовый сетап для Jest/Vitest c промышленными полифилами и безопасными хуками.
 */

// -----------------------------
// Импорты глобальных функций тестирования
// -----------------------------
import { 
  beforeAll as vitestBeforeAll, 
  afterAll as vitestAfterAll, 
  afterEach as vitestAfterEach, 
  expect as vitestExpect 
} from 'vitest';

// Расширяем глобальные объекты для совместимости с Jest
declare global {
  var beforeAll: typeof vitestBeforeAll;
  var afterAll: typeof vitestAfterAll; 
  var afterEach: typeof vitestAfterEach;
  var expect: typeof vitestExpect;
}

globalThis.beforeAll = vitestBeforeAll;
globalThis.afterAll = vitestAfterAll;
globalThis.afterEach = vitestAfterEach;
globalThis.expect = vitestExpect;

// -----------------------------
// Базовые настройки окружения
// -----------------------------
process.env.TZ = process.env.TZ || "UTC"; // стабильные снапшоты по времени

// Jest: увеличить таймаут по умолчанию (при наличии)
// Vitest: не влияет
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const maybeJest: any = (globalThis as any).jest;
if (maybeJest && typeof maybeJest.setTimeout === "function") {
  maybeJest.setTimeout(30000);
}

// -----------------------------
// jest-dom: расширение матчеров expect
// Рекомендовано Testing Library. Для Vitest допустим основной импорт. 
// https://github.com/testing-library/jest-dom
// -----------------------------
import "@testing-library/jest-dom";

// -----------------------------
// React Testing Library cleanup
// Вызываем после каждого теста (если раннер сам не делает автоклин‑ап)
// https://testing-library.com/docs/react-testing-library/api/#cleanup
// -----------------------------
import { cleanup } from "@testing-library/react";
afterEach(() => cleanup());

// -----------------------------
// Безопасный перехват console.*
// -----------------------------
const ALLOW_CONSOLE = String(process.env.ALLOW_CONSOLE || "").toLowerCase() === "true";
const origError = console.error;
const origWarn = console.warn;
const ALLOWED_PATTERNS: RegExp[] = [
  /ReactDOM\.render is no longer supported/i,
  /Warning: An update to .* inside a test was not wrapped in act\(\)/i,
];

beforeAll(() => {
  if (ALLOW_CONSOLE) return;
  console.error = ((...args: unknown[]) => {
    const msg = String(args[0] ?? "");
    const allowed = ALLOWED_PATTERNS.some((re) => re.test(msg));
    if (!allowed) {
      // Поведение по умолчанию — падать, чтобы не терять важные ошибки
      throw new Error(`console.error: ${msg}`);
    }
    return origError.apply(console, args as never);
  }) as typeof console.error;

  console.warn = ((...args: unknown[]) => {
    const msg = String(args[0] ?? "");
    const allowed = ALLOWED_PATTERNS.some((re) => re.test(msg));
    if (!allowed) return; // подавляем шумные ворнинги
    return origWarn.apply(console, args as never);
  }) as typeof console.warn;
});

afterAll(() => {
  console.error = origError;
  console.warn = origWarn;
});

// -----------------------------
// Полифилы для JSDOM/Node
// -----------------------------
import { TextEncoder, TextDecoder } from "node:util";
// Присваиваем глобально, если отсутствует
if (!globalThis.TextEncoder) globalThis.TextEncoder = TextEncoder as unknown as typeof globalThis.TextEncoder;
// Присваиваем глобально, если отсутствует
if (!globalThis.TextDecoder) globalThis.TextDecoder = TextDecoder as unknown as typeof globalThis.TextDecoder;

// Web Crypto API (Node >= 16.17/18 обеспечивает через globalThis.crypto или node:crypto.webcrypto)
// https://nodejs.org/api/webcrypto.html
try {
  // Типы у глобали могут отсутствовать в конфиге
  if (!globalThis.crypto) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { webcrypto } = require("node:crypto");
    // Назначаем как есть
    (globalThis as any).crypto = webcrypto;
  }
} catch {
  // no-op
}

// fetch (Node >=18 содержит глобально; иначе — полифил)
if (typeof (globalThis as any).fetch === "undefined") {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    require("cross-fetch/polyfill");
  } catch {
    // no-op: тесты, не зависящие от fetch, продолжат работать
  }
}

// matchMedia — часто требуется компонентам, зависящим от media queries
// MDN: https://developer.mozilla.org/en-US/docs/Web/API/Window/matchMedia
if (typeof (globalThis as any).matchMedia === "undefined") {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).matchMedia = (query: string) => {
    const listeners = new Set<(e: MediaQueryListEvent) => void>();
    const mql: MediaQueryList = {
      matches: false,
      media: query,
      onchange: null,
      addEventListener: (_: "change", cb: (e: MediaQueryListEvent) => void) => void listeners.add(cb),
      removeEventListener: (_: "change", cb: (e: MediaQueryListEvent) => void) => void listeners.delete(cb),
      addListener: (cb: (e: MediaQueryListEvent) => void) => void listeners.add(cb), // legacy
      removeListener: (cb: (e: MediaQueryListEvent) => void) => void listeners.delete(cb), // legacy
      dispatchEvent: (ev: Event) => {
        listeners.forEach((cb) => cb(ev as MediaQueryListEvent));
        return true;
      },
    } as unknown as MediaQueryList;
    return mql;
  };
}

// ResizeObserver — часто отсутствует в JSDOM
// Спецификация: https://developer.mozilla.org/en-US/docs/Web/API/ResizeObserver
if (typeof (globalThis as any).ResizeObserver === "undefined") {
  class RO {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    observe(_target: Element, _options?: ResizeObserverOptions) {}
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    unobserve(_target: Element) {}
    disconnect() {}
  }
  (globalThis as any).ResizeObserver = RO;
}

// IntersectionObserver — лёгкий полифил
// Спецификация: https://developer.mozilla.org/en-US/docs/Web/API/IntersectionObserver
if (typeof (globalThis as any).IntersectionObserver === "undefined") {
  class IO {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(_cb: IntersectionObserverCallback, _opts?: IntersectionObserverInit) {}
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    observe(_el: Element) {}
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    unobserve(_el: Element) {}
    disconnect() {}
    takeRecords(): IntersectionObserverEntry[] { return []; }
    root: Element | Document | null = null;
    rootMargin = "0px";
    thresholds: ReadonlyArray<number> = [0];
  }
  (globalThis as any).IntersectionObserver = IO;
}

// scrollTo/rAF — заглушки
if (typeof (globalThis as any).scrollTo === "undefined") {
  (globalThis as any).scrollTo = () => {};
}
if (typeof (globalThis as any).requestAnimationFrame === "undefined") {
  (globalThis as any).requestAnimationFrame = (cb: FrameRequestCallback) => setTimeout(() => cb(Date.now()), 16) as unknown as number;
}
if (typeof (globalThis as any).cancelAnimationFrame === "undefined") {
  (globalThis as any).cancelAnimationFrame = (id: number) => clearTimeout(id as unknown as NodeJS.Timeout);
}

// -----------------------------
// Опционально: jest-axe (если установлен) — a11y‑матчер toHaveNoViolations
// -----------------------------
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const axe = require("jest-axe");
  if (axe && axe.toHaveNoViolations && typeof expect !== "undefined") {
    // Типы jest-axe могут не быть объявлены
    (expect as any).extend(axe.toHaveNoViolations);
  }
} catch {
  // пропускаем, если зависимости нет
}

// -----------------------------
// MSW (Node) — поднимаем сервер, если библиотека и хэндлеры существуют
// setupServer описан в оф. доке MSW для Node
// https://mswjs.io/docs/api/setup-server/
// -----------------------------
function startMswIfAvailable() {
  // Минимизируем риски в ESM/Vitest: используем динамический require, если доступен
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const hasRequire = typeof (globalThis as any).require === "function" || typeof require === "function";
  if (!hasRequire) return;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { setupServer } = require("msw/node");
    // Популярные пути к handlers; если не найдены — пропускаем
    const candidates = [
      "./test/mocks/handlers",
      "./tests/mocks/handlers",
      "./__tests__/mocks/handlers",
      "./src/test/mocks/handlers",
    ];
    let handlersMod: { handlers?: any[] } | null = null;
    for (const p of candidates) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        handlersMod = require(p);
        break;
      } catch {
        // попробуем следующий путь
      }
    }
    const handlers = (handlersMod && (handlersMod.handlers || (handlersMod as any).default)) || [];
    const server = setupServer(...handlers);

    beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
    afterEach(() => server.resetHandlers());
    afterAll(() => server.close());
  } catch {
    // MSW не установлен — молча пропускаем
  }
}

startMswIfAvailable();

// Экспорт пуcтой заглушки для корректного ESM
export {};
