/**
 * helpers.js
 * ===================================================================
 * Универсальные утилиты BlackVault (промышленная версия, консиллиум 20)
 * - Проверка типов, работы с объектами и массивами
 * - Безопасные операции с данными
 * - Форматирование дат/времени и чисел
 * - Генерация уникальных идентификаторов
 * - Расширенная работа с промисами, дебаунсы и throttle
 * - Логика для безопасности (sanitization, deepClone)
 * ===================================================================
 */

/* Типизация и проверки */
export function isObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val);
}

export function isArray(val) {
  return Array.isArray(val);
}

export function isFunction(val) {
  return typeof val === 'function';
}

export function isString(val) {
  return typeof val === 'string';
}

export function isNumber(val) {
  return typeof val === 'number' && !isNaN(val);
}

export function isPromise(val) {
  return isObject(val) && isFunction(val.then);
}

/* Безопасная работа с объектами */
export function get(obj, path, fallback) {
  if (!isObject(obj) && !isArray(obj)) return fallback;
  return path.split('.').reduce((acc, part) => (acc && acc[part] !== undefined ? acc[part] : fallback), obj);
}

export function deepClone(obj) {
  return structuredClone
    ? structuredClone(obj)
    : JSON.parse(JSON.stringify(obj));
}

/* Безопасная обработка строк */
export function sanitizeHTML(str) {
  if (!isString(str)) return '';
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return str.replace(/[&<>"']/g, m => map[m]);
}

/* Форматирование дат и времени */
export function formatDate(ts, locale = 'ru-RU') {
  try {
    return new Date(ts).toLocaleString(locale, {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  } catch {
    return '';
  }
}

export function formatNumber(num, locale = 'ru-RU', options = {}) {
  try {
    return new Intl.NumberFormat(locale, options).format(num);
  } catch {
    return num;
  }
}

/* Генерация уникальных идентификаторов */
export function uuid() {
  // RFC4122 v4 compliant
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

/* Асинхронные ивенты (debounce/throttle) */
export function debounce(fn, wait = 200) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn.apply(this, args), wait);
  };
}

export function throttle(fn, limit = 200) {
  let inThrottle;
  return (...args) => {
    if (!inThrottle) {
      fn.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

/* Работа с промисами — безопасное выполнение */
export async function safeAsync(fn, ...args) {
  try {
    return [await fn(...args), null];
  } catch (err) {
    return [null, err];
  }
}

/* Прочее */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

export function uniq(arr) {
  return [...new Set(arr)];
}

/* Глубокое сравнение объектов */
export function deepEqual(a, b) {
  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
  }
}
