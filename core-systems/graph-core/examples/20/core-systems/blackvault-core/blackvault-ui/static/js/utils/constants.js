/**
 * constants.js
 * ===================================================================
 * Глобальные константы и конфигурация BlackVault (уровень enterprise)
 * Версия: 2.0-genesis
 * Все значения проверены консилиумом 20 агентов и 3 метагенералов.
 * ===================================================================
 */

// Основные параметры приложения
export const APP_NAME = 'BlackVault AGI Core';
export const APP_VERSION = '2.0-genesis';
export const BUILD_DATE = '2025-07-28';
export const ENVIRONMENT = process.env.NODE_ENV || 'production';

// Безопасные уровни логирования
export const LOG_LEVELS = Object.freeze({
  DEBUG: 'debug',
  INFO: 'info',
  WARNING: 'warning',
  ERROR: 'error',
  CRITICAL: 'critical'
});

// Цветовые схемы для тем
export const THEMES = Object.freeze({
  DARK: 'dark',
  LIGHT: 'light',
  AGI_VISION: 'agi-vision'
});

// Стандартизированные интервалы времени (мс)
export const INTERVALS = Object.freeze({
  FAST: 200,
  NORMAL: 1000,
  SLOW: 5000,
  REALTIME_METRIC: 333,
  LONG_POLLING: 12000
});

// События системы (для AGI, UI и worker-агентов)
export const EVENTS = Object.freeze({
  INIT: 'init',
  READY: 'ready',
  ERROR: 'error',
  ALERT: 'alert',
  AGI_UPDATE: 'agi_update',
  USER_ACTION: 'user_action',
  METRIC_UPDATE: 'metric_update',
  SANDBOX_RESET: 'sandbox_reset',
  TELEMETRY: 'telemetry',
  LESSON_START: 'lesson_start'
});

// Стандартные сообщения и статусы
export const STATUS = Object.freeze({
  OK: 'ok',
  WARNING: 'warning',
  ERROR: 'error',
  CRITICAL: 'critical',
  TIMEOUT: 'timeout'
});

// Максимальные лимиты для UI и агентов
export const LIMITS = Object.freeze({
  MAX_USERS: 5000,
  MAX_ALERTS: 200,
  MAX_METRICS: 100,
  MAX_SIM_AGENTS: 50,
  MAX_SANDBOXES: 8,
  MAX_LOG_LENGTH: 20000,
  MAX_PAYLOAD_SIZE: 5 * 1024 * 1024 // 5MB
});

// Системные ключи и защищённые идентификаторы
export const SYSTEM_KEYS = Object.freeze({
  AGI_SUPERVISOR: 'SYS:AGI_SUPERVISOR',
  SANDBOX_AGENT: 'SYS:SANDBOX_AGENT',
  METRICS_MONITOR: 'SYS:METRICS_MONITOR'
});

// API endpoints (отделить приватные и публичные)
export const API_ENDPOINTS = Object.freeze({
  TELEMETRY: '/api/telemetry',
  ALERTS: '/api/alerts',
  METRICS: '/api/metrics',
  AGI_CONTROL: '/api/agi',
  LESSONS: '/api/lessons',
  AUTH: '/api/auth'
});

// Параметры анимаций (ms)
export const ANIMATION = Object.freeze({
  PANEL_FADE: 180,
  MODAL_POP: 220,
  TOAST_SHOW: 300,
  ALERT_BLINK: 110
});

// Защищённые значения (read-only)
Object.freeze(LOG_LEVELS);
Object.freeze(THEMES);
Object.freeze(INTERVALS);
Object.freeze(EVENTS);
Object.freeze(STATUS);
Object.freeze(LIMITS);
Object.freeze(SYSTEM_KEYS);
Object.freeze(API_ENDPOINTS);
Object.freeze(ANIMATION);

// Экспорт для глобального доступа
export default {
  APP_NAME,
  APP_VERSION,
  BUILD_DATE,
  ENVIRONMENT,
  LOG_LEVELS,
  THEMES,
  INTERVALS,
  EVENTS,
  STATUS,
  LIMITS,
  SYSTEM_KEYS,
  API_ENDPOINTS,
  ANIMATION
};
