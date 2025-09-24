/**
 * metrics.js
 * ====================================================================
 * Промышленный модуль сбора и отображения метрик в реальном времени.
 * Включает:
 *  - Подключение к источникам данных (WebSocket, HTTP-polling)
 *  - Агрегацию и фильтрацию метрик
 *  - Буферизацию и дебаунсинг обновлений
 *  - Подписки для компонентов UI
 *  - Интеграцию с логгером и системой алертов
 * ====================================================================
 */

import Logger from '../utils/logger.js';
import AlertsModule from './alerts.js';

class MetricsModule {
  constructor(config = {}) {
    this.logger = new Logger('MetricsModule');
    this.subscribers = new Set();
    this.buffer = [];
    this.batchSize = config.batchSize || 100;
    this.debounceTime = config.debounceTime || 200; // ms
    this.sourceUrl = config.sourceUrl || 'wss://metrics.server/stream';
    this.ws = null;
    this.debounceTimer = null;
  }

  /**
   * Инициализация соединения и обработка входящих метрик
   */
  init() {
    try {
      this.ws = new WebSocket(this.sourceUrl);
      this.ws.onmessage = (evt) => this.handleMessage(evt.data);
      this.ws.onerror = (err) => this.logger.error('WebSocket error', err);
      this.ws.onclose = () => this.logger.warn('WebSocket closed, retry in 5s') && setTimeout(() => this.init(), 5000);
      this.logger.info('WebSocket connection established');
    } catch (err) {
      this.logger.error('Failed to init WebSocket', err);
      AlertsModule.addAlert({
        id: `ws-error-${Date.now()}`,
        type: 'error',
        message: 'Не удалось подключиться к серверу метрик',
        timestamp: Date.now(),
        priority: 9,
        category: 'metrics',
        meta: { error: err.message }
      });
    }
  }

  /**
   * Обработка одного сообщения: парсинг и буферизация
   * @param {string} raw
   */
  handleMessage(raw) {
    let metric;
    try {
      metric = JSON.parse(raw);
    } catch {
      this.logger.warn('Invalid metric payload', raw);
      return;
    }
    if (!metric.name || typeof metric.value !== 'number') {
      this.logger.warn('Malformed metric', metric);
      return;
    }
    this.buffer.push(metric);
    if (this.buffer.length >= this.batchSize) {
      this.flushBuffer();
    } else {
      this.scheduleFlush();
    }
  }

  /**
   * Планирование дебаунсированного сброса буфера
   */
  scheduleFlush() {
    if (this.debounceTimer) return;
    this.debounceTimer = setTimeout(() => this.flushBuffer(), this.debounceTime);
  }

  /**
   * Передача накопленных метрик подписчикам и очистка буфера
   */
  flushBuffer() {
    clearTimeout(this.debounceTimer);
    this.debounceTimer = null;
    const batch = this.buffer.splice(0, this.buffer.length);
    this.logger.debug(`Flushing ${batch.length} metrics`);
    this.subscribers.forEach(cb => {
      try {
        cb(batch);
      } catch (err) {
        this.logger.error('Subscriber callback error', err);
      }
    });
  }

  /**
   * Подписка на поступление партий метрик
   * @param {Function} callback - (metricsBatch:Array)
   * @returns {Function} отписка
   */
  subscribe(callback) {
    if (typeof callback !== 'function') {
      this.logger.error('Invalid subscriber');
      return () => {};
    }
    this.subscribers.add(callback);
    this.logger.info('Subscriber added');
    return () => {
      this.subscribers.delete(callback);
      this.logger.info('Subscriber removed');
    };
  }

  /**
   * Остановить модуль и закрыть соединение
   */
  destroy() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    clearTimeout(this.debounceTimer);
    this.buffer = [];
    this.subscribers.clear();
    this.logger.info('MetricsModule destroyed');
  }
}

const metricsModule = new MetricsModule({
  batchSize: 200,
  debounceTime: 100,
  sourceUrl: 'wss://metrics.blackvault.ai/stream'
});

export default metricsModule;
