/**
 * telemetry.js
 * ====================================================================
 * Модуль обработки и визуализации телеметрии AGI в TeslaAI BlackVault UI
 * Промышленный уровень: высокая производительность, устойчивость,
 * декомпозиция по потокам данных, событиям и каналам.
 * Поддержка масштабируемой подписки, буферизации и агрегации.
 * ====================================================================
 */

import Logger from '../utils/logger.js';

class TelemetryModule {
  constructor() {
    this.logger = new Logger('TelemetryModule');

    // Буфер данных телеметрии для агрегации перед отправкой на визуализацию
    this.telemetryBuffer = [];

    // Максимальный размер буфера перед флашем
    this.MAX_BUFFER_SIZE = 100;

    // Подписчики на события телеметрии: { eventType: Set(callback) }
    this.subscribers = new Map();

    // Таймер для периодической отправки данных из буфера
    this.flushInterval = 200; // мс
    this.flushTimer = null;

    this.startFlushTimer();
  }

  /**
   * Подписка на телеметрию по типу события
   * @param {string} eventType - тип события телеметрии
   * @param {Function} callback - обработчик события
   * @returns {Function} функция отписки
   */
  subscribe(eventType, callback) {
    if (!this.subscribers.has(eventType)) {
      this.subscribers.set(eventType, new Set());
    }
    this.subscribers.get(eventType).add(callback);
    this.logger.info(`Subscribed to telemetry event: ${eventType}`);

    return () => {
      this.subscribers.get(eventType).delete(callback);
      this.logger.info(`Unsubscribed from telemetry event: ${eventType}`);
    };
  }

  /**
   * Приём новых данных телеметрии
   * @param {Object} data - структура телеметрии, например:
   * { eventType: string, payload: object, timestamp: number }
   */
  receiveTelemetry(data) {
    if (!data || typeof data !== 'object' || !data.eventType) {
      this.logger.error('Invalid telemetry data received:', data);
      return;
    }

    // Добавление в буфер
    this.telemetryBuffer.push(data);

    // Автоматический флаш, если буфер переполнен
    if (this.telemetryBuffer.length >= this.MAX_BUFFER_SIZE) {
      this.flushBuffer();
    }
  }

  /**
   * Очистка буфера и оповещение подписчиков соответствующих событий
   */
  flushBuffer() {
    if (this.telemetryBuffer.length === 0) return;

    const bufferCopy = this.telemetryBuffer.slice();
    this.telemetryBuffer = [];

    // Группируем данные по типу события
    const groupedByEvent = bufferCopy.reduce((acc, item) => {
      if (!acc[item.eventType]) acc[item.eventType] = [];
      acc[item.eventType].push(item);
      return acc;
    }, {});

    // Оповещаем подписчиков для каждого типа
    for (const [eventType, events] of Object.entries(groupedByEvent)) {
      const callbacks = this.subscribers.get(eventType);
      if (!callbacks || callbacks.size === 0) continue;

      callbacks.forEach((cb) => {
        try {
          cb(events);
        } catch (error) {
          this.logger.error(`Error in telemetry subscriber for event "${eventType}":`, error);
        }
      });
    }
  }

  /**
   * Запускает периодический таймер для флашинга буфера
   */
  startFlushTimer() {
    if (this.flushTimer) return;

    this.flushTimer = setInterval(() => {
      this.flushBuffer();
    }, this.flushInterval);

    this.logger.debug('Telemetry flush timer started');
  }

  /**
   * Останавливает таймер флашинга буфера
   */
  stopFlushTimer() {
    if (!this.flushTimer) return;

    clearInterval(this.flushTimer);
    this.flushTimer = null;

    this.logger.debug('Telemetry flush timer stopped');
  }
}

const telemetryModuleInstance = new TelemetryModule();

export default telemetryModuleInstance;
