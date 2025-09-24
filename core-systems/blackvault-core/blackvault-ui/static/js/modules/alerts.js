/**
 * alerts.js
 * ====================================================================
 * Модуль отображения и обработки алертов TeslaAI BlackVault UI
 * Промышленный уровень: многоуровневая система алертов,
 * приоритеты, категория, фильтрация, уведомления,
 * управление состояниями и интеграция с логгером.
 * ====================================================================
 */

import Logger from '../utils/logger.js';

class AlertsModule {
  constructor() {
    this.logger = new Logger('AlertsModule');

    // Хранилище алертов: Map<alertId, alertObject>
    this.alerts = new Map();

    // Подписчики на события алертов: Set<callback>
    this.subscribers = new Set();

    // Максимальное количество алертов в UI для отображения
    this.MAX_ALERTS_DISPLAYED = 50;
  }

  /**
   * Создать и добавить новый алерт
   * @param {Object} alert - структура алерта:
   * {
   *    id: string,        // уникальный ID алерта
   *    type: string,      // тип (error, warning, info, success)
   *    message: string,   // текст сообщения
   *    timestamp: number, // время создания (ms)
   *    priority: number,  // приоритет, 0 (низкий) - 10 (высокий)
   *    category: string,  // категория (system, agi, user, network и т.п.)
   *    meta: Object       // дополнительные данные
   * }
   */
  addAlert(alert) {
    if (!alert || !alert.id || !alert.type || !alert.message) {
      this.logger.error('Invalid alert object passed:', alert);
      return;
    }
    if (this.alerts.size >= this.MAX_ALERTS_DISPLAYED) {
      this.removeLowestPriorityAlert();
    }
    this.alerts.set(alert.id, alert);
    this.logger.info(`Alert added: [${alert.type}] ${alert.message}`);
    this.notifySubscribers('add', alert);
  }

  /**
   * Удалить алерт по ID
   * @param {string} alertId
   */
  removeAlert(alertId) {
    if (this.alerts.has(alertId)) {
      const alert = this.alerts.get(alertId);
      this.alerts.delete(alertId);
      this.logger.info(`Alert removed: [${alert.type}] ${alert.message}`);
      this.notifySubscribers('remove', alert);
    }
  }

  /**
   * Очистить все алерты
   */
  clearAlerts() {
    this.alerts.clear();
    this.logger.info('All alerts cleared');
    this.notifySubscribers('clear', null);
  }

  /**
   * Получить массив всех алертов, отсортированных по приоритету и времени
   */
  getSortedAlerts() {
    return Array.from(this.alerts.values()).sort((a, b) => {
      if (b.priority !== a.priority) {
        return b.priority - a.priority; // по убыванию приоритета
      }
      return a.timestamp - b.timestamp; // по возрастанию времени
    });
  }

  /**
   * Удаляет алерт с самым низким приоритетом для освобождения места
   */
  removeLowestPriorityAlert() {
    let lowestPriorityAlert = null;
    for (const alert of this.alerts.values()) {
      if (
        !lowestPriorityAlert ||
        alert.priority < lowestPriorityAlert.priority ||
        (alert.priority === lowestPriorityAlert.priority && alert.timestamp < lowestPriorityAlert.timestamp)
      ) {
        lowestPriorityAlert = alert;
      }
    }
    if (lowestPriorityAlert) {
      this.removeAlert(lowestPriorityAlert.id);
    }
  }

  /**
   * Подписка на изменения алертов
   * @param {Function} callback - функция с аргументами (action, alert)
   * где action: 'add' | 'remove' | 'clear'
   */
  subscribe(callback) {
    if (typeof callback === 'function') {
      this.subscribers.add(callback);
      this.logger.debug('Subscriber added to AlertsModule');
      return () => {
        this.subscribers.delete(callback);
        this.logger.debug('Subscriber removed from AlertsModule');
      };
    }
    this.logger.error('Invalid callback passed to AlertsModule.subscribe');
    return () => {};
  }

  /**
   * Оповестить всех подписчиков о событии
   * @param {string} action
   * @param {Object|null} alert
   */
  notifySubscribers(action, alert) {
    this.subscribers.forEach((cb) => {
      try {
        cb(action, alert);
      } catch (error) {
        this.logger.error('Error in alert subscriber callback:', error);
      }
    });
  }
}

const alertsModuleInstance = new AlertsModule();

export default alertsModuleInstance;
