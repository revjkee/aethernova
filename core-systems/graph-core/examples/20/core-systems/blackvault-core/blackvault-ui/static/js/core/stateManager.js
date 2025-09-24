/**
 * stateManager.js
 * ================================================================
 * Менеджер глобального состояния TeslaAI BlackVault UI
 * Обеспечивает централизованное хранение, синхронизацию и реактивное обновление состояния
 * Поддерживает подписки, батчи обновлений и устойчивость к ошибкам
 * ================================================================
 */

import Logger from '../utils/logger.js';

class StateManager {
  constructor() {
    // Хранилище состояния приложения (ключ-значение)
    this.state = new Map();

    // Карта подписчиков: ключ состояния -> Set функций-обработчиков
    this.subscribers = new Map();

    // Флаг для батча обновлений (группировка вызовов)
    this.isBatching = false;
    this.pendingNotifications = new Set();

    this.logger = new Logger('stateManager');
  }

  /**
   * Получить значение состояния по ключу
   * @param {string} key
   * @returns {*} значение состояния или undefined
   */
  getState(key) {
    return this.state.get(key);
  }

  /**
   * Установить значение состояния и уведомить подписчиков
   * @param {string} key
   * @param {*} value
   */
  setState(key, value) {
    const oldValue = this.state.get(key);

    // Сравнение по ссылке и значению (глубокое сравнение можно добавить при необходимости)
    if (oldValue === value) {
      this.logger.debug(`No state change for key "${key}"`);
      return; // Нет изменений - не уведомляем
    }

    this.state.set(key, value);
    this.logger.info(`State updated for key "${key}"`);

    this.notifySubscribers(key);
  }

  /**
   * Подписка на изменения состояния по ключу
   * @param {string} key
   * @param {Function} callback - функция вызывается с новым значением
   * @returns {Function} функция отписки
   */
  subscribe(key, callback) {
    if (!this.subscribers.has(key)) {
      this.subscribers.set(key, new Set());
    }
    this.subscribers.get(key).add(callback);
    this.logger.info(`Subscribed to key "${key}"`);

    // Возвращаем функцию отписки
    return () => {
      this.subscribers.get(key).delete(callback);
      this.logger.info(`Unsubscribed from key "${key}"`);
    };
  }

  /**
   * Уведомление подписчиков состояния по ключу
   * Поддержка батча — если isBatching = true, уведомления группируются
   * @param {string} key
   */
  notifySubscribers(key) {
    if (this.isBatching) {
      this.pendingNotifications.add(key);
      return;
    }

    const callbacks = this.subscribers.get(key);
    if (!callbacks || callbacks.size === 0) return;

    const value = this.state.get(key);

    callbacks.forEach((callback) => {
      try {
        callback(value);
      } catch (error) {
        this.logger.error(`Error in subscriber callback for key "${key}":`, error);
      }
    });
  }

  /**
   * Начать батч обновлений
   */
  beginBatch() {
    this.isBatching = true;
    this.logger.debug('Batch update started');
  }

  /**
   * Завершить батч обновлений и уведомить все подписчиков, изменившиеся в батче
   */
  endBatch() {
    this.isBatching = false;
    this.logger.debug('Batch update ended');

    // Уведомить всех подписчиков для ключей, изменённых в батче
    this.pendingNotifications.forEach((key) => this.notifySubscribers(key));
    this.pendingNotifications.clear();
  }

  /**
   * Обновить несколько ключей состояния в батче
   * @param {Object} updates - объект ключ-значение для обновления
   */
  batchUpdate(updates) {
    this.beginBatch();
    try {
      for (const [key, value] of Object.entries(updates)) {
        this.setState(key, value);
      }
    } finally {
      this.endBatch();
    }
  }
}

const stateManagerInstance = new StateManager();

export default stateManagerInstance;
