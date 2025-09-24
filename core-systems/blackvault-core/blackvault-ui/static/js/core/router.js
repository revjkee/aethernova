/**
 * router.js
 * =================================================================
 * Маршрутизация SPA TeslaAI BlackVault UI
 * Обеспечивает управление состоянием URL, навигацию без перезагрузки,
 * поддержку истории браузера и асинхронную загрузку компонентов.
 * =================================================================
 */

import Logger from '../utils/logger.js';

class Router {
  constructor() {
    this.routes = new Map();
    this.logger = new Logger('router');
    this.currentRoute = null;

    // Обработчик изменения URL (back/forward)
    window.addEventListener('popstate', (event) => {
      this.logger.info('Popstate event:', window.location.pathname);
      this.navigateTo(window.location.pathname, {replace: true});
    });
  }

  /**
   * Регистрирует новый маршрут
   * @param {string} path - путь маршрута, например '/dashboard'
   * @param {Function} handler - функция, вызываемая при переходе на маршрут
   */
  registerRoute(path, handler) {
    if (typeof handler !== 'function') {
      throw new Error('Route handler must be a function');
    }
    this.routes.set(path, handler);
    this.logger.info(`Registered route: ${path}`);
  }

  /**
   * Навигация к маршруту
   * @param {string} path - путь для перехода
   * @param {object} options - опции навигации: {replace: boolean}
   */
  async navigateTo(path, options = {}) {
    this.logger.info(`Navigate to: ${path}`);

    if (!this.routes.has(path)) {
      this.logger.warn(`Route not found: ${path}`);
      // Здесь можно реализовать fallback или 404 страницу
      return;
    }

    // Обновляем историю браузера
    if (options.replace) {
      window.history.replaceState({}, '', path);
    } else {
      window.history.pushState({}, '', path);
    }

    // Запускаем обработчик маршрута
    try {
      const handler = this.routes.get(path);
      await handler();
      this.currentRoute = path;
      this.logger.info(`Successfully navigated to ${path}`);
    } catch (error) {
      this.logger.error(`Error during navigation to ${path}:`, error);
      // Здесь можно показать ошибку UI
    }
  }

  /**
   * Инициализация роутера - переход на текущий URL при загрузке страницы
   */
  async init() {
    const initialPath = window.location.pathname;
    this.logger.info('Router init with path:', initialPath);
    await this.navigateTo(initialPath, {replace: true});
  }
}

const routerInstance = new Router();

export default routerInstance;
