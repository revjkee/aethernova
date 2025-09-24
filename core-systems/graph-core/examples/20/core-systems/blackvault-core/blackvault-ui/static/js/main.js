/**
 * main.js
 * =================================================================
 * Точка входа для UI TeslaAI BlackVault
 * Инициализация основных компонентов, агентов и глобальных сервисов
 * =================================================================
 */

import { initRouter } from './core/router.js';
import { initStateManager } from './core/stateManager.js';
import { initTelemetry } from './modules/telemetry.js';
import { initAlerts } from './modules/alerts.js';
import { initMetrics } from './modules/metrics.js';
import { initAgiInteraction } from './agi/interaction.js';
import { initSimulation } from './agi/simulation.js';
import { initVisualization } from './agi/visualization.js';
import Logger from './utils/logger.js';

class TeslaAIBlackVaultUI {
  constructor() {
    this.logger = new Logger('main');
  }

  async initialize() {
    try {
      this.logger.info('Starting TeslaAI BlackVault UI initialization...');

      // Инициализация глобального состояния
      await initStateManager();
      this.logger.info('State manager initialized.');

      // Инициализация маршрутизатора SPA
      initRouter();
      this.logger.info('Router initialized.');

      // Инициализация модулей
      initTelemetry();
      initAlerts();
      initMetrics();
      this.logger.info('Modules (telemetry, alerts, metrics) initialized.');

      // Инициализация AGI взаимодействия и визуализаций
      initAgiInteraction();
      initSimulation();
      initVisualization();
      this.logger.info('AGI components initialized.');

      this.logger.info('TeslaAI BlackVault UI initialization completed successfully.');
    } catch (error) {
      this.logger.error('Initialization failed:', error);
      // В будущем можно добавить fallback UI или перезагрузку компонентов
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const uiApp = new TeslaAIBlackVaultUI();
  uiApp.initialize();
});

export default TeslaAIBlackVaultUI;
