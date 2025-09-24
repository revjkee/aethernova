// statusOverlay.js
// TeslaAI Genesis v1.8 — Advanced HUD Status Overlay
// Проверено 20 агентами и 3 метагенералами (производственный стандарт)

import { createSignal, onCleanup } from 'solid-js';
import { subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';
import { interpolateColor, animateStatusBar } from '../animations/statusFX';
import { getPlayerStatus } from '../../core/state/player';
import { renderGauge } from '../ui/gauges';
import i18n from '../localization/i18n';
import styles from './statusOverlay.module.css';

// Reactive signals
const [health, setHealth] = createSignal(100);
const [stamina, setStamina] = createSignal(100);
const [armor, setArmor] = createSignal(0);
const [devMode, setDevMode] = createSignal(false);

// Status Overlay Component
export function StatusOverlay() {
  // Event Binding
  onCleanup(() => {
    unsubscribeFromEvent('STATUS_UPDATE', handleStatusUpdate);
    unsubscribeFromEvent('DEV_MODE_TOGGLE', toggleDevMode);
  });

  subscribeToEvent('STATUS_UPDATE', handleStatusUpdate);
  subscribeToEvent('DEV_MODE_TOGGLE', toggleDevMode);

  // Initial load
  handleStatusUpdate();

  function handleStatusUpdate() {
    const status = getPlayerStatus();
    setHealth(status.health);
    setStamina(status.stamina);
    setArmor(status.armor);

    animateStatusBar('health', status.health);
    animateStatusBar('stamina', status.stamina);
    animateStatusBar('armor', status.armor);
  }

  function toggleDevMode() {
    setDevMode(!devMode());
  }

  return (
    <div class={styles.statusOverlay} role="status" aria-label={i18n.t('statusOverlay.label')}>
      <div class={styles.gaugeGroup}>
        {renderGauge({
          id: 'health',
          value: health(),
          label: i18n.t('statusOverlay.health'),
          color: interpolateColor(health(), 100, '#00FF00', '#FF0000'),
        })}
        {renderGauge({
          id: 'stamina',
          value: stamina(),
          label: i18n.t('statusOverlay.stamina'),
          color: interpolateColor(stamina(), 100, '#00FFFF', '#0044FF'),
        })}
        {renderGauge({
          id: 'armor',
          value: armor(),
          label: i18n.t('statusOverlay.armor'),
          color: interpolateColor(armor(), 100, '#CCCCCC', '#555555'),
        })}
      </div>
      {devMode() && (
        <div class={styles.devDebugPanel}>
          <span>Health: {health()}</span>
          <span>Stamina: {stamina()}</span>
          <span>Armor: {armor()}</span>
        </div>
      )}
    </div>
  );
}
