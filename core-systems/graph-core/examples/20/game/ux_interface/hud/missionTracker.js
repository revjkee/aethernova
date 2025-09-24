// missionTracker.js
// TeslaAI Genesis v1.8 — Industrial UX HUD Module (Mission Tracker)
// Authoritative version — enhanced by 20 agents + 3 metagenerals

import { createSignal, onCleanup } from 'solid-js';
import i18n from '../localization/i18n';                     // Мультиязычность
import { subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';
import { animateMissionUpdate } from '../animations/missionFX';
import { getCurrentMissionState } from '../../core/state/missions';
import { renderIcon } from '../ui/icons';
import { logDevMetric } from '../../core/devtools/metrics';
import styles from './missionTracker.module.css';

// Reactive signal storage
const [missions, setMissions] = createSignal([]);
const [highlight, setHighlight] = createSignal(null);
const [devMode, setDevMode] = createSignal(false); // включение через debug menu

// Mission Tracker UI Component
export function MissionTracker() {
  onCleanup(() => {
    unsubscribeFromEvent('MISSION_UPDATE', handleMissionUpdate);
    unsubscribeFromEvent('LANGUAGE_CHANGE', handleLangChange);
  });

  // Initial load
  handleMissionUpdate();

  // Event handlers
  subscribeToEvent('MISSION_UPDATE', handleMissionUpdate);
  subscribeToEvent('LANGUAGE_CHANGE', handleLangChange);

  function handleMissionUpdate() {
    const current = getCurrentMissionState();  // Получение актуальных миссий
    setMissions(current);
    animateMissionUpdate();                   // Плавная анимация
    if (devMode()) logDevMetric('MissionTrackerUpdate', current.length);
  }

  function handleLangChange(newLang) {
    i18n.setLanguage(newLang);                // Перевод интерфейса
  }

  function toggleDev() {
    setDevMode(!devMode());
  }

  return (
    <div class={styles.trackerContainer} role="complementary" aria-label={i18n.t('missions.tracker')}>
      <header class={styles.trackerHeader}>
        <h2>{i18n.t('missions.title')}</h2>
        {devMode() && <span class={styles.devLabel}>DEV</span>}
      </header>
      <ul class={styles.missionList}>
        {missions().map((mission) => (
          <li
            class={`${styles.missionItem} ${highlight() === mission.id ? styles.highlighted : ''}`}
            onMouseEnter={() => setHighlight(mission.id)}
            onMouseLeave={() => setHighlight(null)}
            aria-current={mission.status === 'active' ? 'true' : 'false'}
            data-status={mission.status}
          >
            {renderIcon(mission.icon)}
            <div class={styles.textBlock}>
              <strong>{i18n.t(`missions.${mission.id}.name`)}</strong>
              <p>{i18n.t(`missions.${mission.id}.desc`)}</p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
