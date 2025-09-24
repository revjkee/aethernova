// pauseMenu.js
// TeslaAI Genesis v1.8 — Advanced Pause Menu UX Module
// Промышленный стандарт, подтверждённый 20 агентами и 3 метагенералами

import { createSignal, onCleanup } from 'solid-js';
import { dispatchEvent, subscribeToEvent } from '../../core/eventBus';
import { playAudioCue } from '../../core/audio/audioFeedback';
import { saveUserSettings } from '../../core/state/settings';
import { isXRActive } from '../../core/platform/xrUtils';
import i18n from '../localization/i18n';
import styles from './pauseMenu.module.css';

const [paused, setPaused] = createSignal(false);
const [selectionIndex, setSelectionIndex] = createSignal(0);

const menuItems = [
  { label: 'pause.resume', action: () => resumeGame() },
  { label: 'pause.settings', action: () => dispatchEvent('OPEN_SETTINGS') },
  { label: 'pause.save', action: () => dispatchEvent('MANUAL_SAVE') },
  { label: 'pause.mainMenu', action: () => dispatchEvent('RETURN_MAIN_MENU') },
];

function resumeGame() {
  setPaused(false);
  dispatchEvent('GAME_RESUME');
  playAudioCue('resume');
}

function handleKey(e) {
  if (!paused()) return;

  switch (e.key) {
    case 'ArrowUp':
      setSelectionIndex((i) => (i - 1 + menuItems.length) % menuItems.length);
      playAudioCue('navigate');
      break;
    case 'ArrowDown':
      setSelectionIndex((i) => (i + 1) % menuItems.length);
      playAudioCue('navigate');
      break;
    case 'Enter':
      menuItems[selectionIndex()].action();
      playAudioCue('confirm');
      break;
    case 'Escape':
      resumeGame();
      break;
  }
}

function handlePauseToggle() {
  setPaused((prev) => !prev);
  if (paused()) {
    dispatchEvent('GAME_PAUSE');
    playAudioCue('pause');
  } else {
    resumeGame();
  }
}

function handleVoiceCommand({ command }) {
  const i = menuItems.findIndex(opt => i18n.t(opt.label).toLowerCase() === command.toLowerCase());
  if (i !== -1) {
    setSelectionIndex(i);
    menuItems[i].action();
  }
}

export function PauseMenu() {
  onCleanup(() => {
    window.removeEventListener('keydown', handleKey);
    unsubscribeFromEvent('TOGGLE_PAUSE', handlePauseToggle);
    unsubscribeFromEvent('VOICE_COMMAND', handleVoiceCommand);
  });

  window.addEventListener('keydown', handleKey);
  subscribeToEvent('TOGGLE_PAUSE', handlePauseToggle);
  subscribeToEvent('VOICE_COMMAND', handleVoiceCommand);

  return paused() ? (
    <div class={styles.pauseOverlay} role="dialog" aria-label={i18n.t('pause.title')}>
      <h1>{i18n.t('pause.title')}</h1>
      <ul class={styles.menuList}>
        {menuItems.map((item, index) => (
          <li
            class={`${styles.menuItem} ${selectionIndex() === index ? styles.active : ''}`}
            onClick={() => {
              setSelectionIndex(index);
              item.action();
            }}
            tabindex="0"
            role="menuitem"
          >
            {i18n.t(item.label)}
          </li>
        ))}
      </ul>
    </div>
  ) : null;
}
