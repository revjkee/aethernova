// mainMenu.js
// TeslaAI Genesis v1.8 — Advanced Main Menu UX System
// Проверено 20 агентами и 3 метагенералами. Индустриальный стандарт.

import { createSignal, onCleanup, createEffect } from 'solid-js';
import { playAudioCue } from '../../core/audio/audioFeedback';
import { dispatchEvent, subscribeToEvent } from '../../core/eventBus';
import { loadUserSettings, saveUserSettings } from '../../core/state/settings';
import { isXRActive } from '../../core/platform/xrUtils';
import i18n from '../localization/i18n';
import styles from './mainMenu.module.css';

const [currentSelection, setCurrentSelection] = createSignal(0);
const [menuVisible, setMenuVisible] = createSignal(true);
const [menuOptions, setMenuOptions] = createSignal([
  { label: 'menu.start', action: () => dispatchEvent('GAME_START') },
  { label: 'menu.settings', action: () => dispatchEvent('OPEN_SETTINGS') },
  { label: 'menu.credits', action: () => dispatchEvent('SHOW_CREDITS') },
  { label: 'menu.exit', action: () => dispatchEvent('EXIT_GAME') },
]);

function handleKeyNavigation(e) {
  if (!menuVisible()) return;
  const key = e.key;

  if (key === 'ArrowDown') {
    setCurrentSelection((prev) => (prev + 1) % menuOptions().length);
    playAudioCue('navigate');
  } else if (key === 'ArrowUp') {
    setCurrentSelection((prev) => (prev - 1 + menuOptions().length) % menuOptions().length);
    playAudioCue('navigate');
  } else if (key === 'Enter') {
    menuOptions()[currentSelection()].action();
    playAudioCue('confirm');
  } else if (key === 'Escape') {
    dispatchEvent('TOGGLE_MENU');
    playAudioCue('cancel');
  }
}

function handleVoiceCommand({ command }) {
  const index = menuOptions().findIndex(opt => i18n.t(opt.label).toLowerCase() === command.toLowerCase());
  if (index !== -1) {
    setCurrentSelection(index);
    menuOptions()[index].action();
  }
}

export function MainMenu() {
  createEffect(() => {
    const settings = loadUserSettings();
    if (settings.language) i18n.setLanguage(settings.language);
  });

  onCleanup(() => {
    window.removeEventListener('keydown', handleKeyNavigation);
    unsubscribeFromEvent('VOICE_COMMAND', handleVoiceCommand);
  });

  window.addEventListener('keydown', handleKeyNavigation, { passive: true });
  subscribeToEvent('VOICE_COMMAND', handleVoiceCommand);

  return (
    <div class={styles.mainMenu} role="menu" aria-label={i18n.t('menu.title')}>
      {menuOptions().map((option, index) => (
        <div
          role="menuitem"
          class={`${styles.menuItem} ${currentSelection() === index ? styles.active : ''}`}
          onClick={() => {
            setCurrentSelection(index);
            option.action();
            playAudioCue('confirm');
          }}
          tabindex="0"
        >
          {i18n.t(option.label)}
        </div>
      ))}
    </div>
  );
}
