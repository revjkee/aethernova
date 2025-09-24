// interactionDialog.js
// TeslaAI Genesis v1.8 — Industrial-Grade In-Game Dialog System
// Проверено консиллиумом из 20 агентов и 3 метагенералов

import { createSignal, onCleanup } from 'solid-js';
import { dispatchEvent, subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';
import { playAudioCue } from '../../core/audio/audioFeedback';
import { isXRActive } from '../../core/platform/xrUtils';
import i18n from '../localization/i18n';
import styles from './interactionDialog.module.css';

const [visible, setVisible] = createSignal(false);
const [dialogText, setDialogText] = createSignal('');
const [options, setOptions] = createSignal([]);
const [currentOption, setCurrentOption] = createSignal(0);
const [devMode, setDevMode] = createSignal(false);

function openDialog({ text, choices }) {
  setDialogText(text);
  setOptions(choices || []);
  setCurrentOption(0);
  setVisible(true);
  playAudioCue('dialog-open');
}

function closeDialog() {
  setVisible(false);
  setDialogText('');
  setOptions([]);
  setCurrentOption(0);
  playAudioCue('dialog-close');
  dispatchEvent('DIALOG_CLOSED');
}

function selectOption(index) {
  const choice = options()[index];
  if (choice && choice.action) {
    choice.action();
    playAudioCue('dialog-select');
    dispatchEvent('DIALOG_OPTION_SELECTED', { index, label: choice.label });
  }
  closeDialog();
}

function handleKey(e) {
  if (!visible()) return;

  switch (e.key) {
    case 'ArrowUp':
      setCurrentOption((i) => (i - 1 + options().length) % options().length);
      playAudioCue('navigate');
      break;
    case 'ArrowDown':
      setCurrentOption((i) => (i + 1) % options().length);
      playAudioCue('navigate');
      break;
    case 'Enter':
      selectOption(currentOption());
      break;
    case 'Escape':
      closeDialog();
      break;
  }
}

export function InteractionDialog() {
  onCleanup(() => {
    window.removeEventListener('keydown', handleKey);
    unsubscribeFromEvent('SHOW_DIALOG', openDialog);
    unsubscribeFromEvent('HIDE_DIALOG', closeDialog);
  });

  window.addEventListener('keydown', handleKey);
  subscribeToEvent('SHOW_DIALOG', openDialog);
  subscribeToEvent('HIDE_DIALOG', closeDialog);

  return visible() ? (
    <div class={styles.dialogOverlay} role="dialog" aria-label="Interaction Dialog">
      <div class={styles.dialogBox}>
        <p class={styles.dialogText}>{dialogText()}</p>
        <ul class={styles.optionsList}>
          {options().map((opt, idx) => (
            <li
              class={`${styles.optionItem} ${idx === currentOption() ? styles.active : ''}`}
              tabindex="0"
              onClick={() => selectOption(idx)}
              onMouseEnter={() => setCurrentOption(idx)}
              role="button"
            >
              {i18n.t(opt.label)}
            </li>
          ))}
        </ul>
      </div>
    </div>
  ) : null;
}
