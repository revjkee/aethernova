// npcDialogSystem.js
// TeslaAI Genesis v1.8 — NPC Adaptive Dialog Engine
// Проверено консиллиумом из 20 агентов и 3 метагенералов

import { createSignal, createEffect, onCleanup } from 'solid-js';
import { dispatchEvent, subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';
import { playAudioCue, speakLine } from '../../core/audio/audioFeedback';
import { isXRActive } from '../../core/platform/xrUtils';
import { i18n } from '../localization/i18n';
import styles from './npcDialogSystem.module.css';

const [dialogActive, setDialogActive] = createSignal(false);
const [npcName, setNpcName] = createSignal('');
const [npcMood, setNpcMood] = createSignal('neutral');
const [dialogQueue, setDialogQueue] = createSignal([]);
const [currentLine, setCurrentLine] = createSignal(null);
const [options, setOptions] = createSignal([]);
const [history, setHistory] = createSignal([]);
const [devMode, setDevMode] = createSignal(false);

let dialogTimer = null;
const AUTO_ADVANCE_DELAY = 4500; // ms

function beginDialog({ name, mood = 'neutral', lines = [] }) {
  setNpcName(name);
  setNpcMood(mood);
  setDialogQueue(lines);
  setHistory([]);
  nextLine();
  setDialogActive(true);
  playAudioCue('dialog-open');
  dispatchEvent('NPC_DIALOG_STARTED', { npc: name });

  if (devMode()) console.debug('[DIALOG OPENED]', name, mood, lines);
}

function endDialog() {
  clearTimer();
  setDialogActive(false);
  setOptions([]);
  setCurrentLine(null);
  dispatchEvent('NPC_DIALOG_ENDED', { npc: npcName() });
  playAudioCue('dialog-close');
}

function clearTimer() {
  if (dialogTimer) clearTimeout(dialogTimer);
  dialogTimer = null;
}

function nextLine() {
  clearTimer();
  const queue = [...dialogQueue()];
  const line = queue.shift();

  if (!line) return endDialog();

  setCurrentLine(line);
  setDialogQueue(queue);
  setOptions(line.options || []);

  setHistory((prev) => [...prev, line]);

  if (line.voice) speakLine(line.voice);
  if (!line.options?.length && !line.waitForClick) {
    dialogTimer = setTimeout(nextLine, line.duration || AUTO_ADVANCE_DELAY);
  }
}

function handleOption(index) {
  const opt = options()[index];
  if (opt?.action) opt.action();

  if (opt?.response) {
    setDialogQueue([{ text: opt.response, duration: 3000 }, ...dialogQueue()]);
  }

  playAudioCue('dialog-select');
  nextLine();
}

function handleKey(e) {
  if (!dialogActive()) return;

  const idx = parseInt(e.key);
  if (!isNaN(idx) && options()[idx - 1]) {
    handleOption(idx - 1);
  }
  if (e.key === 'Enter' && options().length === 0) {
    nextLine();
  }
  if (e.key === 'Escape') {
    endDialog();
  }
}

export function NpcDialogSystem() {
  onCleanup(() => {
    window.removeEventListener('keydown', handleKey);
    unsubscribeFromEvent('START_NPC_DIALOG', beginDialog);
    unsubscribeFromEvent('END_NPC_DIALOG', endDialog);
  });

  window.addEventListener('keydown', handleKey);
  subscribeToEvent('START_NPC_DIALOG', beginDialog);
  subscribeToEvent('END_NPC_DIALOG', endDialog);

  return dialogActive() ? (
    <div class={styles.dialogOverlay} role="dialog" aria-label="NPC Dialog">
      <div class={styles.dialogBox}>
        <header class={styles.dialogHeader}>
          <span class={styles.npcName}>{npcName()}</span>
          <span class={styles.npcMood} data-mood={npcMood()} />
        </header>

        <div class={styles.dialogLine}>
          {currentLine()?.text}
        </div>

        {options().length > 0 && (
          <ul class={styles.optionsList}>
            {options().map((opt, idx) => (
              <li
                class={styles.optionItem}
                onClick={() => handleOption(idx)}
                tabindex="0"
                role="button"
              >
                {idx + 1}. {opt.label}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  ) : null;
}
