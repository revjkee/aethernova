// creditsScreen.js
// TeslaAI Genesis v1.8 — Industrial Credits Screen UX Module
// Проверено 20 агентами и 3 метагенералами

import { createSignal, onCleanup, onMount } from 'solid-js';
import { dispatchEvent, subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';
import { playAudioCue } from '../../core/audio/audioFeedback';
import { loadCreditsData } from '../../core/content/creditsProvider';
import i18n from '../localization/i18n';
import styles from './creditsScreen.module.css';

const [visible, setVisible] = createSignal(false);
const [creditsList, setCreditsList] = createSignal([]);
const [devMode, setDevMode] = createSignal(false);

let scrollContainer = null;
let scrollInterval = null;
const SCROLL_SPEED = 0.5; // px/frame

function startAutoScroll() {
  if (!scrollContainer) return;
  scrollInterval = setInterval(() => {
    scrollContainer.scrollTop += SCROLL_SPEED;
    const maxScroll = scrollContainer.scrollHeight - scrollContainer.clientHeight;
    if (scrollContainer.scrollTop >= maxScroll) {
      stopCredits();
    }
  }, 16); // 60 FPS
}

function stopAutoScroll() {
  if (scrollInterval) clearInterval(scrollInterval);
}

function stopCredits() {
  stopAutoScroll();
  setVisible(false);
  dispatchEvent('CREDITS_CLOSED');
  playAudioCue('close');
}

function handleKey(e) {
  if (!visible()) return;
  if (e.key === 'Escape' || e.key === 'Enter') {
    stopCredits();
  }
}

function handleCreditsOpen() {
  setVisible(true);
  playAudioCue('open');

  loadCreditsData().then(setCreditsList);
  setTimeout(startAutoScroll, 500);
}

export function CreditsScreen() {
  onMount(() => {
    window.addEventListener('keydown', handleKey);
    subscribeToEvent('SHOW_CREDITS', handleCreditsOpen);
  });

  onCleanup(() => {
    window.removeEventListener('keydown', handleKey);
    unsubscribeFromEvent('SHOW_CREDITS', handleCreditsOpen);
    stopAutoScroll();
  });

  return visible() ? (
    <div class={styles.creditsWrapper} role="dialog" aria-label={i18n.t('credits.title')}>
      <div
        ref={(el) => (scrollContainer = el)}
        class={styles.scrollContainer}
      >
        <h1 class={styles.title}>{i18n.t('credits.title')}</h1>
        <ul class={styles.creditList}>
          {creditsList().map((entry) => (
            <li class={styles.creditEntry}>
              <strong>{entry.name}</strong> — {entry.role}
            </li>
          ))}
        </ul>
      </div>
      <div class={styles.exitHint}>{i18n.t('credits.exitHint') || 'Press ESC to return'}</div>
    </div>
  ) : null;
}
