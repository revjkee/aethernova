// settingsMenu.js
// TeslaAI Genesis v1.8 — Industrial Settings Menu Component
// Проверено консиллиумом из 20 агентов и 3 метагенералов

import { createSignal, onCleanup, createEffect } from 'solid-js';
import { dispatchEvent, subscribeToEvent } from '../../core/eventBus';
import { playAudioCue } from '../../core/audio/audioFeedback';
import { getAvailableLanguages, setLanguage } from '../../core/localization/i18n';
import { loadUserSettings, saveUserSettings } from '../../core/state/settings';
import { applyGraphicsSettings } from '../../core/graphics/renderer';
import styles from './settingsMenu.module.css';

const [visible, setVisible] = createSignal(false);
const [language, setLang] = createSignal('en');
const [volume, setVolume] = createSignal(0.8);
const [quality, setQuality] = createSignal('high');
const [devMode, setDevMode] = createSignal(false);

function handleEscape(e) {
  if (!visible()) return;
  if (e.key === 'Escape') {
    closeSettings();
  }
}

function openSettings() {
  setVisible(true);
  playAudioCue('open');
}

function closeSettings() {
  setVisible(false);
  saveUserSettings({
    language: language(),
    volume: volume(),
    graphics: { quality: quality() },
  });
  playAudioCue('close');
  dispatchEvent('SETTINGS_CLOSED');
}

function applySettings() {
  setLanguage(language());
  applyGraphicsSettings({ quality: quality() });
  dispatchEvent('SETTINGS_APPLIED');
  playAudioCue('confirm');
  if (devMode()) console.debug('[Settings] Applied:', language(), volume(), quality());
}

function onLangChange(e) {
  setLang(e.target.value);
}

function onVolumeChange(e) {
  setVolume(parseFloat(e.target.value));
}

function onQualityChange(e) {
  setQuality(e.target.value);
}

export function SettingsMenu() {
  createEffect(() => {
    const settings = loadUserSettings();
    if (settings.language) setLang(settings.language);
    if (settings.volume !== undefined) setVolume(settings.volume);
    if (settings.graphics?.quality) setQuality(settings.graphics.quality);
  });

  onCleanup(() => {
    window.removeEventListener('keydown', handleEscape);
    unsubscribeFromEvent('OPEN_SETTINGS', openSettings);
  });

  window.addEventListener('keydown', handleEscape);
  subscribeToEvent('OPEN_SETTINGS', openSettings);

  return visible() ? (
    <div class={styles.settingsMenu} role="dialog" aria-label="Settings Menu">
      <h1>Settings</h1>

      <label>
        Language:
        <select value={language()} onChange={onLangChange}>
          {getAvailableLanguages().map((lang) => (
            <option value={lang}>{lang.toUpperCase()}</option>
          ))}
        </select>
      </label>

      <label>
        Volume:
        <input
          type="range"
          min="0"
          max="1"
          step="0.01"
          value={volume()}
          onInput={onVolumeChange}
        />
        <span>{Math.round(volume() * 100)}%</span>
      </label>

      <label>
        Graphics Quality:
        <select value={quality()} onChange={onQualityChange}>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="ultra">Ultra</option>
        </select>
      </label>

      <div class={styles.buttonRow}>
        <button onClick={applySettings}>Apply</button>
        <button onClick={closeSettings}>Close</button>
      </div>
    </div>
  ) : null;
}
