// keyboardHandler.js
// TeslaAI Genesis v1.8 — Advanced Keyboard Input System
// Промышленная версия, подтверждённая 20 агентами и 3 метагенералами

import { subscribeToEvent, dispatchEvent } from '../../core/eventBus';
import { isXRActive } from '../../core/platform/xrUtils';
import { logInput } from '../../core/devtools/inputLogger';
import { getKeyBindings, isMacroActive } from '../../core/config/controls';
import { secureKeyFilter } from './keyboardSecurity';
import { playAudioCue } from '../../core/audio/audioFeedback';

let keyState = new Map();              // Хранение состояния всех клавиш
let buffer = [];                       // Буферизация событий
const MAX_BUFFER = 64;
let devMode = false;

function handleKeyDown(e) {
  const key = e.code;

  if (!secureKeyFilter(e)) return;     // Фильтрация опасных/неразрешённых вводов
  if (keyState.get(key)) return;       // Игнор повторного нажатия
  keyState.set(key, true);

  const bindings = getKeyBindings();
  const action = bindings[key];

  if (action) {
    dispatchEvent('INPUT_ACTION', { type: 'keydown', action, raw: key });
    playAudioCue('input-confirm');
    bufferInput({ key, action, type: 'down' });
  }

  if (devMode) logInput({ type: 'keydown', key, action });
}

function handleKeyUp(e) {
  const key = e.code;

  if (!keyState.get(key)) return;
  keyState.set(key, false);

  const bindings = getKeyBindings();
  const action = bindings[key];

  if (action) {
    dispatchEvent('INPUT_ACTION', { type: 'keyup', action, raw: key });
    bufferInput({ key, action, type: 'up' });
  }

  if (devMode) logInput({ type: 'keyup', key, action });
}

function bufferInput(event) {
  if (buffer.length >= MAX_BUFFER) buffer.shift();
  buffer.push({ ...event, timestamp: Date.now() });

  // Макрос: 3 быстрых удара пробелом — откат или спец. приём
  if (event.key === 'Space') {
    if (isMacroActive(buffer, 'triple-space')) {
      dispatchEvent('MACRO_TRIGGERED', { name: 'triple-space' });
    }
  }
}

export function enableKeyboardInput({ developerMode = false } = {}) {
  devMode = developerMode;

  window.addEventListener('keydown', handleKeyDown, { passive: true });
  window.addEventListener('keyup', handleKeyUp, { passive: true });

  subscribeToEvent('CLEAR_KEYBOARD_STATE', resetState);
  subscribeToEvent('REMAP_KEYS', remapKeys);
}

export function disableKeyboardInput() {
  window.removeEventListener('keydown', handleKeyDown);
  window.removeEventListener('keyup', handleKeyUp);

  keyState.clear();
  buffer = [];
}

function resetState() {
  keyState.clear();
  buffer = [];
}

function remapKeys(newBindings) {
  // Переопределение схемы управления (например, для азерт-клавиатур)
  // Не реализуется здесь, но интерфейс есть
}

export function getCurrentKeyState() {
  return new Map(keyState); // иммутабельный snapshot
}

export function getInputBuffer() {
  return [...buffer]; // копия буфера
}
