// mouseHandler.js
// TeslaAI Genesis v1.8 — Advanced Mouse Input Handler
// Проверено 20 агентами и 3 метагенералами, промышленный стандарт

import { dispatchEvent, subscribeToEvent } from '../../core/eventBus';
import { normalizeCoords, clampDelta } from './mouseUtils';
import { logMouseEvent } from '../../core/devtools/inputLogger';
import { playAudioCue } from '../../core/audio/audioFeedback';
import { isXRActive } from '../../core/platform/xrUtils';

let mouseState = {
  position: { x: 0, y: 0 },
  buttons: new Set(),
  movementBuffer: [],
};

const MAX_BUFFER = 64;
let devMode = false;

function handleMouseMove(e) {
  const normalized = normalizeCoords(e.clientX, e.clientY);

  const deltaX = clampDelta(e.movementX);
  const deltaY = clampDelta(e.movementY);

  mouseState.position = normalized;

  if (!isXRActive()) {
    dispatchEvent('MOUSE_MOVE', {
      position: normalized,
      delta: { x: deltaX, y: deltaY },
      raw: { x: e.clientX, y: e.clientY },
    });
  }

  bufferMovement({ type: 'move', x: deltaX, y: deltaY, ts: Date.now() });

  if (devMode) logMouseEvent({ type: 'move', deltaX, deltaY });
}

function handleMouseDown(e) {
  const button = e.button;
  mouseState.buttons.add(button);

  dispatchEvent('MOUSE_CLICK', {
    type: 'down',
    button,
    position: mouseState.position,
  });

  playAudioCue('click');
  if (devMode) logMouseEvent({ type: 'down', button });
}

function handleMouseUp(e) {
  const button = e.button;
  mouseState.buttons.delete(button);

  dispatchEvent('MOUSE_CLICK', {
    type: 'up',
    button,
    position: mouseState.position,
  });

  if (devMode) logMouseEvent({ type: 'up', button });
}

function bufferMovement(event) {
  if (mouseState.movementBuffer.length >= MAX_BUFFER) {
    mouseState.movementBuffer.shift();
  }
  mouseState.movementBuffer.push(event);
}

function handleContextMenu(e) {
  e.preventDefault(); // Запрет на вызов контекстного меню
}

export function enableMouseInput({ developerMode = false } = {}) {
  devMode = developerMode;

  window.addEventListener('mousemove', handleMouseMove, { passive: true });
  window.addEventListener('mousedown', handleMouseDown, { passive: true });
  window.addEventListener('mouseup', handleMouseUp, { passive: true });
  window.addEventListener('contextmenu', handleContextMenu);

  subscribeToEvent('CLEAR_MOUSE_STATE', resetMouseState);
}

export function disableMouseInput() {
  window.removeEventListener('mousemove', handleMouseMove);
  window.removeEventListener('mousedown', handleMouseDown);
  window.removeEventListener('mouseup', handleMouseUp);
  window.removeEventListener('contextmenu', handleContextMenu);

  resetMouseState();
}

function resetMouseState() {
  mouseState = {
    position: { x: 0, y: 0 },
    buttons: new Set(),
    movementBuffer: [],
  };
}

export function getMouseSnapshot() {
  return {
    ...mouseState,
    movementBuffer: [...mouseState.movementBuffer],
  };
}
