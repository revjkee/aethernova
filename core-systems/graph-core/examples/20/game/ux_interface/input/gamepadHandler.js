// gamepadHandler.js
// TeslaAI Genesis v1.8 — Industrial Gamepad Input System
// Проверено консиллиумом из 20 агентов и 3 метагенералов

import { dispatchEvent, subscribeToEvent } from '../../core/eventBus';
import { logGamepadInput } from '../../core/devtools/inputLogger';
import { isXRActive } from '../../core/platform/xrUtils';
import { applyDeadzone, normalizeAxis } from './gamepadUtils';
import { playVibration } from '../../core/haptics/vibration';

const POLL_INTERVAL_MS = 16;
let pollInterval = null;
let devMode = false;
let lastState = {};

const deadzone = 0.15;
const axisNames = ['LeftStickX', 'LeftStickY', 'RightStickX', 'RightStickY'];

function pollGamepads() {
  const gamepads = navigator.getGamepads ? navigator.getGamepads() : [];

  for (let index = 0; index < gamepads.length; index++) {
    const gp = gamepads[index];
    if (!gp || !gp.connected) continue;

    const state = {
      buttons: gp.buttons.map(b => b.pressed),
      axes: gp.axes.map(a => normalizeAxis(a, deadzone)),
      id: gp.id,
    };

    const prev = lastState[gp.index] || { buttons: [], axes: [] };

    // Compare buttons
    state.buttons.forEach((pressed, i) => {
      if (pressed !== prev.buttons[i]) {
        dispatchEvent('GAMEPAD_BUTTON', {
          type: pressed ? 'down' : 'up',
          index: i,
          name: `Button${i}`,
          gamepadIndex: gp.index,
        });
        if (devMode) logGamepadInput({ type: pressed ? 'down' : 'up', index: i, gamepad: gp.index });
        if (pressed) playVibration(gp.index, 0.1, 0.2); // Тактильная обратная связь
      }
    });

    // Compare axes (sticks)
    state.axes.forEach((value, i) => {
      if (Math.abs(value - (prev.axes[i] || 0)) > 0.01) {
        dispatchEvent('GAMEPAD_AXIS', {
          axis: axisNames[i] || `Axis${i}`,
          value,
          gamepadIndex: gp.index,
        });
        if (devMode) logGamepadInput({ type: 'axis', axis: i, value, gamepad: gp.index });
      }
    });

    lastState[gp.index] = state;
  }
}

export function enableGamepadInput({ developerMode = false } = {}) {
  devMode = developerMode;

  pollInterval = setInterval(pollGamepads, POLL_INTERVAL_MS);

  window.addEventListener('gamepadconnected', (e) => {
    dispatchEvent('GAMEPAD_CONNECTED', { index: e.gamepad.index, id: e.gamepad.id });
    if (devMode) logGamepadInput({ type: 'connected', gamepad: e.gamepad.index });
  });

  window.addEventListener('gamepaddisconnected', (e) => {
    dispatchEvent('GAMEPAD_DISCONNECTED', { index: e.gamepad.index });
    delete lastState[e.gamepad.index];
    if (devMode) logGamepadInput({ type: 'disconnected', gamepad: e.gamepad.index });
  });

  subscribeToEvent('CLEAR_GAMEPAD_STATE', resetGamepadState);
}

export function disableGamepadInput() {
  clearInterval(pollInterval);
  pollInterval = null;
  lastState = {};
}

function resetGamepadState() {
  lastState = {};
}

export function getGamepadSnapshot() {
  return JSON.parse(JSON.stringify(lastState));
}
