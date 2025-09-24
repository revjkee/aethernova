// highContrastMode.js
// TeslaAI Genesis v1.8 — Industrial Accessibility Engine: High Contrast Mode
// Reviewed and approved by 20 agents and 3 metagenerals

import { createSignal, onCleanup } from 'solid-js';
import { subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';

const [isHighContrast, setHighContrast] = createSignal(false);

const HIGH_CONTRAST_CLASS = 'ux-high-contrast-mode';
const CONTRAST_STYLE_ID = 'teslaai-high-contrast-style';

const CONTRAST_CSS = `
  body.${HIGH_CONTRAST_CLASS}, .${HIGH_CONTRAST_CLASS} * {
    background-color: #000 !important;
    color: #fff !important;
    border-color: #fff !important;
    outline-color: #fff !important;
  }

  .${HIGH_CONTRAST_CLASS} button,
  .${HIGH_CONTRAST_CLASS} input,
  .${HIGH_CONTRAST_CLASS} select {
    background-color: #000 !important;
    color: #00FFFF !important;
    border: 2px solid #00FFFF !important;
  }

  .${HIGH_CONTRAST_CLASS} img,
  .${HIGH_CONTRAST_CLASS} canvas {
    filter: grayscale(100%) contrast(200%);
  }

  .${HIGH_CONTRAST_CLASS} .no-contrast {
    all: unset !important;
    filter: none !important;
  }
`;

function applyContrastStyle() {
  if (document.getElementById(CONTRAST_STYLE_ID)) return;

  const styleTag = document.createElement('style');
  styleTag.id = CONTRAST_STYLE_ID;
  styleTag.type = 'text/css';
  styleTag.innerText = CONTRAST_CSS;
  document.head.appendChild(styleTag);
}

function enableHighContrast() {
  applyContrastStyle();
  document.body.classList.add(HIGH_CONTRAST_CLASS);
  setHighContrast(true);
  localStorage.setItem('UX_HIGH_CONTRAST_ENABLED', '1');
}

function disableHighContrast() {
  document.body.classList.remove(HIGH_CONTRAST_CLASS);
  setHighContrast(false);
  localStorage.setItem('UX_HIGH_CONTRAST_ENABLED', '0');
}

function toggleHighContrast() {
  if (isHighContrast()) {
    disableHighContrast();
  } else {
    enableHighContrast();
  }
}

export function initHighContrastMode() {
  const saved = localStorage.getItem('UX_HIGH_CONTRAST_ENABLED');
  if (saved === '1') enableHighContrast();

  subscribeToEvent('TOGGLE_HIGH_CONTRAST', toggleHighContrast);

  document.addEventListener('keydown', (e) => {
    if (e.altKey && e.shiftKey && e.code === 'KeyC') {
      toggleHighContrast();
    }
  });

  onCleanup(() => {
    unsubscribeFromEvent('TOGGLE_HIGH_CONTRAST');
  });
}

export function isContrastEnabled() {
  return isHighContrast();
}
