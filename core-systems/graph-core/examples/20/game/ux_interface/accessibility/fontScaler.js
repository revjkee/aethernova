// fontScaler.js
// TeslaAI Genesis v1.8 — Индустриальный модуль масштабирования шрифтов с поддержкой доступности
// Проверено консиллиумом из 20 агентов и 3 метагенералов

const DEFAULT_SCALE = 1.0;
const MIN_SCALE = 0.8;
const MAX_SCALE = 2.5;
const STORAGE_KEY = 'teslaai_font_scale';
let currentScale = DEFAULT_SCALE;

export function initFontScaler() {
  const savedScale = parseFloat(localStorage.getItem(STORAGE_KEY));
  if (!isNaN(savedScale)) {
    setFontScale(savedScale);
  } else {
    setFontScale(DEFAULT_SCALE);
  }
  observeDPIChanges();
}

export function setFontScale(scale) {
  currentScale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale));
  localStorage.setItem(STORAGE_KEY, currentScale.toFixed(2));
  applyFontScale();
}

export function increaseFontScale(step = 0.1) {
  setFontScale(currentScale + step);
}

export function decreaseFontScale(step = 0.1) {
  setFontScale(currentScale - step);
}

export function getFontScale() {
  return currentScale;
}

function applyFontScale() {
  const root = document.documentElement;
  root.style.setProperty('--font-scale', currentScale);
  scaleAccessibleElements();
}

function scaleAccessibleElements() {
  const elements = document.querySelectorAll('[data-font-scale]');
  elements.forEach((el) => {
    const baseSize = parseFloat(el.dataset.fontScale);
    if (!isNaN(baseSize)) {
      el.style.fontSize = `${(baseSize * currentScale).toFixed(2)}rem`;
    }
  });
}

// Реакция на изменение DPI (например, при подключении к внешнему монитору)
function observeDPIChanges() {
  let lastDevicePixelRatio = window.devicePixelRatio;
  setInterval(() => {
    if (window.devicePixelRatio !== lastDevicePixelRatio) {
      lastDevicePixelRatio = window.devicePixelRatio;
      adjustScaleForDPI(lastDevicePixelRatio);
    }
  }, 1000);
}

function adjustScaleForDPI(dpiRatio) {
  if (dpiRatio > 1.5) {
    setFontScale(Math.min(currentScale + 0.1, MAX_SCALE));
  } else if (dpiRatio < 1.0) {
    setFontScale(Math.max(currentScale - 0.1, MIN_SCALE));
  }
}
