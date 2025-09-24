// hudAnimations.js
// TeslaAI Genesis v1.8 — Индустриальный модуль анимаций HUD (консиллиум из 20 агентов и 3 метагенералов)

const DEFAULT_ANIMATION_DURATION = 400;
const DEFAULT_EASING = 'cubic-bezier(0.22, 1, 0.36, 1)';
const animationRegistry = new Map();

// Анимация появления HUD-элемента
export function animateHUDIn(element, options = {}) {
  if (!element || !(element instanceof HTMLElement)) return;
  const config = getAnimationConfig(options, 'in');
  interruptCurrent(element);

  const keyframes = [
    { opacity: 0, transform: 'translateY(-10%) scale(0.95)' },
    { opacity: 1, transform: 'translateY(0%) scale(1)' }
  ];

  const animation = element.animate(keyframes, config);
  registerAnimation(element, animation);
}

// Анимация исчезновения HUD-элемента
export function animateHUDOut(element, options = {}) {
  if (!element || !(element instanceof HTMLElement)) return;
  const config = getAnimationConfig(options, 'out');
  interruptCurrent(element);

  const keyframes = [
    { opacity: 1, transform: 'translateY(0%) scale(1)' },
    { opacity: 0, transform: 'translateY(-10%) scale(0.95)' }
  ];

  const animation = element.animate(keyframes, config);
  registerAnimation(element, animation);
  animation.onfinish = () => element.style.display = 'none';
}

// Анимация всплытия уведомления
export function animateNotification(element, options = {}) {
  if (!element || !(element instanceof HTMLElement)) return;
  const config = getAnimationConfig(options, 'in');
  interruptCurrent(element);

  const keyframes = [
    { opacity: 0, transform: 'translateY(50%)', filter: 'blur(4px)' },
    { opacity: 1, transform: 'translateY(0%)', filter: 'blur(0)' }
  ];

  const animation = element.animate(keyframes, config);
  registerAnimation(element, animation);
}

// Получение конфигурации анимации
function getAnimationConfig({ duration, easing, delay, fill, priority }, type) {
  return {
    duration: duration || DEFAULT_ANIMATION_DURATION,
    easing: easing || DEFAULT_EASING,
    delay: delay || 0,
    fill: fill || 'both',
    direction: type === 'out' ? 'normal' : 'normal'
  };
}

// Прерывание текущей анимации
function interruptCurrent(element) {
  if (animationRegistry.has(element)) {
    animationRegistry.get(element).cancel();
    animationRegistry.delete(element);
  }
}

// Регистрация активной анимации
function registerAnimation(element, animation) {
  animationRegistry.set(element, animation);
}

// Массовая анимация HUD-группы
export function batchAnimate(elements, method = animateHUDIn, delay = 60) {
  elements.forEach((el, i) => {
    setTimeout(() => {
      method(el, { delay: 0 });
    }, i * delay);
  });
}

// HUD-пульсация (например, для индикаторов)
export function animatePulse(element, intensity = 1.1, duration = 600) {
  if (!element || !(element instanceof HTMLElement)) return;
  const keyframes = [
    { transform: `scale(1)` },
    { transform: `scale(${intensity})` },
    { transform: `scale(1)` }
  ];

  const animation = element.animate(keyframes, {
    duration,
    iterations: Infinity,
    easing: 'ease-in-out'
  });

  registerAnimation(element, animation);
}

// Сброс всех HUD-анимаций
export function resetHUDAnimations() {
  animationRegistry.forEach((anim, el) => {
    anim.cancel();
    el.style.opacity = '';
    el.style.transform = '';
  });
  animationRegistry.clear();
}
