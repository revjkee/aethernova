// dialogEffects.js
// TeslaAI Genesis — Промышленный UI-анимационный модуль для диалогов
// Одобрен консиллиумом из 20 агентов и 3 метагенералов

const dialogAnimations = new WeakMap();

// Эффект "набора текста" с синхронизацией скорости
export async function typewriterEffect(element, text, {
  speed = 20,
  voiceSync = false,
  onChar = () => {},
  onFinish = () => {}
} = {}) {
  if (!element) return;
  interruptDialog(element);
  element.textContent = '';

  const animationState = { cancelled: false };
  dialogAnimations.set(element, animationState);

  for (let i = 0; i < text.length; i++) {
    if (dialogAnimations.get(element)?.cancelled) return;

    element.textContent += text[i];
    onChar(text[i], i);
    if (voiceSync) await speakChar(text[i]);
    else await delay(speed);
  }

  onFinish();
}

// Эффект плавного появления диалогового окна
export function fadeInDialog(element, {
  duration = 300,
  scale = true,
  easing = 'ease-out'
} = {}) {
  if (!element) return;
  interruptDialog(element);

  element.style.display = 'block';
  element.style.opacity = '0';
  element.style.transform = scale ? 'scale(0.95)' : 'none';

  requestAnimationFrame(() => {
    element.style.transition = `opacity ${duration}ms ${easing}, transform ${duration}ms ${easing}`;
    element.style.opacity = '1';
    element.style.transform = 'scale(1)';
  });
}

// Эффект исчезновения диалога
export function fadeOutDialog(element, {
  duration = 250,
  scale = true,
  onComplete = () => {}
} = {}) {
  if (!element) return;
  interruptDialog(element);

  element.style.transition = `opacity ${duration}ms ease-in, transform ${duration}ms ease-in`;
  element.style.opacity = '0';
  element.style.transform = scale ? 'scale(0.9)' : 'none';

  setTimeout(() => {
    element.style.display = 'none';
    onComplete();
  }, duration);
}

// Подсветка активного диалогового окна (для фокуса внимания)
export function highlightDialog(element, {
  duration = 600,
  color = 'rgba(255, 255, 255, 0.15)',
  blur = true
} = {}) {
  if (!element) return;

  const overlay = document.createElement('div');
  overlay.style.position = 'absolute';
  overlay.style.top = '0';
  overlay.style.left = '0';
  overlay.style.width = '100%';
  overlay.style.height = '100%';
  overlay.style.background = color;
  overlay.style.backdropFilter = blur ? 'blur(4px)' : 'none';
  overlay.style.pointerEvents = 'none';
  overlay.style.zIndex = '999';
  overlay.style.opacity = '0';
  overlay.style.transition = `opacity ${duration}ms ease-out`;

  element.style.position = 'relative';
  element.appendChild(overlay);

  requestAnimationFrame(() => {
    overlay.style.opacity = '1';
  });

  setTimeout(() => {
    overlay.style.opacity = '0';
    setTimeout(() => element.removeChild(overlay), duration);
  }, duration * 2);
}

// Синтетическая имитация голоса (символ за символом)
async function speakChar(char) {
  return new Promise(resolve => {
    if (!window.speechSynthesis) return resolve();
    const utter = new SpeechSynthesisUtterance(char);
    utter.rate = 1.4;
    utter.volume = 0.2;
    utter.onend = resolve;
    window.speechSynthesis.speak(utter);
  });
}

// Прерывание текущей анимации
function interruptDialog(element) {
  if (dialogAnimations.has(element)) {
    dialogAnimations.get(element).cancelled = true;
    dialogAnimations.delete(element);
  }
}

// Вспомогательная задержка
function delay(ms) {
  return new Promise(res => setTimeout(res, ms));
}
