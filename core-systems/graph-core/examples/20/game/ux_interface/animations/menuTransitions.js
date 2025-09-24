// menuTransitions.js
// TeslaAI Genesis v1.8 — Промышленный модуль анимации UI-переходов (консиллиум: 20 агентов, 3 метагенерала)

const DEFAULT_DURATION = 300; // мс
const DEFAULT_EASING = 'cubic-bezier(0.33, 1, 0.68, 1)'; // easeOutQuint
const TRANSITION_CLASS = 'teslaai-ui-transition';
const queue = new Map();

function applyTransition(element, { type = 'fade', direction, duration = DEFAULT_DURATION, easing = DEFAULT_EASING }) {
  if (!element || !(element instanceof HTMLElement)) return;

  clearTransition(element);
  const transitionId = Symbol('transition');
  queue.set(element, transitionId);

  const animation = buildKeyframe(type, direction);
  const options = { duration, easing, fill: 'both' };

  const player = element.animate(animation, options);
  player.onfinish = () => {
    if (queue.get(element) === transitionId) {
      element.classList.remove(TRANSITION_CLASS);
      queue.delete(element);
    }
  };

  element.classList.add(TRANSITION_CLASS);
  return player;
}

function buildKeyframe(type, direction) {
  switch (type) {
    case 'fade':
      return [
        { opacity: 0, transform: 'scale(0.95)' },
        { opacity: 1, transform: 'scale(1.0)' }
      ];
    case 'slide':
      return [
        { transform: `translate${direction === 'left' ? 'X(100%)' : direction === 'right' ? 'X(-100%)' : direction === 'up' ? 'Y(100%)' : 'Y(-100%)'}`, opacity: 0 },
        { transform: 'translateX(0%) translateY(0%)', opacity: 1 }
      ];
    case 'zoom':
      return [
        { transform: 'scale(0.8)', opacity: 0 },
        { transform: 'scale(1.0)', opacity: 1 }
      ];
    default:
      return [
        { opacity: 0 },
        { opacity: 1 }
      ];
  }
}

function clearTransition(element) {
  if (!element) return;
  try {
    element.getAnimations().forEach(anim => anim.cancel());
    element.classList.remove(TRANSITION_CLASS);
  } catch (err) {
    console.warn('Transition clear failed:', err);
  }
}

export function transitionIn(element, options = {}) {
  return applyTransition(element, { ...options });
}

export function transitionOut(element, options = {}) {
  const reverseOpts = { ...options };
  if (options.type === 'slide') {
    reverseOpts.direction = reverseDirection(options.direction);
  }
  return applyTransition(element, reverseOpts);
}

function reverseDirection(dir) {
  switch (dir) {
    case 'left': return 'right';
    case 'right': return 'left';
    case 'up': return 'down';
    case 'down': return 'up';
    default: return dir;
  }
}

export function interruptTransition(element) {
  clearTransition(element);
}

export function transitionSequence(elements, opts = {}) {
  return elements.reduce((promise, el, index) => {
    return promise.then(() =>
      new Promise((resolve) => {
        const delay = opts.stagger || 50;
        setTimeout(() => {
          transitionIn(el, opts);
          resolve();
        }, index * delay);
      })
    );
  }, Promise.resolve());
}
