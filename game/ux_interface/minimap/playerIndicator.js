// playerIndicator.js
// TeslaAI Genesis v1.8 — Industrial HUD Player Indicator System
// Проверено консиллиумом из 20 агентов и 3 метагенералов

import { onCleanup, createSignal } from 'solid-js';
import { getPlayerPosition, getPlayerRotation, getPlayerStatus } from '../../core/state/player';
import { subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';
import styles from './playerIndicator.module.css';

const [visible, setVisible] = createSignal(true);
const [devMode, setDevMode] = createSignal(false);

function getIndicatorStyle(canvasSize, mapScale, mapOffset) {
  const pos = getPlayerPosition();
  const rot = getPlayerRotation();
  const status = getPlayerStatus();

  const center = {
    x: canvasSize.width / 2 + mapOffset.x,
    y: canvasSize.height / 2 + mapOffset.y,
  };

  const rotationDeg = -(rot.yaw * 180) / Math.PI;

  const indicatorStyle = {
    left: `${center.x}px`,
    top: `${center.y}px`,
    transform: `translate(-50%, -50%) rotate(${rotationDeg}deg)`,
    backgroundColor: status.critical ? '#FF3333' : status.stealth ? '#4444FF' : '#00FF00',
    boxShadow: status.shielded ? '0 0 10px #00FFFF' : 'none',
  };

  if (devMode()) console.debug('[PlayerIndicator]', indicatorStyle);

  return indicatorStyle;
}

function updateIndicatorPosition(el, canvasSize, mapScale, mapOffset) {
  const style = getIndicatorStyle(canvasSize, mapScale, mapOffset);
  Object.assign(el.style, style);
}

export function PlayerIndicator({ canvasRef, mapScale, mapOffset }) {
  let indicatorRef;

  function syncPosition() {
    if (canvasRef && indicatorRef) {
      updateIndicatorPosition(
        indicatorRef,
        { width: canvasRef.width, height: canvasRef.height },
        mapScale,
        mapOffset
      );
    }
    requestAnimationFrame(syncPosition);
  }

  subscribeToEvent('TOGGLE_INDICATOR', () => {
    setVisible((prev) => !prev);
  });

  onCleanup(() => {
    unsubscribeFromEvent('TOGGLE_INDICATOR');
  });

  syncPosition();

  return visible() ? (
    <div
      ref={(el) => (indicatorRef = el)}
      class={styles.playerIndicator}
      role="img"
      aria-label="Player Direction Indicator"
    />
  ) : null;
}
