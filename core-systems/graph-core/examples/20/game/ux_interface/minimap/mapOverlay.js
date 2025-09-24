// mapOverlay.js
// TeslaAI Genesis v1.8 — Industrial Dynamic Map Overlay
// Проверено консиллиумом из 20 агентов и 3 метагенералов

import { createSignal, onCleanup } from 'solid-js';
import { subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';
import { getWorldMapData, getVisiblePOIs } from '../../core/state/worldMap';
import { getPlayerPosition } from '../../core/state/player';
import { isXRActive } from '../../core/platform/xrUtils';
import styles from './mapOverlay.module.css';

const [mapVisible, setMapVisible] = createSignal(false);
const [mapScale, setMapScale] = createSignal(1.0);
const [mapOffset, setMapOffset] = createSignal({ x: 0, y: 0 });
const [devMode, setDevMode] = createSignal(false);

function toggleMap() {
  setMapVisible(prev => !prev);
}

function handleWheelZoom(e) {
  const delta = e.deltaY > 0 ? -0.1 : 0.1;
  setMapScale((s) => Math.min(Math.max(s + delta, 0.5), 3.0));
}

function handleDrag(event) {
  // basic drag offset (could be expanded with pan gestures or momentum)
  const dx = event.movementX;
  const dy = event.movementY;
  setMapOffset((prev) => ({
    x: prev.x + dx,
    y: prev.y + dy,
  }));
}

function renderMap(ctx, canvas) {
  const scale = mapScale();
  const offset = mapOffset();
  const player = getPlayerPosition();
  const world = getWorldMapData();
  const pois = getVisiblePOIs();

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.translate(canvas.width / 2 + offset.x, canvas.height / 2 + offset.y);
  ctx.scale(scale, scale);

  // Background map
  ctx.drawImage(world.image, -world.width / 2, -world.height / 2, world.width, world.height);

  // Player marker
  ctx.fillStyle = '#00FF00';
  ctx.beginPath();
  ctx.arc(player.x, player.z, 4, 0, 2 * Math.PI);
  ctx.fill();

  // POIs
  pois.forEach(poi => {
    ctx.fillStyle = poi.type === 'enemy' ? '#FF0000' : '#FFFF00';
    ctx.beginPath();
    ctx.arc(poi.x, poi.z, 3, 0, 2 * Math.PI);
    ctx.fill();
  });

  ctx.restore();
}

function startRenderLoop(canvas) {
  const ctx = canvas.getContext('2d');
  function loop() {
    if (mapVisible()) renderMap(ctx, canvas);
    requestAnimationFrame(loop);
  }
  loop();
}

export function MapOverlay() {
  let canvasEl;

  onCleanup(() => {
    unsubscribeFromEvent('TOGGLE_MAP', toggleMap);
  });

  subscribeToEvent('TOGGLE_MAP', toggleMap);

  return mapVisible() ? (
    <div class={styles.mapContainer} role="region" aria-label="World Map Overlay">
      <canvas
        ref={(el) => {
          canvasEl = el;
          el.width = 512;
          el.height = 512;
          startRenderLoop(el);
        }}
        class={styles.mapCanvas}
        onWheel={handleWheelZoom}
        onMouseDown={(e) => {
          const onMove = (ev) => handleDrag(ev);
          const onUp = () => {
            window.removeEventListener('mousemove', onMove);
            window.removeEventListener('mouseup', onUp);
          };
          window.addEventListener('mousemove', onMove);
          window.addEventListener('mouseup', onUp);
        }}
      />
    </div>
  ) : null;
}
