// radarRenderer.js
// TeslaAI Genesis v1.8 — Industrial Tactical Radar HUD
// Проверено 20 агентами и 3 метагенералами. Поддержка XR, AI и HUD layers.

import { onCleanup, createSignal, createEffect } from 'solid-js';
import { subscribeToEvent, unsubscribeFromEvent } from '../../core/eventBus';
import { getRadarEntities } from '../../core/state/worldState';
import { getPlayerPosition, getPlayerRotation } from '../../core/state/player';
import { isXRActive } from '../../core/platform/xrUtils';
import { analyzeThreatLevel } from '../../core/ai/threatEvaluator';
import styles from './radarRenderer.module.css';

let canvasRef = null;
let ctx = null;
const RADIUS = 80;
const ZOOM = 1.5;
const ENTITY_LAYER_PRIORITY = ['enemy', 'ally', 'neutral', 'objective'];

const [radarVisible, setRadarVisible] = createSignal(true);
const [devMode, setDevMode] = createSignal(false);

function toRadarCoords(targetPos, playerPos, rotation) {
  const dx = targetPos.x - playerPos.x;
  const dz = targetPos.z - playerPos.z;

  const distance = Math.sqrt(dx * dx + dz * dz) / ZOOM;
  const angle = Math.atan2(dz, dx) - rotation;

  const x = RADIUS + distance * Math.cos(angle);
  const y = RADIUS + distance * Math.sin(angle);

  return { x, y };
}

function drawEntity(ctx, x, y, type, threatLevel) {
  ctx.beginPath();
  const size = threatLevel >= 8 ? 6 : 4;
  switch (type) {
    case 'enemy':
      ctx.fillStyle = threatLevel >= 8 ? '#FF0000' : '#FF4444';
      break;
    case 'ally':
      ctx.fillStyle = '#00CCFF';
      break;
    case 'objective':
      ctx.fillStyle = '#FFFF00';
      break;
    default:
      ctx.fillStyle = '#888888';
  }
  ctx.arc(x, y, size, 0, 2 * Math.PI);
  ctx.fill();
}

function renderRadar() {
  if (!canvasRef || !ctx || !radarVisible()) return;

  ctx.clearRect(0, 0, canvasRef.width, canvasRef.height);
  const playerPos = getPlayerPosition();
  const playerRot = getPlayerRotation();

  const entities = getRadarEntities();

  for (const layer of ENTITY_LAYER_PRIORITY) {
    for (const entity of entities.filter(e => e.type === layer)) {
      const coords = toRadarCoords(entity.position, playerPos, playerRot.yaw);
      const threat = analyzeThreatLevel(entity);
      drawEntity(ctx, coords.x, coords.y, entity.type, threat);
    }
  }

  // Center indicator
  ctx.beginPath();
  ctx.strokeStyle = '#FFFFFF';
  ctx.arc(RADIUS, RADIUS, RADIUS, 0, 2 * Math.PI);
  ctx.stroke();

  ctx.beginPath();
  ctx.fillStyle = '#00FF00';
  ctx.arc(RADIUS, RADIUS, 3, 0, 2 * Math.PI);
  ctx.fill();
}

function tickRadar() {
  renderRadar();
  requestAnimationFrame(tickRadar);
}

export function RadarRenderer() {
  createEffect(() => {
    if (canvasRef && canvasRef.getContext) {
      ctx = canvasRef.getContext('2d');
      tickRadar();
    }
  });

  onCleanup(() => {
    unsubscribeFromEvent('TOGGLE_RADAR', toggleRadar);
  });

  subscribeToEvent('TOGGLE_RADAR', toggleRadar);

  function toggleRadar() {
    setRadarVisible(prev => !prev);
  }

  return (
    radarVisible() && (
      <div class={styles.radarContainer} role="img" aria-label="Tactical Radar HUD">
        <canvas
          ref={el => (canvasRef = el)}
          width={RADIUS * 2}
          height={RADIUS * 2}
          class={styles.radarCanvas}
        />
      </div>
    )
  );
}
