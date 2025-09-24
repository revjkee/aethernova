/**
 * index.js
 * Центральный хаб для управления AI-модулями противников в игре.
 * Обеспечивает инициализацию, обновление и маршрутизацию состояний.
 */

import { GhostPredictor } from './networking/ghostPrediction.js';
import { AISyncProtocol } from './networking/aiSyncProtocol.js';

import { updateMeleeCombat } from './tactics/meleeCombatAI.js';
import { updateRangedCombat } from './tactics/rangedCombatAI.js';

import { handlePatrolState, FSMManager } from './states/aiStateManager.js';

import { ProximitySensor } from './perception/proximitySensor.js';
import { SoundSensor } from './perception/soundSensor.js';
import { EventMemory } from './perception/eventMemory.js';

import { loadAIProfiles } from './data/aiProfiles.js';
import { loadSquadPresets } from './data/squadPresets.js';
import { AICache } from './data/memoryCache.js';

// === Глобальные инстансы ===
const aiEntities = new Map();         // entityId -> entityData
const ghostPredictor = new GhostPredictor({});
const syncProtocol = new AISyncProtocol();

const aiFSMs = new Map();             // entityId -> FSMManager
const sensors = new Map();           // entityId -> { proximity, sound }
const memories = new Map();          // entityId -> EventMemory

const aiProfiles = await loadAIProfiles();
const squadPresets = await loadSquadPresets();
const memoryCache = new AICache();

/**
 * Регистрация новой AI-сущности
 */
export function registerAIEntity(entityId, config = {}) {
  const profile = aiProfiles[config.profile || 'default'] || aiProfiles.default;

  aiEntities.set(entityId, {
    id: entityId,
    profile,
    squadId: config.squadId || null,
    health: 100,
    position: { x: 0, y: 0, z: 0 },
    rotation: { yaw: 0, pitch: 0 },
  });

  aiFSMs.set(entityId, new FSMManager(entityId));
  sensors.set(entityId, {
    proximity: new ProximitySensor(entityId),
    sound: new SoundSensor(entityId)
  });
  memories.set(entityId, new EventMemory(entityId));

  syncProtocol.registerEntity(entityId);
  ghostPredictor.registerRemoteState(entityId, aiEntities.get(entityId));
}

/**
 * Основной update, вызываемый каждый кадр
 */
export function updateAIEntities(deltaTime, currentTime = Date.now()) {
  for (const [entityId, entity] of aiEntities) {
    // 1. Обновление предсказаний
    const predicted = ghostPredictor.updateGhost(entityId, currentTime);
    if (predicted) Object.assign(entity, predicted);

    // 2. Обновление сенсоров
    const sensorPack = sensors.get(entityId);
    sensorPack.proximity.update(entity);
    sensorPack.sound.update(entity);

    // 3. Обновление памяти
    const memory = memories.get(entityId);
    memory.update(sensorPack, entity);

    // 4. FSM переходы
    const fsm = aiFSMs.get(entityId);
    fsm.evaluate(memory, entity);

    // 5. Выполнение поведения
    const currentState = fsm.getCurrentState();
    switch (currentState) {
      case 'PATROL':
        handlePatrolState(entity, memory, deltaTime);
        break;
      case 'ATTACK_MELEE':
        updateMeleeCombat(entity, memory, deltaTime);
        break;
      case 'ATTACK_RANGED':
        updateRangedCombat(entity, memory, deltaTime);
        break;
      default:
        break;
    }

    // 6. Синхронизация по сети
    syncProtocol.syncState(entityId, entity, currentTime);
    memoryCache.save(entityId, entity); // для отладки и повторов
  }
}

/**
 * Очистка и сброс
 */
export function clearAIEntities() {
  aiEntities.clear();
  aiFSMs.clear();
  sensors.clear();
  memories.clear();
  memoryCache.resetAll();
  ghostPredictor.resetAll();
  syncProtocol.resetAll();
}

/**
 * Получить состояние AI по ID
 */
export function getAIState(entityId) {
  return aiEntities.get(entityId) || null;
}
