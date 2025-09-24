/**
 * ghostPrediction.js
 * Промышленный модуль предсказания позиций и состояний AI-противников в условиях сетевого лага.
 * Поддерживает интерполяцию, экстраполяцию, сглаживание, rollback и ghost shadow sync.
 */

export class GhostPredictor {
  constructor({ latencyBuffer = 100, maxPredictionTime = 250, smoothing = true }) {
    this.bufferTime = latencyBuffer;        // Задержка в мс для интерполяции (history lag)
    this.maxPrediction = maxPredictionTime; // Макс. экстраполяция в мс
    this.smoothing = smoothing;

    this.stateHistory = new Map(); // entityId -> [{timestamp, state}]
    this.ghostStates = new Map();  // entityId -> current ghost
  }

  /**
   * Сохраняем новое состояние от сети
   */
  registerRemoteState(entityId, state, timestamp = Date.now()) {
    if (!this.stateHistory.has(entityId)) {
      this.stateHistory.set(entityId, []);
    }

    const history = this.stateHistory.get(entityId);
    history.push({ timestamp, state });
    while (history.length > 60) history.shift(); // ограничение на 60 кадров истории
  }

  /**
   * Вызывается каждый кадр, чтобы обновить позиции "теней"
   */
  updateGhost(entityId, currentTime = Date.now()) {
    const history = this.stateHistory.get(entityId);
    if (!history || history.length < 2) return null;

    const targetTime = currentTime - this.bufferTime;

    let prev, next;
    for (let i = history.length - 1; i >= 1; i--) {
      if (history[i - 1].timestamp <= targetTime && history[i].timestamp >= targetTime) {
        prev = history[i - 1];
        next = history[i];
        break;
      }
    }

    if (prev && next) {
      // Интерполяция
      const t = (targetTime - prev.timestamp) / (next.timestamp - prev.timestamp);
      const interpolated = this.interpolateState(prev.state, next.state, t);
      return this.commitGhost(entityId, interpolated);
    }

    // Экстраполяция
    const [last, beforeLast] = history.slice(-2);
    const dt = last.timestamp - beforeLast.timestamp;
    if (dt === 0 || currentTime - last.timestamp > this.maxPrediction) return null;

    const velocity = this.estimateVelocity(beforeLast.state, last.state, dt);
    const dtPredict = currentTime - last.timestamp;
    const extrapolated = this.extrapolateState(last.state, velocity, dtPredict);

    return this.commitGhost(entityId, extrapolated);
  }

  /**
   * Интерполяция между двумя состояниями
   */
  interpolateState(a, b, t) {
    return {
      position: {
        x: a.position.x + (b.position.x - a.position.x) * t,
        y: a.position.y + (b.position.y - a.position.y) * t,
        z: a.position.z + (b.position.z - a.position.z) * t,
      },
      rotation: {
        yaw: this.lerpAngle(a.rotation.yaw, b.rotation.yaw, t),
        pitch: this.lerpAngle(a.rotation.pitch, b.rotation.pitch, t),
      },
      ...this.mergeAdditional(a, b, t)
    };
  }

  /**
   * Прогнозирование на основе скорости
   */
  extrapolateState(state, velocity, dt) {
    return {
      position: {
        x: state.position.x + velocity.x * dt / 1000,
        y: state.position.y + velocity.y * dt / 1000,
        z: state.position.z + velocity.z * dt / 1000,
      },
      rotation: { ...state.rotation },
      ...state // дополнительные поля
    };
  }

  estimateVelocity(a, b, dt) {
    return {
      x: (b.position.x - a.position.x) / (dt / 1000),
      y: (b.position.y - a.position.y) / (dt / 1000),
      z: (b.position.z - a.position.z) / (dt / 1000),
    };
  }

  lerpAngle(a, b, t) {
    let delta = b - a;
    while (delta > 180) delta -= 360;
    while (delta < -180) delta += 360;
    return a + delta * t;
  }

  mergeAdditional(a, b, t) {
    return {
      health: a.health + (b.health - a.health) * t,
      animationFrame: Math.round(a.animationFrame + (b.animationFrame - a.animationFrame) * t)
    };
  }

  /**
   * Сохраняет текущее предсказание
   */
  commitGhost(entityId, predictedState) {
    const prev = this.ghostStates.get(entityId);
    if (this.smoothing && prev) {
      predictedState.position = {
        x: prev.position.x + (predictedState.position.x - prev.position.x) * 0.4,
        y: prev.position.y + (predictedState.position.y - prev.position.y) * 0.4,
        z: prev.position.z + (predictedState.position.z - prev.position.z) * 0.4,
      };
    }
    this.ghostStates.set(entityId, predictedState);
    return predictedState;
  }

  /**
   * Получить текущее предсказанное состояние
   */
  getGhostState(entityId) {
    return this.ghostStates.get(entityId) || null;
  }

  clear(entityId) {
    this.stateHistory.delete(entityId);
    this.ghostStates.delete(entityId);
  }

  resetAll() {
    this.stateHistory.clear();
    this.ghostStates.clear();
  }
}
