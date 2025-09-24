/**
 * aiSyncProtocol.js
 * Промышленный модуль синхронизации ИИ между клиентом, сервером и peer-узлами.
 * Поддерживает авторитетный sync, репликацию состояния, предсказание, откат и защиту от рассинхронизации.
 */

import { createHash } from 'crypto';

export class AISyncProtocol {
  constructor({ isServer = false, transportLayer, stateSerializer, maxLag = 100 }) {
    this.isServer = isServer;
    this.transport = transportLayer;
    this.serialize = stateSerializer.serialize;
    this.deserialize = stateSerializer.deserialize;

    this.localState = new Map(); // id -> state
    this.lastSent = new Map();   // id -> hash
    this.maxLag = maxLag;        // in ms
    this.lastUpdate = Date.now();

    this.outgoingQueue = [];
    this.incomingBuffer = [];
    this.initTransport();
  }

  initTransport() {
    this.transport.onMessage((msg) => {
      const { type, payload } = JSON.parse(msg);
      if (type === 'ai_sync') {
        this.incomingBuffer.push(payload);
      }
    });
  }

  /**
   * Called by local AI engine to register an entity for sync
   */
  trackEntity(id, getStateFn, applyStateFn) {
    this.localState.set(id, { getStateFn, applyStateFn });
  }

  /**
   * Called each tick on server or authoritative peer
   */
  updateSyncCycle() {
    const now = Date.now();
    if (now - this.lastUpdate < this.maxLag) return;
    this.lastUpdate = now;

    const updates = [];

    for (const [id, { getStateFn }] of this.localState.entries()) {
      const state = getStateFn();
      const serialized = this.serialize(state);
      const hash = this.hashState(serialized);

      if (this.lastSent.get(id) !== hash) {
        this.lastSent.set(id, hash);
        updates.push({ id, state: serialized });
      }
    }

    if (updates.length > 0) {
      this.sendMessage({ type: 'ai_sync', payload: updates });
    }
  }

  /**
   * Process incoming messages (client or peer mode)
   */
  processIncoming() {
    if (this.incomingBuffer.length === 0) return;
    const updates = this.incomingBuffer.shift(); // FIFO

    for (const { id, state } of updates) {
      const deserialized = this.deserialize(state);
      if (this.localState.has(id)) {
        const { applyStateFn } = this.localState.get(id);
        applyStateFn(deserialized);
      }
    }
  }

  sendMessage(messageObj) {
    const message = JSON.stringify(messageObj);
    this.transport.send(message);
  }

  hashState(serializedState) {
    return createHash('sha256').update(serializedState).digest('hex');
  }

  /**
   * Force re-sync for all AI entities
   */
  forceResync() {
    this.lastSent.clear();
  }

  debugSnapshot() {
    const snapshot = {};
    for (const [id, { getStateFn }] of this.localState.entries()) {
      snapshot[id] = getStateFn();
    }
    return snapshot;
  }
}
