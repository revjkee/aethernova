// eventMemory.js
// Промышленный AI-модуль краткосрочной памяти для восприятия событий

const MAX_MEMORY_SIZE = 128
const MEMORY_EXPIRATION_MS = 30_000  // 30 секунд
const PRIORITY_WEIGHTS = {
    'enemy_seen': 5,
    'trap_detected': 4,
    'heard_sound': 3,
    'attacked': 6,
    'cover_found': 2,
    'unknown_anomaly': 7
}

class EventMemory {
    constructor(agentId) {
        this.agentId = agentId
        this.events = []
    }

    remember(event) {
        const timestamp = Date.now()
        const record = {
            ...event,
            timestamp,
            id: crypto.randomUUID?.() || `${timestamp}-${Math.random().toString(36).slice(2)}`,
            priority: PRIORITY_WEIGHTS[event.type] || 1
        }

        this.events.push(record)

        if (this.events.length > MAX_MEMORY_SIZE) {
            this.events.sort((a, b) => b.priority - a.priority)
            this.events = this.events.slice(0, MAX_MEMORY_SIZE)
        }

        this._cleanupExpired()
    }

    recall(filterFn = () => true) {
        this._cleanupExpired()
        return this.events.filter(filterFn).sort((a, b) => b.timestamp - a.timestamp)
    }

    recallByType(type) {
        return this.recall(e => e.type === type)
    }

    forget(id) {
        this.events = this.events.filter(e => e.id !== id)
    }

    clear() {
        this.events = []
    }

    _cleanupExpired() {
        const now = Date.now()
        this.events = this.events.filter(e => now - e.timestamp <= MEMORY_EXPIRATION_MS)
    }
}

// Пул для всех агентов
const agentMemories = new Map()

export function getAgentMemory(agentId) {
    if (!agentMemories.has(agentId)) {
        agentMemories.set(agentId, new EventMemory(agentId))
    }
    return agentMemories.get(agentId)
}

export function updateMemoryProximityEvent(agentId, event) {
    const memory = getAgentMemory(agentId)
    memory.remember({ ...event, type: 'proximity' })
}

export function updateMemoryEvent(agentId, type, payload = {}) {
    const memory = getAgentMemory(agentId)
    memory.remember({ type, ...payload })
}

export function recallRecentEvents(agentId, limit = 10) {
    const memory = getAgentMemory(agentId)
    return memory.recall().slice(0, limit)
}

export function forgetAll(agentId) {
    const memory = getAgentMemory(agentId)
    memory.clear()
}
