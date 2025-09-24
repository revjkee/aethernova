// aiStateManager.js
// Промышленный менеджер состояний AI: гибкая FSM с приоритетами и fallback

import { logStateTransition } from '../../logging/aiDebugger.js'
import { getCurrentTime } from '../../engine/timeUtils.js'

const STATE_REGISTRY = new Map()
const STATE_CONTEXT = new Map()

export function defineState(name, { onEnter, onUpdate, onExit, priority = 0 }) {
    if (!name || typeof onUpdate !== 'function') {
        throw new Error(`State "${name}" must have at least an onUpdate() handler`)
    }
    STATE_REGISTRY.set(name, { name, onEnter, onUpdate, onExit, priority })
}

export function setAgentState(agentId, stateName, force = false) {
    const context = _getContext(agentId)
    const next = STATE_REGISTRY.get(stateName)
    if (!next) throw new Error(`Unknown state: ${stateName}`)

    const prev = context.current
    if (!force && prev && prev.name === next.name) return

    if (prev?.onExit) prev.onExit(agentId, context.data)
    if (next.onEnter) next.onEnter(agentId, context.data)

    context.current = next
    context.lastChanged = getCurrentTime()

    logStateTransition(agentId, prev?.name || null, next.name)
}

export function updateAgentState(agentId) {
    const context = _getContext(agentId)
    const state = context.current
    if (!state) return

    const result = state.onUpdate(agentId, context.data)
    if (result?.nextState && STATE_REGISTRY.has(result.nextState)) {
        setAgentState(agentId, result.nextState)
    }
}

export function injectTemporaryState(agentId, tempStateName, durationMs = 3000) {
    const context = _getContext(agentId)
    const original = context.current
    setAgentState(agentId, tempStateName, true)

    setTimeout(() => {
        if (original) setAgentState(agentId, original.name, true)
    }, durationMs)
}

export function getCurrentState(agentId) {
    return _getContext(agentId).current?.name || null
}

export function getAllStates() {
    return Array.from(STATE_REGISTRY.keys())
}

export function clearAgentState(agentId) {
    STATE_CONTEXT.delete(agentId)
}

function _getContext(agentId) {
    if (!STATE_CONTEXT.has(agentId)) {
        STATE_CONTEXT.set(agentId, { current: null, lastChanged: 0, data: {} })
    }
    return STATE_CONTEXT.get(agentId)
}
