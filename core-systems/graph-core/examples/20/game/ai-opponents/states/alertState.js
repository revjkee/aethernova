// alertState.js
// Промышленная FSM-система боевой готовности с реагированием на угрозы и приоритетами

import { getVisibleEntities, isEntityHostile } from '../perception/visionSensor.js'
import { getHeardEntities } from '../perception/soundSensor.js'
import { getRecentEvents } from '../perception/eventMemory.js'
import { moveToTarget, lookAtTarget } from '../../engine/navigationController.js'
import { setAgentState } from './aiStateManager.js'
import { computeThreatLevel } from '../brain/threatEvaluator.js'
import { requestSquadBackup } from '../tactics/squadCoordinator.js'

const ALERT_DURATION_MS = 6000
const THREAT_REASSESS_INTERVAL_MS = 2000

export default {
    name: 'alert',

    onEnter(agentId, context) {
        context.alert = {
            timestamp: Date.now(),
            lastThreatCheck: 0,
            focusedTarget: context.lastSeenEnemy || null,
            previousState: context.previousState || 'patrol'
        }

        if (context.alert.focusedTarget) {
            lookAtTarget(agentId, context.alert.focusedTarget.position)
        }
    },

    onUpdate(agentId, context) {
        const now = Date.now()
        const alert = context.alert

        if (!alert) return { nextState: 'patrol' }

        // Редкий пересчёт угроз
        if (now - alert.lastThreatCheck >= THREAT_REASSESS_INTERVAL_MS) {
            const visibles = getVisibleEntities(agentId)
            const heard = getHeardEntities(agentId)
            const events = getRecentEvents(agentId)

            const all = [...visibles, ...heard, ...events].filter(e => isEntityHostile(e))
            if (all.length > 0) {
                const mostDangerous = all.sort((a, b) => {
                    return computeThreatLevel(b, agentId) - computeThreatLevel(a, agentId)
                })[0]

                alert.focusedTarget = mostDangerous
                moveToTarget(agentId, mostDangerous.position)
                lookAtTarget(agentId, mostDangerous.position)

                requestSquadBackup(agentId, mostDangerous.position)
                alert.lastThreatCheck = now
                alert.timestamp = now
            }
        }

        // Если цель видна — перейти в режим преследования
        if (alert.focusedTarget && isEntityHostile(alert.focusedTarget)) {
            return { nextState: 'chase', target: alert.focusedTarget }
        }

        // Возврат в прошлое состояние по таймеру
        if (now - alert.timestamp > ALERT_DURATION_MS) {
            return { nextState: alert.previousState || 'patrol' }
        }

        return null
    },

    onExit(agentId, context) {
        delete context.alert
    }
}
