// chaseState.js
// Промышленная реализация: динамическое преследование с предсказанием, укрытиями и переключением стратегий

import { getAgentPosition, moveToTarget, isAtTarget, stopMovement } from '../../engine/navigationController.js'
import { getVisibleEntities, isEntityHostile } from '../perception/visionSensor.js'
import { predictTargetPosition } from '../brain/predictionModel.js'
import { getCoverPointsNearby } from '../tactics/coverPlanner.js'
import { computeThreatLevel } from '../brain/threatEvaluator.js'
import { setAgentState } from './aiStateManager.js'

const MAX_CHASE_TIME = 10000
const MIN_DISTANCE_TO_TARGET = 1.5
const LOS_RECHECK_INTERVAL = 2000

export default {
    name: 'chase',

    onEnter(agentId, context) {
        const target = context.lastSeenEnemy
        if (!target) return { nextState: 'patrol' }

        context.chase = {
            target,
            startTime: Date.now(),
            lastSeenPos: target.position,
            lastLOSCheck: 0
        }

        const predicted = predictTargetPosition(target)
        moveToTarget(agentId, predicted)
    },

    onUpdate(agentId, context) {
        const chase = context.chase
        if (!chase || !chase.target) return { nextState: 'patrol' }

        const now = Date.now()

        // Прекращаем погоню после таймаута
        if (now - chase.startTime > MAX_CHASE_TIME) {
            stopMovement(agentId)
            return { nextState: 'search', lastKnown: chase.lastSeenPos }
        }

        // Проверка видимости цели
        if (now - chase.lastLOSCheck > LOS_RECHECK_INTERVAL) {
            const visibles = getVisibleEntities(agentId)
            const found = visibles.find(e => e.id === chase.target.id)

            if (found) {
                chase.lastSeenPos = found.position
                const dist = distance(getAgentPosition(agentId), found.position)

                if (dist <= MIN_DISTANCE_TO_TARGET) {
                    stopMovement(agentId)
                    return { nextState: 'attack', target: found }
                }

                const predicted = predictTargetPosition(found)
                moveToTarget(agentId, predicted)
            } else {
                // Потеря цели, переходим в поиск
                stopMovement(agentId)
                return { nextState: 'search', lastKnown: chase.lastSeenPos }
            }

            chase.lastLOSCheck = now
        }

        return null
    },

    onExit(agentId, context) {
        stopMovement(agentId)
        delete context.chase
    }
}

// Вспомогательная функция
function distance(a, b) {
    const dx = a[0] - b[0]
    const dy = a[1] - b[1]
    const dz = a[2] - b[2]
    return Math.sqrt(dx * dx + dy * dy + dz * dz)
}
