// retreatState.js
// Промышленный FSM-модуль: умное отступление с анализом угроз, укрытием и тревогой

import { getAgentPosition, moveToTarget, stopMovement } from '../../engine/navigationController.js'
import { findNearestCover } from '../tactics/coverPlanner.js'
import { getVisibleEntities, isEntityHostile } from '../perception/visionSensor.js'
import { computeThreatLevel } from '../brain/threatEvaluator.js'
import { sendDistressSignal } from '../tactics/squadCoordinator.js'
import { setAgentState } from './aiStateManager.js'

const MAX_RETREAT_TIME = 8000
const REEVALUATION_INTERVAL = 2000
const MIN_SAFE_DISTANCE = 15

export default {
    name: 'retreat',

    onEnter(agentId, context) {
        const currentPosition = getAgentPosition(agentId)
        const hostiles = getVisibleEntities(agentId).filter(isEntityHostile)

        const mostDangerous = hostiles.sort((a, b) => {
            return computeThreatLevel(b, agentId) - computeThreatLevel(a, agentId)
        })[0]

        const retreatPoint = findNearestCover(currentPosition, mostDangerous?.position || null)
        if (!retreatPoint) return { nextState: 'panic' }

        context.retreat = {
            startTime: Date.now(),
            targetPosition: retreatPoint,
            reevaluationTime: 0,
            originalThreat: mostDangerous
        }

        moveToTarget(agentId, retreatPoint)
        sendDistressSignal(agentId, retreatPoint)
    },

    onUpdate(agentId, context) {
        const now = Date.now()
        const retreat = context.retreat
        if (!retreat) return { nextState: 'patrol' }

        const currentPos = getAgentPosition(agentId)

        // Время истекло
        if (now - retreat.startTime > MAX_RETREAT_TIME) {
            stopMovement(agentId)
            return { nextState: 'recover' }
        }

        // Проверка расстояния до угрозы
        const currentHostiles = getVisibleEntities(agentId).filter(isEntityHostile)
        const closestHostile = currentHostiles.reduce((closest, h) => {
            const dist = distance(currentPos, h.position)
            return dist < closest.dist ? { dist, h } : closest
        }, { dist: Infinity, h: null })

        if (closestHostile.dist >= MIN_SAFE_DISTANCE) {
            stopMovement(agentId)
            return { nextState: 'cover', from: closestHostile.h }
        }

        // Переоценка точки укрытия каждые 2 сек
        if (now - retreat.reevaluationTime > REEVALUATION_INTERVAL) {
            const newCover = findNearestCover(currentPos, closestHostile.h?.position)
            if (newCover && distance(currentPos, newCover) > 1.5) {
                moveToTarget(agentId, newCover)
                retreat.targetPosition = newCover
            }
            retreat.reevaluationTime = now
        }

        return null
    },

    onExit(agentId, context) {
        stopMovement(agentId)
        delete context.retreat
    }
}

function distance(a, b) {
    const dx = a[0] - b[0]
    const dy = a[1] - b[1]
    const dz = a[2] - b[2]
    return Math.sqrt(dx * dx + dy * dy + dz * dz)
}
