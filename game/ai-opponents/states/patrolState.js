// patrolState.js
// Промышленный AI-модуль патрулирования с динамикой маршрутов и реакцией на окружение

import { getPathById, sampleRandomPatrolPath } from '../data/patrolRoutes.js'
import { moveToTarget, isAtTarget } from '../../engine/navigationController.js'
import { getVisibleEntities, isEntityHostile } from '../perception/visionSensor.js'
import { setAgentState } from './aiStateManager.js'
import { getCurrentTime } from '../../engine/timeUtils.js'

const WAIT_DURATION_MS = 1000
const PATROL_REEVALUATION_INTERVAL = 15000

export default {
    name: 'patrol',

    onEnter(agentId, context) {
        const path = sampleRandomPatrolPath(agentId)
        context.patrol = {
            path,
            index: 0,
            lastEval: getCurrentTime()
        }

        const target = path[0]
        moveToTarget(agentId, target)
    },

    onUpdate(agentId, context) {
        const patrol = context.patrol
        if (!patrol || patrol.path.length === 0) return

        const currentTarget = patrol.path[patrol.index]
        if (isAtTarget(agentId, currentTarget)) {
            patrol.index = (patrol.index + 1) % patrol.path.length
            moveToTarget(agentId, patrol.path[patrol.index])
        }

        // Переоценка маршрута с возможностью изменения
        if (getCurrentTime() - patrol.lastEval > PATROL_REEVALUATION_INTERVAL) {
            const newPath = sampleRandomPatrolPath(agentId)
            if (newPath && newPath.length > 0) {
                patrol.path = newPath
                patrol.index = 0
                moveToTarget(agentId, newPath[0])
            }
            patrol.lastEval = getCurrentTime()
        }

        // Реакция на врагов в поле зрения
        const visibles = getVisibleEntities(agentId)
        for (const entity of visibles) {
            if (isEntityHostile(entity)) {
                context.lastSeenEnemy = entity
                return { nextState: 'alert' }
            }
        }

        return null
    },

    onExit(agentId, context) {
        delete context.patrol
    }
}
