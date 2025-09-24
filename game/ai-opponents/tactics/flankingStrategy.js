// flankingStrategy.js
// Промышленный модуль обхода и перехвата цели с использованием динамического предсказания

import { getPlayerPosition, getPlayerVelocity } from '../../engine/spatialUtils.js'
import { isLineOfSightClear, findFlankPath, getCoverScore } from '../../engine/combatUtils.js'
import { setAgentState } from '../states/aiStateManager.js'
import { getAgentMemory } from '../perception/eventMemory.js'

const FLANK_DISTANCE = 7.5
const INTERCEPT_RANGE = 4.0
const MAX_RETRY_PATH = 3
const MIN_COVER_SCORE = 0.4

export class FlankingStrategy {
    constructor(agent) {
        this.agent = agent
        this.memory = getAgentMemory(agent.id)
        this.lastFlankSuccess = false
    }

    update() {
        const playerPos = getPlayerPosition()
        const playerVel = getPlayerVelocity()
        const predictedPos = playerPos.add(playerVel.scale(0.7))  // предсказание позиции

        if (this._shouldIntercept(predictedPos)) {
            this._intercept(predictedPos)
            return
        }

        const flankPath = this._findBestFlank(predictedPos)
        if (flankPath) {
            this.agent.followPath(flankPath)
            this.memory.remember({
                type: 'flank_attempt',
                target: predictedPos,
                success: true,
                timestamp: Date.now()
            })
            setAgentState(this.agent.id, 'flank')
            this.lastFlankSuccess = true
        } else {
            this.lastFlankSuccess = false
            setAgentState(this.agent.id, 'fallback')
        }
    }

    _shouldIntercept(predictedPos) {
        const distance = this.agent.getDistanceTo(predictedPos)
        const coverScore = getCoverScore(this.agent.position)
        return (
            distance < INTERCEPT_RANGE &&
            isLineOfSightClear(this.agent.position, predictedPos) &&
            coverScore >= MIN_COVER_SCORE
        )
    }

    _intercept(predictedPos) {
        this.agent.aimAt(predictedPos)
        this.agent.fireWeapon()
        setAgentState(this.agent.id, 'engage')
        this.memory.remember({
            type: 'intercept_fire',
            target: predictedPos,
            timestamp: Date.now()
        })
    }

    _findBestFlank(targetPos) {
        for (let attempt = 0; attempt < MAX_RETRY_PATH; attempt++) {
            const flankPath = findFlankPath(this.agent.position, targetPos, FLANK_DISTANCE)
            if (flankPath && this._isPathValid(flankPath)) {
                return flankPath
            }
        }
        return null
    }

    _isPathValid(path) {
        const lastPoint = path[path.length - 1]
        const visibility = isLineOfSightClear(lastPoint, getPlayerPosition())
        const cover = getCoverScore(lastPoint)
        return visibility && cover >= MIN_COVER_SCORE
    }
}
