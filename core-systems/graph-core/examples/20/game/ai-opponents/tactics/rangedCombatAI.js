// rangedCombatAI.js
// Промышленный AI-модуль дальнего боя: укрытие, траектория, прицеливание, тактика

import { getPlayerPosition } from '../../engine/spatialUtils.js'
import { evaluateThreat } from '../brain/threatEvaluator.js'
import { getAgentMemory } from '../perception/eventMemory.js'
import { findCoverNear, isLineOfFireClear, calculateBallisticPath } from '../../engine/combatUtils.js'
import { setAgentState } from '../states/aiStateManager.js'

const FIRING_RANGE = 35.0
const REPOSITION_INTERVAL_MS = 6000
const SHOOT_COOLDOWN_MS = 1500
const PRECISION_FACTOR = 0.85
const RETREAT_THRESHOLD = 0.25  // HP

export class RangedCombatAI {
    constructor(agent) {
        this.agent = agent
        this.lastShotTime = 0
        this.lastRepositionTime = 0
    }

    update(deltaTime) {
        const playerPos = getPlayerPosition()
        const distance = this.agent.getDistanceTo(playerPos)

        if (distance > FIRING_RANGE) {
            setAgentState(this.agent.id, 'chase')
            return
        }

        if (this.agent.health < this.agent.maxHealth * RETREAT_THRESHOLD) {
            setAgentState(this.agent.id, 'retreat')
            return
        }

        this._evaluateCover(playerPos)

        if (this._canShoot() && isLineOfFireClear(this.agent.position, playerPos)) {
            this._shoot(playerPos)
        }

        if (this._needsReposition()) {
            this._reposition(playerPos)
        }
    }

    _canShoot() {
        return Date.now() - this.lastShotTime >= SHOOT_COOLDOWN_MS
    }

    _needsReposition() {
        return Date.now() - this.lastRepositionTime >= REPOSITION_INTERVAL_MS
    }

    _evaluateCover(playerPos) {
        if (!this.agent.isInCover()) {
            const coverPos = findCoverNear(this.agent.position, playerPos)
            if (coverPos) {
                this.agent.moveTo(coverPos)
                this.agent.takeCover(coverPos)
                this._logEvent('cover_acquired', { coverPos })
            }
        }
    }

    _shoot(targetPos) {
        const memory = getAgentMemory(this.agent.id)
        const threat = evaluateThreat(this.agent, targetPos)
        const precision = PRECISION_FACTOR * (1 - threat)

        const path = calculateBallisticPath(this.agent.position, targetPos, this.agent.weapon, precision)
        this.agent.playAnimation('shoot')
        this.agent.fireWeapon(path)
        this.lastShotTime = Date.now()

        memory.remember({
            type: 'ranged_attack',
            data: { targetPos, path },
            threat,
            timestamp: Date.now()
        })
    }

    _reposition(playerPos) {
        const flankOffset = this.agent.getFlankVector(playerPos)
        const newPos = this.agent.position.add(flankOffset.scale(5.0))

        if (this.agent.canMoveTo(newPos)) {
            this.agent.moveTo(newPos)
            this._logEvent('reposition', { newPos })
            this.lastRepositionTime = Date.now()
        }
    }

    _logEvent(type, data) {
        const memory = getAgentMemory(this.agent.id)
        memory.remember({
            type: `ranged_${type}`,
            data,
            agentPosition: { ...this.agent.position },
            targetPosition: getPlayerPosition(),
            timestamp: Date.now()
        })
    }
}
