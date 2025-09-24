// meleeCombatAI.js
// Промышленная AI-система ближнего боя с уклонениями, анализом, контратакой и приоритетами

import { getAgentMemory } from '../perception/eventMemory.js'
import { getDistance, isInLineOfSight, getPlayerPosition } from '../../engine/spatialUtils.js'
import { evaluateThreat } from '../brain/threatEvaluator.js'
import { setAgentState } from '../states/aiStateManager.js'

const MELEE_RANGE = 2.5  // метра
const ATTACK_COOLDOWN_MS = 1800
const EVADE_CHANCE = 0.35
const CRITICAL_HIT_CHANCE = 0.1

export class MeleeCombatAI {
    constructor(agent) {
        this.agent = agent
        this.lastAttackTime = 0
    }

    update(deltaTime) {
        const playerPos = getPlayerPosition()
        const distToPlayer = getDistance(this.agent.position, playerPos)

        if (distToPlayer > MELEE_RANGE || !isInLineOfSight(this.agent, playerPos)) {
            setAgentState(this.agent.id, 'chase')
            return
        }

        if (this._canAttack()) {
            const threatLevel = evaluateThreat(this.agent, playerPos)
            const shouldEvade = Math.random() < EVADE_CHANCE * threatLevel
            if (shouldEvade) {
                this._evade()
            } else {
                this._attack(playerPos)
            }
        } else {
            this._circlePlayer(playerPos, deltaTime)
        }
    }

    _canAttack() {
        return Date.now() - this.lastAttackTime >= ATTACK_COOLDOWN_MS
    }

    _attack(targetPos) {
        const isCritical = Math.random() < CRITICAL_HIT_CHANCE
        const damage = isCritical ? this.agent.stats.meleeDamage * 2 : this.agent.stats.meleeDamage
        this._logEvent('attack', { isCritical, damage })

        this.agent.playAnimation('melee_attack', { speed: 1.15 })
        this.agent.dealDamageToTarget(damage)
        this.lastAttackTime = Date.now()
    }

    _evade() {
        const directions = ['left', 'right', 'back']
        const dir = directions[Math.floor(Math.random() * directions.length)]

        this.agent.performEvade(dir)
        this._logEvent('evade', { direction: dir })
    }

    _circlePlayer(playerPos, deltaTime) {
        const angle = Math.sin(Date.now() / 500) * 1.5
        this.agent.moveInCircleAround(playerPos, angle, deltaTime)
    }

    _logEvent(type, data) {
        const memory = getAgentMemory(this.agent.id)
        memory.remember({
            type: `melee_${type}`,
            data,
            agentPosition: { ...this.agent.position },
            targetPosition: getPlayerPosition()
        })
    }
}
