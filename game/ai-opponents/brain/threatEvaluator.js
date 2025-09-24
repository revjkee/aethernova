// threatEvaluator.js
// Анализ боевых угроз и динамическая адаптация поведения AI-оппонента

import { getDistance3D, angleBetweenVectors } from '../../utils/vectorMath'
import { getCoverLevelAt } from '../../world/coverSystem'
import { getAgentMemory } from '../data/memoryCache'
import { logThreatEval } from '../../monitoring/aiLogger'

// Весовые коэффициенты (можно адаптировать из профиля)
const weights = {
    proximity: 1.2,
    weaponPower: 1.5,
    lineOfSight: 1.0,
    coverLevel: -1.0,
    recentDamage: 1.3,
    groupSupport: -0.7,
    flankingRisk: 1.1,
    memoryFear: 0.5
}

export class ThreatEvaluator {
    constructor(agentId, environment) {
        this.agentId = agentId
        this.env = environment
    }

    evaluateThreat(opponentId) {
        const agent = this.env.getAgentById(this.agentId)
        const target = this.env.getAgentById(opponentId)
        const memory = getAgentMemory(this.agentId, opponentId)

        if (!agent || !target) return 0

        const posA = agent.position
        const posT = target.position
        const dist = getDistance3D(posA, posT)
        const los = this.env.hasLineOfSight(posA, posT) ? 1 : 0
        const cover = getCoverLevelAt(posA, posT)
        const weaponPower = target.weapon?.damage || 0
        const support = this.env.getNearbyAllies(opponentId).length
        const flankAngle = angleBetweenVectors(agent.forward, target.position, posA)
        const isFlanked = flankAngle > 120 && flankAngle < 240 ? 1 : 0

        const recentDamage = memory?.recentDamage || 0
        const fear = memory?.fearLevel || 0

        const threatScore =
            weights.proximity * (1 / Math.max(dist, 1)) +
            weights.weaponPower * weaponPower +
            weights.lineOfSight * los +
            weights.coverLevel * cover +
            weights.recentDamage * recentDamage +
            weights.groupSupport * support +
            weights.flankingRisk * isFlanked +
            weights.memoryFear * fear

        logThreatEval(this.agentId, opponentId, threatScore)

        return threatScore
    }

    evaluateAllVisibleThreats() {
        const enemies = this.env.getVisibleEnemies(this.agentId)
        const threats = []

        for (const enemy of enemies) {
            const score = this.evaluateThreat(enemy.id)
            threats.push({ id: enemy.id, threat: score })
        }

        // Сортировка по убыванию угрозы
        threats.sort((a, b) => b.threat - a.threat)
        return threats
    }

    chooseStrategy(threatLevel) {
        if (threatLevel > 20) return 'retreat'
        if (threatLevel > 10) return 'defensive'
        if (threatLevel > 5) return 'aggressive'
        return 'advance'
    }

    getRecommendedStrategy() {
        const topThreats = this.evaluateAllVisibleThreats()
        const cumulative = topThreats.reduce((sum, t) => sum + t.threat, 0)
        return this.chooseStrategy(cumulative)
    }
}
