// visionSensor.js
// Промышленный модуль обработки визуального восприятия для AI-противников

import { getDistance3D, angleBetweenVectors } from '../../utils/vectorMath'
import { isObstructed } from '../../world/obstacleChecker'
import { getLightingAt } from '../../world/lightingSystem'
import { logPerception } from '../../monitoring/aiLogger'

const DEFAULT_FOV_DEGREES = 120
const DEFAULT_VIEW_DISTANCE = 30
const VISIBILITY_THRESHOLD = 0.4

export class VisionSensor {
    constructor(agentId, environment, config = {}) {
        this.agentId = agentId
        this.env = environment
        this.fov = config.fov || DEFAULT_FOV_DEGREES
        this.viewDistance = config.viewDistance || DEFAULT_VIEW_DISTANCE
        this.lightingSensitivity = config.lightingSensitivity || 0.8
        this.priorityTargetTags = config.priorityTargetTags || ['player', 'hero', 'objective']
    }

    isVisible(target) {
        const agent = this.env.getAgentById(this.agentId)
        const posA = agent.position
        const posT = target.position

        // Расстояние
        const distance = getDistance3D(posA, posT)
        if (distance > this.viewDistance) return false

        // Угол обзора
        const angle = angleBetweenVectors(agent.forward, posT, posA)
        if (angle > this.fov / 2) return false

        // Препятствия
        if (isObstructed(posA, posT, this.env)) return false

        // Освещённость
        const lightLevel = getLightingAt(posT)
        const visibilityFactor = this.calculateVisibility(distance, lightLevel)
        return visibilityFactor >= VISIBILITY_THRESHOLD
    }

    calculateVisibility(distance, lightLevel) {
        const distanceFactor = 1 - (distance / this.viewDistance)
        const lightFactor = Math.min(1, lightLevel / this.lightingSensitivity)
        return 0.6 * distanceFactor + 0.4 * lightFactor
    }

    getVisibleEntities() {
        const allTargets = this.env.getAllAgents().filter(a => a.id !== this.agentId)
        const visible = []

        for (const target of allTargets) {
            if (this.isVisible(target)) {
                visible.push({
                    id: target.id,
                    tag: target.tag,
                    position: target.position,
                    threatLevel: target.weapon?.damage || 0
                })
            }
        }

        logPerception(this.agentId, visible.map(t => t.id))
        return visible
    }

    getPrimaryTarget() {
        const visible = this.getVisibleEntities()
        if (visible.length === 0) return null

        const prioritized = visible.filter(e => this.priorityTargetTags.includes(e.tag))
        if (prioritized.length > 0) {
            return prioritized.sort((a, b) => b.threatLevel - a.threatLevel)[0]
        }

        return visible.sort((a, b) => b.threatLevel - a.threatLevel)[0]
    }
}
