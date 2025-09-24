// proximitySensor.js
// Промышленный AI-модуль пространственного восприятия ближнего радиуса

import { getDistance3D } from '../../utils/vectorMath'
import { isVisibleDirectly } from '../../world/obstacleChecker'
import { logProximityDetection } from '../../monitoring/aiLogger'
import { updateMemoryProximityEvent } from '../data/eventMemory'

const DEFAULT_SCAN_RADIUS = 8.0
const DEFAULT_RESOLUTION = 0.5  // Точность (интервал сканирования по сетке)
const ENTITY_TYPES = ['trap', 'enemy', 'cover', 'loot', 'hazard']

export class ProximitySensor {
    constructor(agentId, environment, config = {}) {
        this.agentId = agentId
        this.env = environment
        this.scanRadius = config.scanRadius || DEFAULT_SCAN_RADIUS
        this.resolution = config.resolution || DEFAULT_RESOLUTION
        this.includeInvisible = config.includeInvisible || false
        this.memory = config.memory !== false
    }

    scanArea() {
        const agent = this.env.getAgentById(this.agentId)
        if (!agent) return []

        const objects = this.env.getNearbyObjects(agent.position, this.scanRadius)
        const detected = []

        for (const obj of objects) {
            if (!ENTITY_TYPES.includes(obj.type)) continue

            const dist = getDistance3D(agent.position, obj.position)
            if (dist > this.scanRadius) continue

            const visible = isVisibleDirectly(agent.position, obj.position, this.env)
            if (!visible && !this.includeInvisible) continue

            const detection = {
                id: obj.id,
                type: obj.type,
                distance: dist,
                visible,
                position: obj.position,
                metadata: obj.metadata || {}
            }

            detected.push(detection)

            if (this.memory) {
                updateMemoryProximityEvent(this.agentId, {
                    ...detection,
                    timestamp: Date.now()
                })
            }

            logProximityDetection(this.agentId, detection)
        }

        return detected.sort((a, b) => a.distance - b.distance)
    }

    detectSpecific(type) {
        return this.scanArea().filter(obj => obj.type === type)
    }

    detectTraps() {
        return this.detectSpecific('trap')
    }

    detectHazards() {
        return this.detectSpecific('hazard')
    }

    detectCover() {
        return this.detectSpecific('cover')
    }

    detectEnemies() {
        return this.detectSpecific('enemy')
    }
}
