// soundSensor.js
// Промышленный AI-модуль слухового восприятия: радиус, направление, затухание, приоритеты

import { getDistance3D, normalizeVector, dotProduct } from '../../utils/vectorMath'
import { isObstructed } from '../../world/obstacleChecker'
import { logSoundDetection } from '../../monitoring/aiLogger'
import { updateMemorySoundEvent } from '../data/eventMemory'

const DEFAULT_HEARING_RADIUS = 25
const DIRECTIONALITY_THRESHOLD = 0.3  // Косинус угла, насколько направлен звук
const MIN_AUDIBLE_POWER = 0.2         // Порог слышимости

export class SoundSensor {
    constructor(agentId, environment, config = {}) {
        this.agentId = agentId
        this.env = environment
        this.hearingRadius = config.hearingRadius || DEFAULT_HEARING_RADIUS
        this.directionalSensitivity = config.directionalSensitivity || 0.8
        this.memory = config.memory !== false  // По умолчанию активна память звуков
    }

    processSoundEvent(soundEvent) {
        const agent = this.env.getAgentById(this.agentId)
        if (!agent) return false

        const { sourceId, position, power, direction, type } = soundEvent
        const dist = getDistance3D(agent.position, position)
        if (dist > this.hearingRadius) return false

        // Затухание звука
        const attenuation = 1 - (dist / this.hearingRadius)
        if (attenuation * power < MIN_AUDIBLE_POWER) return false

        // Направление восприятия
        const dirToSound = normalizeVector(position, agent.position)
        const angleFactor = dotProduct(agent.forward, dirToSound)

        // Препятствия
        const blocked = isObstructed(position, agent.position, this.env)
        if (blocked) return false

        const directionalScore = angleFactor * this.directionalSensitivity
        const detectionConfidence = attenuation * (directionalScore + 1) / 2

        if (detectionConfidence < MIN_AUDIBLE_POWER) return false

        logSoundDetection(this.agentId, {
            sourceId,
            position,
            type,
            confidence: detectionConfidence.toFixed(2)
        })

        if (this.memory) {
            updateMemorySoundEvent(this.agentId, {
                sourceId,
                position,
                type,
                timestamp: Date.now(),
                confidence: detectionConfidence
            })
        }

        return {
            sourceId,
            position,
            type,
            confidence: detectionConfidence
        }
    }

    scanRecentSoundEvents() {
        const recentSounds = this.env.getRecentSoundEvents()
        const detections = []

        for (const event of recentSounds) {
            const result = this.processSoundEvent(event)
            if (result) detections.push(result)
        }

        return detections.sort((a, b) => b.confidence - a.confidence)
    }

    getMostRelevantSound() {
        const sounds = this.scanRecentSoundEvents()
        return sounds.length > 0 ? sounds[0] : null
    }
}
