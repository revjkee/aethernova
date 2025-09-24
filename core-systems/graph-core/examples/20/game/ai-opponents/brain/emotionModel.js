// emotionModel.js
// Индустриальный эмоциональный движок ИИ (20x enhancement — TeslaAI Genesis Standard)

import { clamp } from '../../utils/mathUtils'
import { logEmotionChange } from '../../monitoring/aiLogger'

const EMOTION_NAMES = ['fear', 'anger', 'joy', 'surprise', 'disgust', 'trust', 'anticipation', 'sadness']

const DEFAULT_PARAMS = {
    decayRate: 0.005,               // Естественное затухание
    intensityMultiplier: 1.0,       // Коэффициент усиления реакции
    maxLevel: 1.0,                  // Максимум эмоции
    minLevel: 0.0,                  // Минимум
}

export class EmotionModel {
    constructor(agentId, config = {}) {
        this.agentId = agentId
        this.params = { ...DEFAULT_PARAMS, ...config }
        this.state = new Map()
        EMOTION_NAMES.forEach(name => this.state.set(name, 0.0))
        this.lastEvent = null
    }

    getEmotion(name) {
        return this.state.get(name) || 0.0
    }

    getDominantEmotion() {
        let maxVal = -Infinity
        let dominant = null
        for (const [name, value] of this.state.entries()) {
            if (value > maxVal) {
                maxVal = value
                dominant = name
            }
        }
        return { emotion: dominant, intensity: maxVal }
    }

    injectEvent(event) {
        this.lastEvent = event
        for (const [emotion, delta] of Object.entries(this.mapEventToEmotionDelta(event))) {
            const prev = this.state.get(emotion) || 0.0
            const updated = clamp(
                prev + delta * this.params.intensityMultiplier,
                this.params.minLevel,
                this.params.maxLevel
            )
            this.state.set(emotion, updated)
            logEmotionChange(this.agentId, emotion, prev, updated, event)
        }
    }

    decayEmotions(deltaTime = 1) {
        for (const [emotion, value] of this.state.entries()) {
            const decayed = Math.max(this.params.minLevel, value - this.params.decayRate * deltaTime)
            this.state.set(emotion, decayed)
        }
    }

    mapEventToEmotionDelta(event) {
        // Событие: {type, severity, source}
        const deltas = {}

        switch (event.type) {
            case 'damage':
                deltas.fear = 0.4 * event.severity
                deltas.anger = 0.5 * event.severity
                deltas.sadness = 0.2 * event.severity
                break

            case 'enemy_killed':
                deltas.joy = 0.6
                deltas.trust = 0.3
                deltas.anticipation = -0.2
                break

            case 'ally_killed':
                deltas.sadness = 0.7
                deltas.anger = 0.3
                break

            case 'surprise_attack':
                deltas.surprise = 0.9
                deltas.fear = 0.6
                break

            case 'safe_zone_entered':
                deltas.trust = 0.5
                deltas.joy = 0.3
                deltas.fear = -0.3
                break

            case 'trapped':
                deltas.fear = 0.8
                deltas.anger = 0.4
                break

            default:
                break
        }

        return deltas
    }

    applyToBlackboard(blackboard) {
        // Пример: влияем на стиль боя
        const { emotion, intensity } = this.getDominantEmotion()
        blackboard.set('dominantEmotion', emotion)
        blackboard.set('emotionIntensity', intensity)
        blackboard.set('isPanicking', emotion === 'fear' && intensity > 0.7)
    }

    reset() {
        EMOTION_NAMES.forEach(name => this.state.set(name, 0.0))
    }
}

// ===== Utils (если нет в проекте) =====

export function getEmotionColor(emotionName) {
    const colorMap = {
        joy: '#fdd835',
        fear: '#0288d1',
        anger: '#d32f2f',
        sadness: '#512da8',
        trust: '#388e3c',
        surprise: '#ff7043',
        anticipation: '#ffa000',
        disgust: '#6d4c41',
    }
    return colorMap[emotionName] || '#cccccc'
}
