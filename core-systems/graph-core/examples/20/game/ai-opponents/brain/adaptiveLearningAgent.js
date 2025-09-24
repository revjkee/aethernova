// adaptiveLearningAgent.js
// RL-агент с адаптивным поведением для AI-противников (уровень TeslaAI Genesis 20x)

import { randomChoice } from '../../utils/mathUtils'
import { logRLAction, logRLStateChange } from '../../monitoring/aiLogger'
import { loadProfileConfig } from '../data/aiProfiles'

export class AdaptiveLearningAgent {
    constructor(agentId, environment, profileName = 'default') {
        this.agentId = agentId
        this.env = environment                  // Интерфейс среды: getState(), getActions(), applyAction()
        this.profile = loadProfileConfig(profileName)

        // RL-параметры
        this.qTable = new Map()
        this.learningRate = this.profile.learningRate || 0.1
        this.discountFactor = this.profile.discountFactor || 0.9
        this.epsilon = this.profile.epsilon || 0.2

        this.lastState = null
        this.lastAction = null
    }

    // Кодирует состояние + действие в строку
    encode(state, action) {
        return `${JSON.stringify(state)}::${action}`
    }

    // Получить Q-значение
    getQ(state, action) {
        return this.qTable.get(this.encode(state, action)) || 0
    }

    // Установить Q-значение
    setQ(state, action, value) {
        this.qTable.set(this.encode(state, action), value)
    }

    // Выбор действия (ε-greedy)
    chooseAction(state) {
        const actions = this.env.getAvailableActions(state)
        if (Math.random() < this.epsilon) {
            return randomChoice(actions)
        }

        let maxQ = -Infinity
        let bestActions = []
        for (const action of actions) {
            const q = this.getQ(state, action)
            if (q > maxQ) {
                maxQ = q
                bestActions = [action]
            } else if (q === maxQ) {
                bestActions.push(action)
            }
        }
        return randomChoice(bestActions)
    }

    // Обновление Q-значения после действия
    learn(reward, newState) {
        if (this.lastState === null || this.lastAction === null) return

        const oldQ = this.getQ(this.lastState, this.lastAction)
        const futureQs = this.env.getAvailableActions(newState)
            .map(a => this.getQ(newState, a))
        const maxFutureQ = futureQs.length > 0 ? Math.max(...futureQs) : 0

        const newQ = oldQ + this.learningRate * (reward + this.discountFactor * maxFutureQ - oldQ)
        this.setQ(this.lastState, this.lastAction, newQ)

        logRLStateChange(this.agentId, this.lastState, this.lastAction, reward, newQ)
    }

    // Основной шаг обучения
    step() {
        const currentState = this.env.getState(this.agentId)
        const action = this.chooseAction(currentState)
        const result = this.env.applyAction(this.agentId, action)

        this.learn(result.reward, result.newState)
        this.lastState = currentState
        this.lastAction = action

        logRLAction(this.agentId, currentState, action, result.reward)
    }

    // Применение знаний к blackboard
    exportToBlackboard(blackboard) {
        blackboard.set(`agent_${this.agentId}_qTableSize`, this.qTable.size)
        blackboard.set(`agent_${this.agentId}_lastAction`, this.lastAction)
    }

    reset() {
        this.qTable.clear()
        this.lastState = null
        this.lastAction = null
    }
}
