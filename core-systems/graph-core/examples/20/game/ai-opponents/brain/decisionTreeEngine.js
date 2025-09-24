// decisionTreeEngine.js
// Промышленный AI-модуль: улучшено консиллиумом из 20 агентов и 3 метагенералов

import { BehaviorProfile } from '../data/aiProfiles.json'
import { logDecision, monitorBranch } from '../../monitoring/aiLogger'
import { getCurrentGameState } from '../../core/gameStateProvider'

export class DecisionTreeEngine {
    constructor(agentId, profile = 'default') {
        this.agentId = agentId
        this.root = null
        this.currentNode = null
        this.stateContext = {}
        this.behaviorProfile = BehaviorProfile[profile] || BehaviorProfile['default']
        this.diagnostics = []
        this.interruptQueue = []
        this.maxDepth = 32
    }

    setTree(rootNode) {
        this.root = rootNode
        this.currentNode = rootNode
    }

    async evaluate(gameSnapshot) {
        if (!this.root) return
        this.stateContext = { ...gameSnapshot }
        this.diagnostics = []
        this.interruptQueue = []

        try {
            await this.traverse(this.root, 0)
        } catch (e) {
            console.error(`[AI-${this.agentId}] DecisionTree evaluation error:`, e)
        }
    }

    async traverse(node, depth) {
        if (depth > this.maxDepth) {
            console.warn(`[AI-${this.agentId}] Max decision depth exceeded`)
            return
        }

        if (!node || typeof node.condition !== 'function') return

        const result = await node.condition(this.stateContext)
        this.logNode(node, result, depth)

        if (result && node.trueBranch) {
            await this.traverse(node.trueBranch, depth + 1)
        } else if (!result && node.falseBranch) {
            await this.traverse(node.falseBranch, depth + 1)
        }

        if (typeof node.action === 'function' && result) {
            await node.action(this.agentId, this.stateContext)
        }
    }

    queueInterrupt(node) {
        if (node && typeof node.condition === 'function') {
            this.interruptQueue.push(node)
        }
    }

    async evaluateInterrupts() {
        for (const node of this.interruptQueue) {
            const result = await node.condition(this.stateContext)
            if (result && node.action) {
                await node.action(this.agentId, this.stateContext)
                logDecision(this.agentId, 'Interrupt Executed', node.name)
            }
        }
    }

    logNode(node, result, depth) {
        const log = {
            agentId: this.agentId,
            node: node.name || 'UnnamedNode',
            result,
            depth,
            timestamp: Date.now(),
        }
        this.diagnostics.push(log)
        monitorBranch(log)
    }

    getDiagnostics() {
        return [...this.diagnostics]
    }

    reset() {
        this.currentNode = this.root
        this.stateContext = {}
        this.diagnostics = []
        this.interruptQueue = []
    }
}

// Example Node structure
export function createNode(name, conditionFn, actionFn = null, trueBranch = null, falseBranch = null) {
    return {
        name,
        condition: conditionFn,
        action: actionFn,
        trueBranch,
        falseBranch
    }
}
