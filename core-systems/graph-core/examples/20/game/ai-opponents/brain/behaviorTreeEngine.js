// behaviorTreeEngine.js
// Промышленный BT-движок: разработано консиллиумом из 20 агентов и 3 метагенералов

import { getCurrentGameState } from '../../core/gameStateProvider'
import { logBTExecution } from '../../monitoring/aiLogger'

export const Status = {
    SUCCESS: 'success',
    FAILURE: 'failure',
    RUNNING: 'running',
    INTERRUPTED: 'interrupted',
}

class BTNode {
    constructor(name) {
        this.name = name
        this.children = []
        this.parent = null
    }

    async tick(agent, blackboard) {
        throw new Error(`tick not implemented for ${this.constructor.name}`)
    }

    addChild(node) {
        node.parent = this
        this.children.push(node)
    }

    log(agent, status) {
        logBTExecution(agent.id, {
            node: this.name,
            type: this.constructor.name,
            status,
            timestamp: Date.now(),
        })
    }
}

// ====== Leaf Nodes ======

class ActionNode extends BTNode {
    constructor(name, actionFn) {
        super(name)
        this.actionFn = actionFn
    }

    async tick(agent, blackboard) {
        const status = await this.actionFn(agent, blackboard)
        this.log(agent, status)
        return status
    }
}

class ConditionNode extends BTNode {
    constructor(name, conditionFn) {
        super(name)
        this.conditionFn = conditionFn
    }

    async tick(agent, blackboard) {
        const result = await this.conditionFn(agent, blackboard)
        const status = result ? Status.SUCCESS : Status.FAILURE
        this.log(agent, status)
        return status
    }
}

// ====== Control Flow Nodes ======

class SelectorNode extends BTNode {
    async tick(agent, blackboard) {
        for (const child of this.children) {
            const result = await child.tick(agent, blackboard)
            this.log(agent, result)
            if (result === Status.SUCCESS || result === Status.RUNNING) {
                return result
            }
        }
        return Status.FAILURE
    }
}

class SequenceNode extends BTNode {
    async tick(agent, blackboard) {
        for (const child of this.children) {
            const result = await child.tick(agent, blackboard)
            this.log(agent, result)
            if (result === Status.FAILURE) {
                return Status.FAILURE
            }
            if (result === Status.RUNNING) {
                return Status.RUNNING
            }
        }
        return Status.SUCCESS
    }
}

class ParallelNode extends BTNode {
    constructor(name, successThreshold = 1) {
        super(name)
        this.successThreshold = successThreshold
    }

    async tick(agent, blackboard) {
        const results = await Promise.all(this.children.map(child => child.tick(agent, blackboard)))
        const successes = results.filter(r => r === Status.SUCCESS).length
        const status = successes >= this.successThreshold ? Status.SUCCESS : Status.FAILURE
        this.log(agent, status)
        return status
    }
}

class InverterNode extends BTNode {
    constructor(name, child) {
        super(name)
        this.addChild(child)
    }

    async tick(agent, blackboard) {
        const result = await this.children[0].tick(agent, blackboard)
        const status = result === Status.SUCCESS ? Status.FAILURE : Status.SUCCESS
        this.log(agent, status)
        return status
    }
}

// ====== Tree Executor ======

export class BehaviorTree {
    constructor(rootNode) {
        this.root = rootNode
    }

    async tick(agent, blackboard) {
        if (!this.root) return Status.FAILURE
        const result = await this.root.tick(agent, blackboard)
        return result
    }
}

// ====== Builder Helpers ======

export const BTFactory = {
    action: (name, fn) => new ActionNode(name, fn),
    condition: (name, fn) => new ConditionNode(name, fn),
    selector: name => new SelectorNode(name),
    sequence: name => new SequenceNode(name),
    parallel: (name, threshold) => new ParallelNode(name, threshold),
    inverter: (name, child) => new InverterNode(name, child),
}
