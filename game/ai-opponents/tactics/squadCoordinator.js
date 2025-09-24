// squadCoordinator.js
// Промышленная система координации отряда ИИ-противников

import { getSharedMemory, broadcastToSquad } from '../data/memoryCache.js'
import { getPlayerPosition } from '../../engine/spatialUtils.js'
import { setAgentState } from '../states/aiStateManager.js'
import { findCoverNear } from '../../engine/combatUtils.js'

const ROLES = ['leader', 'flanker', 'support', 'sniper', 'reserver']
const FORMATION_DISTANCE = 5.0
const COMM_INTERVAL_MS = 1200

export class SquadCoordinator {
    constructor(squadId, agents) {
        this.squadId = squadId
        this.agents = agents
        this.roleMap = {}
        this.lastCommTime = 0
        this.sharedMemory = getSharedMemory(squadId)
        this._assignRoles()
    }

    _assignRoles() {
        this.agents.forEach((agent, index) => {
            const role = ROLES[index % ROLES.length]
            this.roleMap[agent.id] = role
            agent.setMeta('role', role)
        })
    }

    update() {
        const now = Date.now()
        const playerPos = getPlayerPosition()

        this.agents.forEach(agent => {
            const role = this.roleMap[agent.id]
            switch (role) {
                case 'leader':
                    this._executeLeader(agent, playerPos)
                    break
                case 'flanker':
                    this._executeFlanker(agent, playerPos)
                    break
                case 'support':
                    this._executeSupport(agent)
                    break
                case 'sniper':
                    this._executeSniper(agent, playerPos)
                    break
                case 'reserver':
                    this._holdInReserve(agent)
                    break
            }
        })

        if (now - this.lastCommTime > COMM_INTERVAL_MS) {
            this._broadcastStatus()
            this.lastCommTime = now
        }
    }

    _executeLeader(agent, playerPos) {
        const coverPos = findCoverNear(agent.position, playerPos)
        if (coverPos) {
            agent.moveTo(coverPos)
            agent.takeCover(coverPos)
        }
        setAgentState(agent.id, 'alert')
        this.sharedMemory.set('target', playerPos)
    }

    _executeFlanker(agent, playerPos) {
        const flankVector = agent.getFlankVector(playerPos)
        const targetPos = playerPos.add(flankVector.scale(FORMATION_DISTANCE))
        if (agent.canMoveTo(targetPos)) {
            agent.moveTo(targetPos)
            setAgentState(agent.id, 'chase')
        }
    }

    _executeSupport(agent) {
        const leader = this._getAgentByRole('leader')
        if (leader) {
            const offset = leader.getSupportOffset()
            const pos = leader.position.add(offset)
            agent.moveTo(pos)
            agent.cover(leader)
            setAgentState(agent.id, 'support')
        }
    }

    _executeSniper(agent, playerPos) {
        const snipePos = findCoverNear(agent.position, playerPos, true) // prefers high ground
        if (snipePos) {
            agent.moveTo(snipePos)
            agent.enterSniperMode(snipePos)
            setAgentState(agent.id, 'snipe')
        }
    }

    _holdInReserve(agent) {
        const safeZone = agent.findSafeZoneBehind()
        if (safeZone) {
            agent.moveTo(safeZone)
            setAgentState(agent.id, 'reserve')
        }
    }

    _getAgentByRole(role) {
        return this.agents.find(agent => this.roleMap[agent.id] === role)
    }

    _broadcastStatus() {
        const stateReport = this.agents.map(agent => ({
            id: agent.id,
            position: agent.position,
            health: agent.health,
            role: this.roleMap[agent.id],
            state: agent.getCurrentState()
        }))
        broadcastToSquad(this.squadId, { type: 'status_update', data: stateReport })
    }
}
