// src/widgets/XAI/AgentCausalChain.tsx

import React, { useState, useEffect } from 'react'
import { useXAIContext } from '@/shared/context/XAIContext'
import { fetchCausalChain, CausalLink } from '@/services/xai/causalityService'
import { GraphCanvas, GraphEdge, GraphNode } from '@/shared/ui/GraphCanvas'
import { Panel } from '@/shared/ui/Panel'
import { Skeleton } from '@/shared/ui/Skeleton'
import { EventDetailModal } from './EventDetailModal'
import { getColorByCausalityWeight, formatCausalLabel } from '@/shared/utils/causalUtils'
import './AgentCausalChain.css'

interface AgentCausalChainProps {
  agentId: string
  taskId: string
}

export const AgentCausalChain: React.FC<AgentCausalChainProps> = ({ agentId, taskId }) => {
  const { triggerGlobalAlert } = useXAIContext()
  const [links, setLinks] = useState<CausalLink[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)

  useEffect(() => {
    const loadChain = async () => {
      try {
        const data = await fetchCausalChain(agentId, taskId)
        setLinks(data)
      } catch (err) {
        triggerGlobalAlert('Ошибка при загрузке причинной цепочки', 'error')
      } finally {
        setLoading(false)
      }
    }
    loadChain()
  }, [agentId, taskId, triggerGlobalAlert])

  const nodes: GraphNode[] = Array.from(
    new Set(links.flatMap(link => [link.source, link.target]))
  ).map(id => ({
    id,
    label: formatCausalLabel(id),
    type: 'state',
    onClick: () => setSelectedNodeId(id)
  }))

  const edges: GraphEdge[] = links.map(link => ({
    id: `${link.source}->${link.target}`,
    source: link.source,
    target: link.target,
    label: `${(link.weight * 100).toFixed(1)}%`,
    color: getColorByCausalityWeight(link.weight),
    dashed: link.type === 'indirect'
  }))

  return (
    <Panel title="Причинно-следственная цепочка агента">
      {loading ? (
        <Skeleton height={420} />
      ) : (
        <GraphCanvas nodes={nodes} edges={edges} height={420} />
      )}
      {selectedNodeId && (
        <EventDetailModal
          nodeId={selectedNodeId}
          onClose={() => setSelectedNodeId(null)}
        />
      )}
    </Panel>
  )
}
