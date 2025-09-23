// src/widgets/Voting/VotingSimulationPreview.tsx

import React, { useCallback, useEffect, useState } from 'react'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useLatencyTracker } from '@/shared/hooks/useLatencyTracker'
import { useTelemetry } from '@/shared/hooks/useTelemetry'
import { useVotingSimulation } from '@/services/voteSimulator'
import { motion } from 'framer-motion'
import { SimulationChart } from '@/widgets/Voting/SimulationChart'
import { SimulationImpactTable } from '@/widgets/Voting/SimulationImpactTable'
import { AiSummaryPanel } from '@/widgets/Voting/AiSummaryPanel'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'

interface VotingSimulationPreviewProps {
  proposalId: string
  userId: string
}

export const VotingSimulationPreview: React.FC<VotingSimulationPreviewProps> = ({
  proposalId,
  userId
}) => {
  const { theme } = useTheme()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<any>(null)
  const { verifyZKProof } = useZKAuth()
  const { trackLatency } = useLatencyTracker('VotingSimulation')
  const telemetry = useTelemetry()

  const simulate = useVotingSimulation()

  const loadSimulation = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const zkValid = await verifyZKProof({ userId, purpose: 'vote_simulation_access' })
      if (!zkValid) {
        setError('Доступ к симуляции ограничен.')
        setLoading(false)
        return
      }

      const start = Date.now()
      const result = await simulate(proposalId)
      const latency = Date.now() - start
      trackLatency(latency)
      telemetry.track('vote_simulation_preview_loaded', { proposalId, latency })

      setData(result)
    } catch (e) {
      setError('Ошибка при запуске симуляции голосования.')
    } finally {
      setLoading(false)
    }
  }, [proposalId, userId, verifyZKProof, simulate, trackLatency, telemetry])

  useEffect(() => {
    loadSimulation()
  }, [loadSimulation])

  if (loading) {
    return (
      <div className="flex justify-center items-center h-60">
        <Spinner />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center text-sm text-red-500 py-4">
        {error}
      </div>
    )
  }

  if (!data) return null

  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className={cn(
        'rounded-xl p-4 border shadow-md',
        theme === 'dark' ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'
      )}
    >
      <h2 className="text-xl font-semibold mb-2 text-center">Симуляция исхода голосования</h2>

      <div className="mb-4">
        <AiSummaryPanel insights={data.summary} />
      </div>

      <div className="mb-6">
        <SimulationChart distribution={data.distribution} />
      </div>

      <div>
        <SimulationImpactTable impacts={data.impacts} />
      </div>
    </motion.div>
  )
}
