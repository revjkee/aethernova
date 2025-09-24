// src/widgets/Voting/VoteConsensusStatus.tsx

import React, { useEffect, useState } from 'react'
import { useConsensusTracker } from '@/services/consensusService'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useLatencyTracker } from '@/shared/hooks/useLatencyTracker'
import { ProgressBar } from '@/shared/components/ProgressBar'
import { Spinner } from '@/shared/components/Spinner'
import { motion } from 'framer-motion'
import { cn } from '@/shared/utils/classNames'
import { ShieldCheck, AlertCircle } from 'lucide-react'

interface VoteConsensusStatusProps {
  proposalId: string
  userId: string
}

interface ConsensusSnapshot {
  yes: number
  no: number
  abstain: number
  totalVotes: number
  quorum: number
  consensusReached: boolean
  updatedAt: number
}

export const VoteConsensusStatus: React.FC<VoteConsensusStatusProps> = ({ proposalId, userId }) => {
  const { theme } = useTheme()
  const [snapshot, setSnapshot] = useState<ConsensusSnapshot | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const { verifyZKProof } = useZKAuth()
  const { fetchConsensusSnapshot } = useConsensusTracker()
  const { trackLatency } = useLatencyTracker('VoteConsensusStatus')

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      try {
        const zkValid = await verifyZKProof({ purpose: 'view_consensus', userId })
        if (!zkValid) {
          setError('Отказано в доступе по ZK-протоколу')
          return
        }

        const start = Date.now()
        const data = await fetchConsensusSnapshot(proposalId)
        trackLatency(Date.now() - start)

        setSnapshot(data)
      } catch (e) {
        setError('Ошибка загрузки статуса консенсуса')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [proposalId, userId, fetchConsensusSnapshot, verifyZKProof, trackLatency])

  if (loading) {
    return (
      <div className="flex justify-center items-center h-24">
        <Spinner />
      </div>
    )
  }

  if (error || !snapshot) {
    return (
      <div className="text-sm text-center text-red-500">{error || 'Ошибка данных'}</div>
    )
  }

  const percentage = Math.round((snapshot.yes / snapshot.totalVotes) * 100)
  const consensusClass = snapshot.consensusReached ? 'text-green-600' : 'text-yellow-500'

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={cn(
        'rounded-xl p-4 border shadow-md',
        theme === 'dark' ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-lg font-semibold">Статус консенсуса</h3>
        <span className={cn('text-xs font-medium flex items-center gap-1', consensusClass)}>
          {snapshot.consensusReached ? (
            <>
              <ShieldCheck className="w-4 h-4" />
              Консенсус достигнут
            </>
          ) : (
            <>
              <AlertCircle className="w-4 h-4" />
              Нет консенсуса
            </>
          )}
        </span>
      </div>

      <ProgressBar
        label="Голоса 'За'"
        value={percentage}
        threshold={snapshot.quorum}
        color={snapshot.consensusReached ? 'green' : 'yellow'}
      />

      <div className="grid grid-cols-3 gap-4 mt-4 text-sm text-gray-700 dark:text-gray-300">
        <div className="flex flex-col">
          <span className="text-xs uppercase text-gray-500">За</span>
          <span className="font-semibold">{snapshot.yes}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-xs uppercase text-gray-500">Против</span>
          <span className="font-semibold">{snapshot.no}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-xs uppercase text-gray-500">Воздержались</span>
          <span className="font-semibold">{snapshot.abstain}</span>
        </div>
      </div>

      <div className="text-xs text-right text-gray-400 mt-2">
        Обновлено: {new Date(snapshot.updatedAt).toLocaleTimeString()}
      </div>
    </motion.div>
  )
}
