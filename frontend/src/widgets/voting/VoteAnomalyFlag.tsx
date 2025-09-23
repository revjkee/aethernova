// src/widgets/Voting/VoteAnomalyFlag.tsx

import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useAnomalyScanner } from '@/services/anomalyService'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useAuditLogger } from '@/shared/hooks/useAuditLogger'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { AlertTriangle, ShieldOff, EyeOff, Clock } from 'lucide-react'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'

interface Props {
  userId: string
  proposalId: string
}

interface AnomalyFlag {
  code: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  timestamp: number
  detectedBy: string
  zkProof: string
}

export const VoteAnomalyFlag: React.FC<Props> = ({ userId, proposalId }) => {
  const { theme } = useTheme()
  const [flags, setFlags] = useState<AnomalyFlag[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const { verifyZKProof } = useZKAuth()
  const { fetchAnomalies } = useAnomalyScanner()
  const audit = useAuditLogger()

  useEffect(() => {
    const loadFlags = async () => {
      try {
        const zkVerified = await verifyZKProof({ userId, purpose: 'vote_anomaly_view' })
        if (!zkVerified) {
          setError('Недостаточно прав для просмотра аномалий (ZK отклонено)')
          return
        }

        const data = await fetchAnomalies({ userId, proposalId })

        if (data && data.length > 0) {
          audit({
            event: 'anomaly_flags_viewed',
            userId,
            timestamp: Date.now(),
            metadata: { proposalId, anomalyCount: data.length }
          })
          setFlags(data)
        } else {
          setFlags([])
        }
      } catch (e) {
        setError('Ошибка при получении флагов аномалий')
      } finally {
        setLoading(false)
      }
    }

    loadFlags()
  }, [userId, proposalId, verifyZKProof, fetchAnomalies, audit])

  const severityColor = {
    low: 'text-green-600 dark:text-green-300',
    medium: 'text-yellow-600 dark:text-yellow-300',
    high: 'text-orange-600 dark:text-orange-300',
    critical: 'text-red-600 dark:text-red-300',
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-20">
        <Spinner />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-sm text-center text-red-500">{error}</div>
    )
  }

  if (!flags || flags.length === 0) {
    return null
  }

  return (
    <div
      className={cn(
        'border-l-4 p-4 rounded-md shadow-sm space-y-3',
        theme === 'dark' ? 'bg-red-900 border-red-600' : 'bg-red-50 border-red-500'
      )}
    >
      <h4 className="font-semibold flex items-center gap-2 text-red-700 dark:text-white">
        <AlertTriangle className="w-5 h-5" />
        Обнаружены аномалии голосования
      </h4>

      <ul className="space-y-2">
        <AnimatePresence initial={false}>
          {flags.map((flag, idx) => (
            <motion.li
              key={`${flag.code}-${idx}`}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="text-sm flex flex-col border rounded-md p-3 bg-white/10 dark:bg-black/20"
            >
              <div className="flex items-center justify-between">
                <div className="font-medium">{flag.description}</div>
                <span className={cn('text-xs font-semibold', severityColor[flag.severity])}>
                  {flag.severity.toUpperCase()}
                </span>
              </div>
              <div className="text-xs text-gray-400 mt-1 flex gap-3 items-center">
                <Clock className="w-4 h-4" />
                {new Date(flag.timestamp).toLocaleString()}
                <ShieldOff className="w-4 h-4 ml-2" />
                AI: {flag.detectedBy}
              </div>
              <div className="text-[10px] text-gray-500 mt-1 truncate flex items-center gap-1">
                <EyeOff className="w-3 h-3" />
                zkProof: {flag.zkProof.slice(0, 16)}...
              </div>
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </div>
  )
}
