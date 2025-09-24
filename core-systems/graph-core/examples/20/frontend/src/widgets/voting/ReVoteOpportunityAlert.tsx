// src/widgets/Voting/ReVoteOpportunityAlert.tsx

import React, { useEffect, useState } from 'react'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useReVoteRegistry } from '@/services/reVoteService'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useAuditLogger } from '@/shared/hooks/useAuditLogger'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertCircle } from 'lucide-react'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'

interface Props {
  userId: string
  proposalId: string
  onReVoteClick: (proposalId: string) => void
}

interface ReVoteStatus {
  available: boolean
  reason: string
  expiresAt: number
  triggeredBy: string
  zkToken: string
}

export const ReVoteOpportunityAlert: React.FC<Props> = ({ userId, proposalId, onReVoteClick }) => {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState<ReVoteStatus | null>(null)
  const { verifyZKProof } = useZKAuth()
  const { getReVoteStatus } = useReVoteRegistry()
  const { theme } = useTheme()
  const audit = useAuditLogger()

  useEffect(() => {
    const loadStatus = async () => {
      setLoading(true)
      try {
        const zkValid = await verifyZKProof({ userId, purpose: 'revote_access' })
        if (!zkValid) {
          setError('Доступ к переголосованию отклонён ZK-механизмом.')
          return
        }

        const res = await getReVoteStatus({ userId, proposalId })
        if (res?.available) {
          setStatus(res)

          audit({
            event: 'revote_alert_shown',
            userId,
            timestamp: Date.now(),
            metadata: {
              proposalId,
              reason: res.reason,
              expiresAt: res.expiresAt
            }
          })
        }
      } catch (e) {
        setError('Ошибка получения данных о возможности переголосовать.')
      } finally {
        setLoading(false)
      }
    }

    loadStatus()
  }, [userId, proposalId, verifyZKProof, getReVoteStatus, audit])

  if (loading) {
    return (
      <div className="flex justify-center items-center h-24">
        <Spinner />
      </div>
    )
  }

  if (error || !status) return null

  return (
    <AnimatePresence>
      {status.available && (
        <motion.div
          key="revote-alert"
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.25 }}
          className={cn(
            'p-4 rounded-md border-l-4 shadow-sm text-sm cursor-pointer transition-all',
            theme === 'dark'
              ? 'bg-yellow-900 border-yellow-600 text-white'
              : 'bg-yellow-50 border-yellow-600 text-yellow-800'
          )}
          onClick={() => onReVoteClick(proposalId)}
        >
          <div className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            <div className="flex-1">
              <p className="font-semibold">Доступно переголосование</p>
              <p className="text-xs opacity-80">
                Причина: {status.reason}
              </p>
              <p className="text-xs opacity-60">
                Истекает: {new Date(status.expiresAt).toLocaleString()}
              </p>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
