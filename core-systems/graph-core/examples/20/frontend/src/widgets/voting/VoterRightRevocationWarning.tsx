// src/widgets/Voting/VoterRightRevocationWarning.tsx

import React, { useEffect, useState } from 'react'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useRevocationRegistry } from '@/services/revocationService'
import { useAuditLogger } from '@/shared/hooks/useAuditLogger'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertOctagon } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'
import { Spinner } from '@/shared/components/Spinner'

interface VoterRightRevocationWarningProps {
  userId: string
}

export const VoterRightRevocationWarning: React.FC<VoterRightRevocationWarningProps> = ({ userId }) => {
  const { theme } = useTheme()
  const [loading, setLoading] = useState(true)
  const [revoked, setRevoked] = useState(false)
  const [reason, setReason] = useState<string | null>(null)
  const [timestamp, setTimestamp] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  const { verifyZKProof } = useZKAuth()
  const audit = useAuditLogger()
  const { fetchRevocation } = useRevocationRegistry()

  useEffect(() => {
    const checkRevocation = async () => {
      setLoading(true)
      setError(null)
      try {
        const zkValid = await verifyZKProof({ userId, purpose: 'revocation_check' })
        if (!zkValid) {
          setError('Ошибка верификации доступа.')
          setLoading(false)
          return
        }

        const data = await fetchRevocation(userId)
        if (data?.revoked) {
          setRevoked(true)
          setReason(data.reason || 'Не указана')
          setTimestamp(data.timestamp)

          audit({
            event: 'voter_right_revoked_viewed',
            userId,
            timestamp: Date.now(),
            metadata: { reason: data.reason }
          })
        }
      } catch (err) {
        setError('Не удалось проверить статус прав.')
      } finally {
        setLoading(false)
      }
    }

    checkRevocation()
  }, [userId, verifyZKProof, fetchRevocation, audit])

  if (loading) {
    return (
      <div className="flex justify-center items-center h-20">
        <Spinner />
      </div>
    )
  }

  if (error || !revoked) return null

  return (
    <AnimatePresence>
      <motion.div
        key="revocation-alert"
        initial={{ opacity: 0, y: -12 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        transition={{ duration: 0.3 }}
        className={cn(
          'p-4 border-l-4 rounded-md shadow-sm text-sm',
          theme === 'dark'
            ? 'bg-red-900 text-white border-red-700'
            : 'bg-red-50 text-red-800 border-red-500'
        )}
      >
        <div className="flex items-center gap-2">
          <AlertOctagon className="w-5 h-5 flex-shrink-0" />
          <div className="flex-1">
            <div className="font-semibold uppercase tracking-wide">Права голоса аннулированы</div>
            <div className="mt-1">Причина: <span className="font-medium">{reason}</span></div>
            {timestamp && (
              <div className="mt-1 text-xs opacity-70">
                Дата: {new Date(timestamp).toLocaleString()}
              </div>
            )}
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  )
}
