// src/widgets/Voting/EmergencyVoteAlert.tsx

import React, { useEffect, useState } from 'react'
import { useTelemetry } from '@/shared/hooks/useTelemetry'
import { useAlertContext } from '@/shared/context/AlertContext'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { useAuditLogger } from '@/shared/hooks/useAuditLogger'
import { AlertTriangle } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'
import { motion, AnimatePresence } from 'framer-motion'
import { Spinner } from '@/shared/components/Spinner'
import { EmergencyModal } from '@/widgets/Voting/EmergencyModal'

interface EmergencyVoteData {
  id: string
  title: string
  reason: string
  severity: 'critical' | 'high' | 'medium'
  timestamp: number
  triggeredBy: string
}

export const EmergencyVoteAlert: React.FC = () => {
  const { theme } = useTheme()
  const { fetchAlertData } = useAlertContext()
  const { verifyZKProof } = useZKAuth()
  const [alertData, setAlertData] = useState<EmergencyVoteData | null>(null)
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const logAudit = useAuditLogger()
  const telemetry = useTelemetry()

  useEffect(() => {
    const load = async () => {
      try {
        const zkValid = await verifyZKProof({ purpose: 'emergency_vote_access' })
        if (!zkValid) return

        const data = await fetchAlertData()
        if (data?.active) {
          setAlertData(data)
          telemetry.track('emergency_vote_triggered', { id: data.id, severity: data.severity })
        }
      } catch (e) {
        console.error('Emergency alert load error', e)
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [])

  const openModal = () => {
    if (!alertData) return
    setModalOpen(true)
    logAudit({
      event: 'emergency_vote_alert_viewed',
      userId: 'auto', // or from context
      timestamp: Date.now(),
      metadata: { alertId: alertData.id }
    })
  }

  const closeModal = () => setModalOpen(false)

  if (loading) {
    return (
      <div className="flex justify-center items-center h-32">
        <Spinner />
      </div>
    )
  }

  return (
    <AnimatePresence>
      {alertData && (
        <motion.div
          key="emergency-alert"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          className={cn(
            'border-l-4 p-4 rounded-lg shadow-md cursor-pointer transition-all',
            alertData.severity === 'critical'
              ? 'bg-red-50 border-red-500 text-red-800 dark:bg-red-900 dark:text-white'
              : alertData.severity === 'high'
              ? 'bg-yellow-50 border-yellow-500 text-yellow-800 dark:bg-yellow-900 dark:text-white'
              : 'bg-blue-50 border-blue-500 text-blue-800 dark:bg-blue-900 dark:text-white'
          )}
          onClick={openModal}
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 flex-shrink-0" />
            <div className="flex-1">
              <p className="font-semibold text-sm uppercase">Экстренное голосование</p>
              <p className="text-sm font-medium">{alertData.title}</p>
              <p className="text-xs opacity-70">Причина: {alertData.reason}</p>
            </div>
            <div className="text-xs opacity-50">
              {new Date(alertData.timestamp).toLocaleTimeString()}
            </div>
          </div>
        </motion.div>
      )}

      {modalOpen && alertData && (
        <EmergencyModal data={alertData} isOpen={modalOpen} onClose={closeModal} />
      )}
    </AnimatePresence>
  )
}
