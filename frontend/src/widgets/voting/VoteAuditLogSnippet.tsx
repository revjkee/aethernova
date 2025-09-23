// src/widgets/Voting/VoteAuditLogSnippet.tsx

import React, { useEffect, useState } from 'react'
import { useAuditLog } from '@/services/auditLogService'
import { useZKAuth } from '@/shared/hooks/useZKAuth'
import { Spinner } from '@/shared/components/Spinner'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/shared/utils/classNames'
import { ShieldCheck, Clock } from 'lucide-react'
import { useTheme } from '@/shared/hooks/useTelegramTheme'

interface VoteAuditEntry {
  id: string
  user: string
  action: string
  choice: string
  proposalId: string
  timestamp: number
  signature: string
  valid: boolean
}

interface Props {
  userId: string
  limit?: number
}

export const VoteAuditLogSnippet: React.FC<Props> = ({ userId, limit = 10 }) => {
  const [entries, setEntries] = useState<VoteAuditEntry[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { verifyZKProof } = useZKAuth()
  const { fetchAuditLog } = useAuditLog()
  const { theme } = useTheme()

  useEffect(() => {
    const loadAudit = async () => {
      setLoading(true)
      setError(null)

      try {
        const zkVerified = await verifyZKProof({ purpose: 'audit_log_access', userId })
        if (!zkVerified) {
          setError('Доступ к логу отклонён ZK-валидатором.')
          setLoading(false)
          return
        }

        const data = await fetchAuditLog(userId, limit)
        setEntries(data)
      } catch (e) {
        setError('Ошибка при загрузке журнала голосований.')
      } finally {
        setLoading(false)
      }
    }

    loadAudit()
  }, [userId, limit, verifyZKProof, fetchAuditLog])

  if (loading) {
    return (
      <div className="flex justify-center items-center h-24">
        <Spinner />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center text-sm text-red-500">{error}</div>
    )
  }

  if (!entries || entries.length === 0) {
    return (
      <div className="text-center text-sm text-gray-500 dark:text-gray-400">
        Нет зафиксированных действий по голосованию.
      </div>
    )
  }

  return (
    <div
      className={cn(
        'p-4 rounded-lg border shadow-md text-sm',
        theme === 'dark' ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'
      )}
    >
      <h3 className="font-semibold text-center mb-4">Журнал голосований</h3>

      <ul className="space-y-3">
        <AnimatePresence initial={false}>
          {entries.map(entry => (
            <motion.li
              key={entry.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.25 }}
              className={cn(
                'p-3 rounded-md border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2',
                entry.valid
                  ? 'border-green-500 bg-green-50 dark:bg-green-900 text-green-800 dark:text-white'
                  : 'border-red-500 bg-red-50 dark:bg-red-900 text-red-800 dark:text-white'
              )}
            >
              <div className="flex flex-col">
                <span className="font-medium">Пользователь: {entry.user}</span>
                <span className="text-xs">Голос: {entry.choice} (по предложению {entry.proposalId})</span>
              </div>

              <div className="flex flex-col sm:items-end">
                <span className="text-xs flex items-center gap-1">
                  <Clock className="w-4 h-4" />
                  {new Date(entry.timestamp).toLocaleString()}
                </span>
                <span className="text-xs flex items-center gap-1 mt-1">
                  <ShieldCheck className="w-4 h-4" />
                  {entry.valid ? 'Подпись подтверждена' : 'Неверная подпись'}
                </span>
              </div>
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </div>
  )
}
