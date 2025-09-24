import React, { useEffect, useState } from 'react'
import { Lock, ShieldCheck, AlertTriangle, RefreshCcw } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'
import { useSecureSessionStore } from '@/store/privacy/sessionStore'
import { useHeartbeat } from '@/shared/hooks/useHeartbeat'
import { Tooltip } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { formatDistanceToNow } from 'date-fns'
import { motion } from 'framer-motion'

interface EncryptedSessionInfoProps {
  className?: string
}

export const EncryptedSessionInfo: React.FC<EncryptedSessionInfoProps> = ({ className }) => {
  const {
    encryptionStatus,
    sessionStartTime,
    sessionId,
    encryptionStrength,
    protocol,
    fingerprint,
    lastValidated,
    validateSession,
  } = useSecureSessionStore()

  const [validating, setValidating] = useState(false)
  const [lastPing, setLastPing] = useState<Date | null>(null)

  useHeartbeat(() => setLastPing(new Date()), 15000)

  const handleManualValidation = async () => {
    setValidating(true)
    try {
      await validateSession()
    } finally {
      setValidating(false)
    }
  }

  return (
    <motion.div
      className={cn(
        'rounded-xl border bg-white dark:bg-neutral-900 shadow-lg p-5 space-y-4',
        className
      )}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {encryptionStatus === 'secured' ? (
            <ShieldCheck className="text-green-600 w-6 h-6" />
          ) : (
            <AlertTriangle className="text-yellow-500 w-6 h-6" />
          )}
          <div>
            <h4 className="text-lg font-semibold">
              {encryptionStatus === 'secured'
                ? 'Сессия защищена'
                : 'Шифрование не подтверждено'}
            </h4>
            <p className="text-sm text-muted-foreground">
              Протокол: {protocol} — Сила: {encryptionStrength} бит
            </p>
          </div>
        </div>
        <div>
          <Tooltip content="Повторная валидация">
            <button
              onClick={handleManualValidation}
              disabled={validating}
              className="p-2 hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded-md transition"
            >
              <RefreshCcw className="w-5 h-5 text-muted-foreground" />
            </button>
          </Tooltip>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">ID сессии</span>
          <div className="font-mono text-sm truncate">{sessionId}</div>
        </div>
        <div>
          <span className="text-muted-foreground">Fingerprint</span>
          <div className="font-mono text-sm truncate">{fingerprint}</div>
        </div>
        <div>
          <span className="text-muted-foreground">Начало сессии</span>
          <div>
            {sessionStartTime
              ? formatDistanceToNow(new Date(sessionStartTime), { addSuffix: true })
              : '—'}
          </div>
        </div>
        <div>
          <span className="text-muted-foreground">Последняя проверка</span>
          <div>
            {lastValidated
              ? formatDistanceToNow(new Date(lastValidated), { addSuffix: true })
              : '—'}
          </div>
        </div>
        <div>
          <span className="text-muted-foreground">Heartbeat</span>
          <Badge variant="outline">
            {lastPing
              ? formatDistanceToNow(lastPing, { addSuffix: true })
              : 'нет сигнала'}
          </Badge>
        </div>
      </div>

      <div className="flex justify-end">
        <Badge variant="success" className="flex items-center gap-1">
          <Lock className="w-4 h-4" /> ZK-Validated
        </Badge>
      </div>
    </motion.div>
  )
}

export default EncryptedSessionInfo
