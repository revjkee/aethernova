import React, { useEffect, useMemo, useState } from 'react'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useThemeSwitcher'
import { motion, AnimatePresence } from 'framer-motion'
import { useWebSocket } from '@/shared/hooks/useSocket'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { CheckCircle, AlertTriangle, XCircle, Clock, Loader2 } from 'lucide-react'
import { HealthStatus, SubsystemHealth } from '@/types/health.types'

const STATUS_ICONS: Record<HealthStatus, React.ReactNode> = {
  healthy: <CheckCircle className="w-4 h-4" />,
  degraded: <AlertTriangle className="w-4 h-4" />,
  offline: <XCircle className="w-4 h-4" />,
  unknown: <Clock className="w-4 h-4" />,
  loading: <Loader2 className="w-4 h-4 animate-spin" />,
}

const STATUS_CLASSES: Record<HealthStatus, string> = {
  healthy: 'bg-green-500 text-white',
  degraded: 'bg-yellow-400 text-black',
  offline: 'bg-red-600 text-white',
  unknown: 'bg-muted text-foreground',
  loading: 'bg-slate-300 text-black',
}

const STATUS_LABELS: Record<HealthStatus, string> = {
  healthy: 'Работает',
  degraded: 'Сбои',
  offline: 'Недоступен',
  unknown: 'Неизвестно',
  loading: 'Обновляется',
}

type Props = {
  subsystemId: string
  size?: 'sm' | 'md' | 'lg'
}

export const HealthStatusBadge: React.FC<Props> = ({ subsystemId, size = 'md' }) => {
  const { theme } = useTheme()
  const [status, setStatus] = useState<HealthStatus>('loading')
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)

  const socket = useWebSocket(`/ws/health/${subsystemId}`, {
    onMessage: (raw: string) => {
      try {
        const data: SubsystemHealth = JSON.parse(raw)
        if (data?.status) {
          setStatus(data.status)
          setLastUpdate(new Date())
        }
      } catch {
        setStatus('unknown')
      }
    },
    reconnectInterval: 10000,
  })

  useEffect(() => {
    return () => socket.disconnect()
  }, [])

  const sizeClasses = useMemo(() => {
    switch (size) {
      case 'sm': return 'text-xs px-2 py-1'
      case 'lg': return 'text-base px-4 py-2'
      case 'md':
      default: return 'text-sm px-3 py-1.5'
    }
  }, [size])

  const tooltipText = useMemo(() => {
    const label = STATUS_LABELS[status]
    return lastUpdate
      ? `${label} — ${lastUpdate.toLocaleTimeString()}`
      : label
  }, [status, lastUpdate])

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <AnimatePresence mode="wait">
            <motion.div
              key={status}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.2 }}
              aria-label={`Статус: ${STATUS_LABELS[status]}`}
              role="status"
            >
              <Badge
                className={cn(
                  'inline-flex items-center gap-2 font-medium rounded-full transition-all',
                  STATUS_CLASSES[status],
                  sizeClasses
                )}
              >
                {STATUS_ICONS[status]}
                <span className="capitalize">{STATUS_LABELS[status]}</span>
              </Badge>
            </motion.div>
          </AnimatePresence>
        </TooltipTrigger>
        <TooltipContent>
          <span className="text-xs text-muted-foreground">{tooltipText}</span>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
