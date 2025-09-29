import React, { useEffect, useMemo, useState } from 'react'
import { cn } from '@/lib/utils'
import { motion, AnimatePresence } from 'framer-motion'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { CheckCircle, AlertTriangle, XCircle, Clock, Loader2 } from 'lucide-react'

// Types
export type HealthStatus = 'healthy' | 'degraded' | 'offline' | 'unknown' | 'loading'

export interface SubsystemHealth {
  name: string
  status: HealthStatus
  lastCheck: string
  details?: string
  metrics?: Record<string, number>
}

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
  const [status, setStatus] = useState<HealthStatus>('loading')
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)

  // Mock health check - в реальном приложении здесь был бы WebSocket или API call
  useEffect(() => {
    const interval = setInterval(() => {
      // Симуляция проверки здоровья системы
      const healthStatuses: HealthStatus[] = ['healthy', 'degraded', 'offline', 'unknown']
      const randomStatus = healthStatuses[Math.floor(Math.random() * healthStatuses.length)]
      setStatus(randomStatus)
      setLastUpdate(new Date())
    }, 5000)

    // Начальная загрузка
    setTimeout(() => {
      setStatus('healthy')
      setLastUpdate(new Date())
    }, 1000)

    return () => clearInterval(interval)
  }, [subsystemId])

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
