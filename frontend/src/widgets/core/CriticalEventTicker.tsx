import React, { useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { useCriticalEventStream } from '@/services/monitoring/useCriticalEventStream'
import { cn } from '@/shared/utils/classNames'
import { Badge } from '@/components/ui/badge'
import { AlertCircle, ShieldAlert, Flame, BellRing } from 'lucide-react'

type EventSeverity = 'critical' | 'warning' | 'info' | 'secure'

const severityIcons: Record<EventSeverity, JSX.Element> = {
  critical: <Flame className="text-red-600 w-4 h-4" />,
  warning: <AlertCircle className="text-yellow-500 w-4 h-4" />,
  info: <BellRing className="text-blue-500 w-4 h-4" />,
  secure: <ShieldAlert className="text-emerald-500 w-4 h-4" />,
}

const severityClass: Record<EventSeverity, string> = {
  critical: 'border-red-600 text-red-600 bg-red-50',
  warning: 'border-yellow-500 text-yellow-600 bg-yellow-50',
  info: 'border-blue-500 text-blue-600 bg-blue-50',
  secure: 'border-emerald-600 text-emerald-600 bg-emerald-50',
}

interface CriticalEvent {
  id: string
  timestamp: number
  message: string
  source: string
  severity: EventSeverity
}

export const CriticalEventTicker: React.FC = () => {
  const { events, status, retry } = useCriticalEventStream()
  const [visibleEvents, setVisibleEvents] = useState<CriticalEvent[]>([])
  const timerRef = useRef<NodeJS.Timeout | null>(null)

  useEffect(() => {
    if (!events.length) return

    setVisibleEvents(prev => {
      const next = [events[0], ...prev].slice(0, 6)
      return next
    })

    timerRef.current = setTimeout(() => {
      setVisibleEvents(prev => prev.slice(0, -1))
    }, 10000)

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [events])

  return (
    <div className="w-full bg-background border-t border-border px-4 py-2 overflow-hidden relative">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">
          Критические события
        </span>
        {status === 'error' && (
          <button
            className="text-red-600 text-xs underline"
            onClick={retry}
          >
            Ошибка. Повторить
          </button>
        )}
      </div>

      <div className="relative h-[24px] overflow-hidden">
        <AnimatePresence mode="popLayout">
          {visibleEvents.map(event => (
            <motion.div
              key={event.id}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.3 }}
              className={cn(
                'absolute left-0 right-0 flex items-center gap-2 text-sm px-2 py-1 rounded shadow-sm border',
                severityClass[event.severity]
              )}
            >
              {severityIcons[event.severity]}
              <span className="truncate font-medium">{event.message}</span>
              <span className="ml-auto text-xs opacity-70">{event.source}</span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  )
}

export default CriticalEventTicker
