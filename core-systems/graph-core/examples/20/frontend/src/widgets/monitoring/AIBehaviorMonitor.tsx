import React, { useEffect, useMemo, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { motion, AnimatePresence } from 'framer-motion'
import { useWebSocket } from '@/shared/hooks/useSocket'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipProvider, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/shared/utils/classNames'
import { Eye, AlertCircle, Activity, Sparkles, Search } from 'lucide-react'

type BehaviorEvent = {
  timestamp: string
  agentId: string
  type: 'normal' | 'deviation' | 'alert' | 'anomaly'
  description: string
  vector: string
  meta: Record<string, string>
}

const TYPE_LABELS: Record<BehaviorEvent['type'], string> = {
  normal: 'Норма',
  deviation: 'Отклонение',
  alert: 'Тревога',
  anomaly: 'Аномалия',
}

const TYPE_COLORS: Record<BehaviorEvent['type'], string> = {
  normal: 'bg-green-500 text-white',
  deviation: 'bg-yellow-400 text-black',
  alert: 'bg-red-600 text-white',
  anomaly: 'bg-purple-500 text-white',
}

const TYPE_ICONS: Record<BehaviorEvent['type'], JSX.Element> = {
  normal: <Activity className="w-4 h-4" />,
  deviation: <Search className="w-4 h-4" />,
  alert: <AlertCircle className="w-4 h-4" />,
  anomaly: <Sparkles className="w-4 h-4" />,
}

const MAX_EVENTS = 200

export const AIBehaviorMonitor: React.FC = () => {
  const [loading, setLoading] = useState(true)
  const [events, setEvents] = useState<BehaviorEvent[]>([])

  const socket = useWebSocket('/ws/ai-behavior', {
    onMessage: (raw) => {
      try {
        const event: BehaviorEvent = JSON.parse(raw)
        setEvents(prev => [...prev.slice(-MAX_EVENTS + 1), event])
        setLoading(false)
      } catch {
        // invalid input
      }
    },
    reconnectInterval: 10000,
  })

  useEffect(() => {
    return () => socket.disconnect()
  }, [])

  const orderedEvents = useMemo(
    () => [...events].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()),
    [events]
  )

  return (
    <Card className="h-full shadow-xl">
      <CardContent className="p-4 h-full flex flex-col">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Eye className="w-5 h-5 text-muted-foreground" />
          Монитор поведения AI
        </h2>

        {loading ? (
          <Skeleton className="w-full h-72 rounded" />
        ) : (
          <ScrollArea className="flex-1">
            <AnimatePresence>
              <ul className="space-y-3">
                {orderedEvents.map((e, idx) => (
                  <motion.li
                    key={`${e.agentId}-${e.timestamp}-${idx}`}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.25 }}
                    className="p-3 border rounded-md bg-muted hover:bg-accent"
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2">
                        <Badge className={cn('text-xs px-2', TYPE_COLORS[e.type])}>
                          {TYPE_ICONS[e.type]} {TYPE_LABELS[e.type]}
                        </Badge>
                        <span className="text-sm text-muted-foreground">
                          Агент: <strong>{e.agentId}</strong>
                        </span>
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {new Date(e.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-sm font-medium mb-1">{e.description}</div>
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div className="text-xs text-muted-foreground truncate cursor-help">
                            Вектор: {e.vector}
                          </div>
                        </TooltipTrigger>
                        <TooltipContent>
                          <div className="max-w-xs text-xs break-words">
                            <div><strong>Агент:</strong> {e.agentId}</div>
                            <div><strong>Вектор:</strong> {e.vector}</div>
                            {Object.entries(e.meta).map(([k, v]) => (
                              <div key={k}>
                                <strong>{k}:</strong> {v}
                              </div>
                            ))}
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </motion.li>
                ))}
              </ul>
            </AnimatePresence>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  )
}

export default AIBehaviorMonitor
