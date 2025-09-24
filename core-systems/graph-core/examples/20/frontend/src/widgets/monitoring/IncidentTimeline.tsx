import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useThemeSwitcher'
import { formatDistanceToNowStrict, parseISO } from 'date-fns'
import { AnimatePresence, motion } from 'framer-motion'
import { useWebSocket } from '@/shared/hooks/useSocket'
import { debounce } from 'lodash'
import { useIncidentStore } from '@/state/incidents'
import { Incident } from '@/types/incident.types'

const TIMELINE_REFRESH_INTERVAL = 6000
const MAX_EVENTS_DISPLAYED = 150

export const IncidentTimeline = () => {
  const [loading, setLoading] = useState(true)
  const { theme } = useTheme()
  const timelineRef = useRef<HTMLDivElement>(null)

  const {
    incidents,
    fetchIncidents,
    appendIncident,
    clearIncidents,
  } = useIncidentStore()

  const socket = useWebSocket('/ws/incidents', {
    onMessage: (data) => {
      const parsed: Incident = JSON.parse(data)
      if (parsed?.id) {
        debouncedAppend(parsed)
      }
    },
    reconnectInterval: 10000,
  })

  const debouncedAppend = useMemo(() => debounce((incident: Incident) => {
    appendIncident(incident)
  }, 500), [])

  useEffect(() => {
    fetchIncidents().finally(() => setLoading(false))
    return () => {
      debouncedAppend.cancel()
      socket.disconnect()
    }
  }, [])

  useEffect(() => {
    if (timelineRef.current) {
      timelineRef.current.scrollTop = timelineRef.current.scrollHeight
    }
  }, [incidents.length])

  const getColorForSeverity = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white'
      case 'high': return 'bg-orange-500 text-white'
      case 'medium': return 'bg-yellow-400 text-black'
      case 'low': return 'bg-green-400 text-black'
      default: return 'bg-gray-300 text-black'
    }
  }

  const renderItem = (incident: Incident, index: number) => (
    <motion.div
      key={incident.id}
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2, delay: index * 0.01 }}
      className="border-b border-muted py-2 px-4 last:border-none"
    >
      <div className="flex justify-between items-center">
        <span className={cn(
          'text-sm font-medium truncate max-w-[60%]',
          getColorForSeverity(incident.severity),
          'rounded px-2 py-1'
        )}>
          {incident.type.toUpperCase()}
        </span>
        <span className="text-xs text-muted-foreground">
          {formatDistanceToNowStrict(parseISO(incident.timestamp), { addSuffix: true })}
        </span>
      </div>
      <div className="text-sm mt-1 text-foreground/90">
        {incident.description}
      </div>
    </motion.div>
  )

  return (
    <Card className="h-full shadow-lg">
      <CardContent className="p-0 h-full">
        <ScrollArea ref={timelineRef} className="h-full px-0 py-2">
          <div className="flex flex-col">
            {loading ? (
              Array.from({ length: 10 }).map((_, idx) => (
                <Skeleton key={idx} className="h-14 my-1 mx-4 rounded" />
              ))
            ) : (
              <AnimatePresence mode="popLayout">
                {incidents.slice(-MAX_EVENTS_DISPLAYED).map(renderItem)}
              </AnimatePresence>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  )
}

export default IncidentTimeline
