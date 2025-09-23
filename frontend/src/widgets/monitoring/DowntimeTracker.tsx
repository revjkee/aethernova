import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'
import { useDowntimeStore } from '@/state/downtime'
import { DowntimeEvent } from '@/types/monitoring.types'
import { formatDistanceToNowStrict, parseISO } from 'date-fns'
import { ResponsiveLine } from '@nivo/line'
import { motion, AnimatePresence } from 'framer-motion'
import { debounce } from 'lodash'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useThemeSwitcher'
import { useWebSocket } from '@/shared/hooks/useSocket'

const MAX_EVENTS = 100
const REFRESH_INTERVAL = 10000

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-400 text-black',
  low: 'bg-green-400 text-black',
  info: 'bg-slate-300 text-black',
}

export const DowntimeTracker = () => {
  const { theme } = useTheme()
  const [activeTab, setActiveTab] = useState('timeline')
  const [loading, setLoading] = useState(true)
  const ref = useRef<HTMLDivElement>(null)

  const {
    downtimes,
    fetchDowntimes,
    appendDowntime,
    getDowntimeStats,
  } = useDowntimeStore()

  const socket = useWebSocket('/ws/downtimes', {
    onMessage: (msg) => {
      const parsed: DowntimeEvent = JSON.parse(msg)
      if (parsed?.id) debouncedAdd(parsed)
    },
    reconnectInterval: 15000,
  })

  const debouncedAdd = useMemo(() =>
    debounce((event: DowntimeEvent) => {
      appendDowntime(event)
    }, 500), [])

  useEffect(() => {
    fetchDowntimes().finally(() => setLoading(false))
    return () => {
      debouncedAdd.cancel()
      socket.disconnect()
    }
  }, [])

  useEffect(() => {
    if (ref.current && activeTab === 'timeline') {
      ref.current.scrollTop = ref.current.scrollHeight
    }
  }, [downtimes.length, activeTab])

  const chartData = useMemo(() => {
    const stats = getDowntimeStats()
    return [
      {
        id: 'Downtime',
        data: stats.map((s) => ({
          x: s.date,
          y: s.minutes,
        })),
      },
    ]
  }, [downtimes])

  const renderTimelineItem = (event: DowntimeEvent, index: number) => (
    <motion.div
      key={event.id}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.2, delay: index * 0.015 }}
      className="border-b border-muted px-4 py-2 last:border-none"
    >
      <div className="flex justify-between items-center">
        <span className={cn(
          'text-sm font-semibold px-2 py-1 rounded',
          SEVERITY_COLORS[event.severity] || 'bg-gray-200 text-black'
        )}>
          {event.service.toUpperCase()}
        </span>
        <span className="text-xs text-muted-foreground">
          {formatDistanceToNowStrict(parseISO(event.timestamp), { addSuffix: true })}
        </span>
      </div>
      <div className="text-sm mt-1 text-foreground/90">
        {event.description}
      </div>
    </motion.div>
  )

  return (
    <Card className="h-full shadow-md">
      <CardContent className="p-0 h-full">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="h-full">
          <TabsList className="flex justify-around p-2 bg-muted border-b">
            <TabsTrigger value="timeline">Хронология</TabsTrigger>
            <TabsTrigger value="graph">График</TabsTrigger>
          </TabsList>

          <TabsContent value="timeline" className="h-[calc(100%-2.5rem)]">
            <ScrollArea ref={ref} className="h-full px-0 py-2">
              {loading ? (
                Array.from({ length: 10 }).map((_, idx) => (
                  <Skeleton key={idx} className="h-14 my-1 mx-4 rounded" />
                ))
              ) : (
                <AnimatePresence mode="popLayout">
                  {downtimes.slice(-MAX_EVENTS).map(renderTimelineItem)}
                </AnimatePresence>
              )}
            </ScrollArea>
          </TabsContent>

          <TabsContent value="graph" className="h-[calc(100%-2.5rem)] px-4 py-2">
            {loading ? (
              <Skeleton className="w-full h-full rounded" />
            ) : (
              <div className="h-full w-full">
                <ResponsiveLine
                  data={chartData}
                  margin={{ top: 20, right: 30, bottom: 50, left: 50 }}
                  xScale={{ type: 'point' }}
                  yScale={{
                    type: 'linear',
                    min: 'auto',
                    max: 'auto',
                    stacked: true,
                    reverse: false,
                  }}
                  axisBottom={{
                    tickSize: 5,
                    tickPadding: 5,
                    tickRotation: -45,
                    legend: 'Дата',
                    legendOffset: 36,
                    legendPosition: 'middle',
                  }}
                  axisLeft={{
                    tickSize: 5,
                    tickPadding: 5,
                    tickRotation: 0,
                    legend: 'Минуты простоя',
                    legendOffset: -40,
                    legendPosition: 'middle',
                  }}
                  theme={{
                    axis: {
                      ticks: {
                        text: {
                          fill: theme === 'dark' ? '#fff' : '#000',
                        },
                      },
                    },
                    legends: {
                      text: {
                        fill: theme === 'dark' ? '#fff' : '#000',
                      },
                    },
                  }}
                  colors={{ scheme: 'set2' }}
                  enablePoints={true}
                  pointSize={6}
                  pointColor={{ theme: 'background' }}
                  pointBorderWidth={2}
                  pointBorderColor={{ from: 'serieColor' }}
                  useMesh={true}
                />
              </div>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}

export default DowntimeTracker
