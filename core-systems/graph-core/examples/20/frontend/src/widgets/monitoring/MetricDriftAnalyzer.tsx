import React, { useEffect, useMemo, useState } from 'react'
import { ResponsiveLine } from '@nivo/line'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useWebSocket } from '@/shared/hooks/useSocket'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { debounce } from 'lodash'
import { AnimatePresence, motion } from 'framer-motion'
import { cn } from '@/shared/utils/classNames'

type DriftPoint = {
  timestamp: string
  category: string
  metric: string
  value: number
  baseline: number
  zscore: number
  stddev: number
}

type DriftSeries = Record<string, DriftPoint[]>

const MAX_POINTS = 200

export const MetricDriftAnalyzer: React.FC = () => {
  const [loading, setLoading] = useState(true)
  const [data, setData] = useState<DriftPoint[]>([])
  const [selectedCategory, setSelectedCategory] = useState<string>('all')

  const socket = useWebSocket('/ws/drift-metrics', {
    onMessage: debounce((raw) => {
      try {
        const incoming: DriftPoint = JSON.parse(raw)
        setData(prev =>
          [...prev.slice(-MAX_POINTS + 1), incoming]
        )
        setLoading(false)
      } catch {
        // ignore invalid input
      }
    }, 200),
    reconnectInterval: 10000,
  })

  useEffect(() => {
    return () => socket.disconnect()
  }, [])

  const categories = useMemo(() => {
    const unique = new Set(data.map(d => d.category))
    return Array.from(unique)
  }, [data])

  const filtered = useMemo(() => {
    return selectedCategory === 'all'
      ? data
      : data.filter(d => d.category === selectedCategory)
  }, [data, selectedCategory])

  const grouped = useMemo(() => {
    const map: DriftSeries = {}
    for (const point of filtered) {
      if (!map[point.metric]) map[point.metric] = []
      map[point.metric].push(point)
    }
    return map
  }, [filtered])

  const renderChart = (metric: string, points: DriftPoint[]) => {
    return (
      <ResponsiveLine
        data={[
          {
            id: `${metric} — отклонение`,
            data: points.map(p => ({
              x: new Date(p.timestamp).toLocaleTimeString(),
              y: p.value,
            })),
          },
          {
            id: `${metric} — baseline`,
            data: points.map(p => ({
              x: new Date(p.timestamp).toLocaleTimeString(),
              y: p.baseline,
            })),
          },
        ]}
        margin={{ top: 20, right: 40, bottom: 50, left: 60 }}
        xScale={{ type: 'point' }}
        yScale={{ type: 'linear', min: 'auto', max: 'auto', stacked: false }}
        axisBottom={{
          tickSize: 5,
          tickPadding: 5,
          tickRotation: -45,
          legend: 'Время',
          legendOffset: 36,
          legendPosition: 'middle',
        }}
        axisLeft={{
          tickSize: 5,
          tickPadding: 5,
          tickRotation: 0,
          legend: 'Значение',
          legendOffset: -50,
          legendPosition: 'middle',
        }}
        curve="monotoneX"
        enableSlices="x"
        useMesh={true}
        enableArea={true}
        pointSize={6}
        pointBorderWidth={2}
        colors={['#ef4444', '#3b82f6']}
        tooltip={({ point }) => (
          <div className="text-xs bg-background border p-2 shadow-md rounded-md">
            <div><strong>{point.serieId}</strong></div>
            <div>{point.data.xFormatted}</div>
            <div>Значение: {point.data.yFormatted}</div>
          </div>
        )}
      />
    )
  }

  return (
    <Card className="h-full shadow-lg">
      <CardContent className="p-4 h-full flex flex-col gap-4">
        <h2 className="text-lg font-semibold">Анализ отклонений метрик (Drift)</h2>

        {loading ? (
          <Skeleton className="h-64 w-full" />
        ) : (
          <>
            <Tabs value={selectedCategory} onValueChange={setSelectedCategory}>
              <TabsList>
                <TabsTrigger value="all">Все</TabsTrigger>
                {categories.map(c => (
                  <TabsTrigger key={c} value={c}>
                    {c}
                  </TabsTrigger>
                ))}
              </TabsList>
              {categories.map(category => (
                <TabsContent key={category} value={category}>
                  <AnimatePresence>
                    {Object.entries(grouped).map(([metric, points]) => (
                      <motion.div
                        key={metric}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.3 }}
                        className="mb-8"
                      >
                        <h3 className="text-sm font-medium text-muted-foreground mb-2">
                          Метрика: {metric}
                        </h3>
                        <div className="h-[260px]">
                          {renderChart(metric, points)}
                        </div>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </TabsContent>
              ))}
            </Tabs>
          </>
        )}
      </CardContent>
    </Card>
  )
}

export default MetricDriftAnalyzer
