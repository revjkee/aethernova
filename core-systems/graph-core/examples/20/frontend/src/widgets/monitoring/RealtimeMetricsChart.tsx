import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ResponsiveLine } from '@nivo/line'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useWebSocket } from '@/shared/hooks/useSocket'
import { useTheme } from '@/shared/hooks/useThemeSwitcher'
import { motion, AnimatePresence } from 'framer-motion'
import { debounce } from 'lodash'

type MetricPoint = {
  timestamp: string
  latency: number
  io: number
  throughput: number
}

const MAX_POINTS = 60

export const RealtimeMetricsChart: React.FC = () => {
  const { theme } = useTheme()
  const [loading, setLoading] = useState(true)
  const [metrics, setMetrics] = useState<MetricPoint[]>([])

  const socket = useWebSocket('/ws/metrics', {
    onMessage: debounce((raw) => {
      try {
        const point: MetricPoint = JSON.parse(raw)
        setMetrics(prev =>
          [...prev.slice(-MAX_POINTS + 1), point]
        )
        setLoading(false)
      } catch {
        // ignore
      }
    }, 200),
    reconnectInterval: 10000,
  })

  useEffect(() => {
    return () => socket.disconnect()
  }, [])

  const series = useMemo(() => {
    return [
      {
        id: 'Latency',
        color: 'hsl(200, 70%, 50%)',
        data: metrics.map(p => ({
          x: new Date(p.timestamp).toLocaleTimeString(),
          y: p.latency,
        })),
      },
      {
        id: 'IO',
        color: 'hsl(90, 70%, 50%)',
        data: metrics.map(p => ({
          x: new Date(p.timestamp).toLocaleTimeString(),
          y: p.io,
        })),
      },
      {
        id: 'Throughput',
        color: 'hsl(10, 80%, 50%)',
        data: metrics.map(p => ({
          x: new Date(p.timestamp).toLocaleTimeString(),
          y: p.throughput,
        })),
      },
    ]
  }, [metrics])

  const nivoTheme = useMemo(() => ({
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
    tooltip: {
      container: {
        background: theme === 'dark' ? '#1f2937' : '#fff',
        color: theme === 'dark' ? '#f9fafb' : '#111',
      },
    },
  }), [theme])

  return (
    <Card className="h-full shadow-md">
      <CardContent className="p-0 h-full">
        {loading ? (
          <div className="flex h-full items-center justify-center">
            <Skeleton className="w-full h-64 rounded" />
          </div>
        ) : (
          <AnimatePresence>
            <motion.div
              key="chart"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="w-full h-full"
            >
              <ResponsiveLine
                data={series}
                theme={nivoTheme}
                margin={{ top: 20, right: 60, bottom: 50, left: 60 }}
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
                pointSize={6}
                pointColor={{ theme: 'background' }}
                pointBorderWidth={2}
                pointBorderColor={{ from: 'serieColor' }}
                useMesh={true}
                enableSlices="x"
                enableArea={true}
                curve="monotoneX"
                legends={[
                  {
                    anchor: 'top-right',
                    direction: 'column',
                    justify: false,
                    translateX: 100,
                    translateY: 0,
                    itemsSpacing: 4,
                    itemDirection: 'left-to-right',
                    itemWidth: 80,
                    itemHeight: 20,
                    symbolSize: 12,
                    symbolShape: 'circle',
                  },
                ]}
              />
            </motion.div>
          </AnimatePresence>
        )}
      </CardContent>
    </Card>
  )
}

export default RealtimeMetricsChart
