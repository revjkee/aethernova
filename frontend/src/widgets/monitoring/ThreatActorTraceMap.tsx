import React, { useEffect, useMemo, useRef, useState } from 'react'
import { ComposableMap, Geographies, Geography, Marker, Line } from 'react-simple-maps'
import { useWebSocket } from '@/shared/hooks/useSocket'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { motion, AnimatePresence } from 'framer-motion'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Globe, AlertTriangle, MapPin } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'

type TracePoint = {
  id: string
  ip: string
  country: string
  region: string
  city: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  coordinates: [number, number]
  timestamp: string
  attackVector: string
  target: string
}

const SEVERITY_COLOR: Record<TracePoint['severity'], string> = {
  low: '#34d399',
  medium: '#facc15',
  high: '#f97316',
  critical: '#ef4444',
}

const geoUrl = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

export const ThreatActorTraceMap: React.FC = () => {
  const [loading, setLoading] = useState(true)
  const [tracePoints, setTracePoints] = useState<TracePoint[]>([])
  const MAX_POINTS = 100

  const socket = useWebSocket('/ws/threat-traces', {
    onMessage: (msg) => {
      try {
        const point: TracePoint = JSON.parse(msg)
        setTracePoints(prev => [...prev.slice(-MAX_POINTS + 1), point])
        setLoading(false)
      } catch {
        // ignore invalid
      }
    },
    reconnectInterval: 10000,
  })

  useEffect(() => {
    return () => socket.disconnect()
  }, [])

  const lines = useMemo(() => {
    return tracePoints.map((p, i) => ({
      from: p.coordinates,
      to: [0, 0], // target assumed at [0, 0] for simplicity, or change to dynamic
      severity: p.severity,
      key: `${p.id}-${i}`,
    }))
  }, [tracePoints])

  return (
    <Card className="h-full shadow-md">
      <CardContent className="p-0 h-full overflow-hidden">
        {loading ? (
          <Skeleton className="w-full h-full rounded-none" />
        ) : (
          <AnimatePresence>
            <motion.div
              key="map"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="w-full h-full"
            >
              <TooltipProvider>
                <ComposableMap
                  projection="geoEqualEarth"
                  width={980}
                  height={520}
                  style={{ width: '100%', height: '100%' }}
                  projectionConfig={{ scale: 180 }}
                >
                  <Geographies geography={geoUrl}>
                    {({ geographies }) =>
                      geographies.map(geo => (
                        <Geography
                          key={geo.rsmKey}
                          geography={geo}
                          fill="#e5e7eb"
                          stroke="#9ca3af"
                          style={{
                            default: { outline: 'none' },
                            hover: { fill: '#cbd5e1', outline: 'none' },
                            pressed: { fill: '#94a3b8', outline: 'none' },
                          }}
                        />
                      ))
                    }
                  </Geographies>

                  {tracePoints.map((point) => (
                    <Tooltip key={point.id}>
                      <TooltipTrigger asChild>
                        <Marker coordinates={point.coordinates}>
                          <circle
                            r={6}
                            fill={SEVERITY_COLOR[point.severity]}
                            stroke="#1e293b"
                            strokeWidth={1.5}
                          />
                        </Marker>
                      </TooltipTrigger>
                      <TooltipContent>
                        <div className="text-xs font-medium">
                          {point.city}, {point.country}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          IP: {point.ip}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Атака: {point.attackVector}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Цель: {point.target}
                        </div>
                      </TooltipContent>
                    </Tooltip>
                  ))}

                  {lines.map(line => (
                    <Line
                      key={line.key}
                      from={line.from}
                      to={line.to}
                      stroke={SEVERITY_COLOR[line.severity]}
                      strokeWidth={2}
                      strokeLinecap="round"
                      strokeDasharray="4 2"
                    />
                  ))}
                </ComposableMap>
              </TooltipProvider>
            </motion.div>
          </AnimatePresence>
        )}
      </CardContent>
    </Card>
  )
}

export default ThreatActorTraceMap
