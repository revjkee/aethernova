import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { useWebSocket } from '@/shared/hooks/useSocket'
import { useTheme } from '@/shared/hooks/useThemeSwitcher'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { SubsystemHealth } from '@/types/health.types'
import { Badge } from '@/components/ui/badge'
import { AnimatePresence, motion } from 'framer-motion'
import { debounce } from 'lodash'

type ServiceNode = {
  id: string
  name: string
  status: 'healthy' | 'degraded' | 'offline' | 'unknown'
}

type ServiceLink = {
  source: string
  target: string
  traffic?: number
}

type GraphData = {
  nodes: ServiceNode[]
  links: ServiceLink[]
}

const STATUS_COLORS: Record<ServiceNode['status'], string> = {
  healthy: '#10b981',
  degraded: '#facc15',
  offline: '#ef4444',
  unknown: '#94a3b8',
}

export const ServiceDependencyMap: React.FC = () => {
  const { theme } = useTheme()
  const [graphData, setGraphData] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const graphRef = useRef<any>(null)

  const socket = useWebSocket('/ws/dependencies', {
    onMessage: debounce((raw) => {
      try {
        const data: GraphData = JSON.parse(raw)
        if (data.nodes?.length && data.links?.length) {
          setGraphData(data)
          setLoading(false)
        }
      } catch {
        setLoading(false)
      }
    }, 1000),
    reconnectInterval: 15000,
  })

  useEffect(() => {
    return () => {
      socket.disconnect()
    }
  }, [])

  const handleNodeHover = useCallback((node: ServiceNode | null) => {
    if (node) {
      document.body.style.cursor = 'pointer'
    } else {
      document.body.style.cursor = 'default'
    }
  }, [])

  const drawNode = useCallback((node: ServiceNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const label = node.name
    const fontSize = 12 / globalScale
    const statusColor = STATUS_COLORS[node.status] || '#999'

    ctx.beginPath()
    ctx.arc(node.x!, node.y!, 12, 0, 2 * Math.PI, false)
    ctx.fillStyle = statusColor
    ctx.fill()

    ctx.font = `${fontSize}px Inter`
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    ctx.fillStyle = theme === 'dark' ? '#fff' : '#111'
    ctx.fillText(label, node.x!, node.y! + 14)
  }, [theme])

  const drawLink = useCallback((link: ServiceLink, ctx: CanvasRenderingContext2D) => {
    ctx.strokeStyle = '#888'
    ctx.lineWidth = 1.5
    ctx.beginPath()
    ctx.moveTo(link.source['x'], link.source['y'])
    ctx.lineTo(link.target['x'], link.target['y'])
    ctx.stroke()
  }, [])

  return (
    <Card className="h-full shadow-xl">
      <CardContent className="relative p-0 h-full">
        {loading || !graphData ? (
          <div className="flex h-full items-center justify-center">
            <Skeleton className="w-80 h-80 rounded-full" />
          </div>
        ) : (
          <AnimatePresence>
            <motion.div
              className="w-full h-full"
              key="graph"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
            >
              <ForceGraph2D
                ref={graphRef}
                graphData={graphData}
                nodeCanvasObject={drawNode}
                linkCanvasObject={drawLink}
                nodePointerAreaPaint={(node, color, ctx) => {
                  ctx.fillStyle = color
                  ctx.beginPath()
                  ctx.arc(node.x!, node.y!, 14, 0, 2 * Math.PI, false)
                  ctx.fill()
                }}
                onNodeHover={handleNodeHover}
                linkDirectionalParticles={2}
                linkDirectionalParticleSpeed={d => 0.002 + (d.traffic || 1) * 0.0005}
                cooldownTicks={100}
                onEngineStop={() => graphRef.current?.zoomToFit(400)}
              />
            </motion.div>
          </AnimatePresence>
        )}
      </CardContent>
    </Card>
  )
}

export default ServiceDependencyMap
