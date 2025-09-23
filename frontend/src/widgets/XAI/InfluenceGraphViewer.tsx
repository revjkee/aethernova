import React, { useEffect, useRef, useState } from 'react'
import { ForceGraph2D } from 'react-force-graph'
import { useTheme } from '@/hooks/useTheme'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { IconLoader2 } from '@tabler/icons-react'
import clsx from 'clsx'

type InfluenceNode = {
  id: string
  label: string
  group: 'input' | 'hidden' | 'decision'
  weight: number
  importance: number
}

type InfluenceLink = {
  source: string
  target: string
  weight: number
  rationale?: string
  zkVerified?: boolean
}

interface InfluenceGraphProps {
  data: {
    nodes: InfluenceNode[]
    links: InfluenceLink[]
  }
  loading?: boolean
  maxNodes?: number
}

export const InfluenceGraphViewer: React.FC<InfluenceGraphProps> = ({
  data,
  loading = false,
  maxNodes = 200
}) => {
  const fgRef = useRef<any>()
  const { theme } = useTheme()
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  useEffect(() => {
    const resize = () => {
      const width = window.innerWidth * 0.9
      const height = window.innerHeight * 0.65
      setDimensions({ width, height })
    }
    resize()
    window.addEventListener('resize', resize)
    return () => window.removeEventListener('resize', resize)
  }, [])

  const colorByGroup = (group: string) => {
    switch (group) {
      case 'input':
        return theme === 'dark' ? '#9ae6b4' : '#2f855a'
      case 'hidden':
        return theme === 'dark' ? '#fbd38d' : '#c05621'
      case 'decision':
        return theme === 'dark' ? '#f56565' : '#c53030'
      default:
        return '#a0aec0'
    }
  }

  if (loading || !data.nodes.length) {
    return (
      <Card className="w-full h-[600px] flex items-center justify-center">
        <Skeleton className="w-16 h-16 animate-spin text-muted-foreground">
          <IconLoader2 />
        </Skeleton>
      </Card>
    )
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>Граф влияния факторов</CardTitle>
      </CardHeader>
      <CardContent>
        <ForceGraph2D
          ref={fgRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={{
            nodes: data.nodes.slice(0, maxNodes),
            links: data.links.filter(
              (l) =>
                data.nodes.find((n) => n.id === l.source) &&
                data.nodes.find((n) => n.id === l.target)
            )
          }}
          nodeLabel={(node: any) => `
            <div style="font-size: 12px">
              <b>${node.label}</b><br/>
              Weight: ${node.weight}<br/>
              Importance: ${node.importance}
            </div>
          `}
          nodeAutoColorBy="group"
          nodeCanvasObject={(node, ctx, globalScale) => {
            const label = node.label
            const fontSize = 12 / globalScale
            ctx.font = `${fontSize}px Sans-Serif`
            const textWidth = ctx.measureText(label).width
            const bckgDimensions = [textWidth + 6, fontSize + 4]
            ctx.fillStyle = colorByGroup(node.group)
            ctx.fillRect(node.x! - bckgDimensions[0] / 2, node.y! - bckgDimensions[1] / 2, ...bckgDimensions)
            ctx.textAlign = 'center'
            ctx.textBaseline = 'middle'
            ctx.fillStyle = '#ffffff'
            ctx.fillText(label, node.x!, node.y!)
          }}
          linkWidth={(link) => (link.zkVerified ? 2.5 : Math.max(1, link.weight * 2))}
          linkColor={(link) => (link.zkVerified ? '#3182ce' : '#718096')}
          onNodeClick={(node) => {
            if (fgRef.current) {
              fgRef.current.centerAt(node.x, node.y, 1000)
              fgRef.current.zoom(3, 2000)
            }
          }}
          cooldownTicks={80}
          onEngineStop={() => fgRef.current && fgRef.current.zoomToFit(400)}
        />
      </CardContent>
    </Card>
  )
}
