import React, { useEffect, useState } from 'react'
import { ShieldCheck, ShieldX, AlertTriangle, TimerReset } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import { fetchZeroTrustLayers } from '@/services/security/zeroTrustAPI'
import { cn } from '@/shared/utils/classNames'
import { motion } from 'framer-motion'

type TrustState = 'trusted' | 'warning' | 'blocked' | 'verifying'

interface TrustLayer {
  id: string
  name: string
  zone: string
  lastVerified: string
  state: TrustState
  details?: string
}

const ICONS: Record<TrustState, JSX.Element> = {
  trusted: <ShieldCheck className="text-emerald-500 w-4 h-4" />,
  warning: <AlertTriangle className="text-yellow-500 w-4 h-4" />,
  blocked: <ShieldX className="text-red-600 w-4 h-4" />,
  verifying: <TimerReset className="text-blue-500 w-4 h-4 animate-spin" />,
}

const COLORS: Record<TrustState, string> = {
  trusted: 'border-emerald-500 bg-emerald-50',
  warning: 'border-yellow-500 bg-yellow-50',
  blocked: 'border-red-600 bg-red-50',
  verifying: 'border-blue-500 bg-blue-50',
}

export const ZeroTrustLayerInfo: React.FC = () => {
  const [layers, setLayers] = useState<TrustLayer[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let interval: NodeJS.Timer

    const load = async () => {
      setLoading(true)
      try {
        const result = await fetchZeroTrustLayers()
        setLayers(result)
      } catch {
        setLayers([])
      }
      setLoading(false)
    }

    load()
    interval = setInterval(load, 15000)

    return () => clearInterval(interval)
  }, [])

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="text-sm font-semibold tracking-wide">
          Zero Trust Слои Безопасности
        </CardTitle>
      </CardHeader>

      <CardContent className="flex flex-col gap-3">
        {loading && (
          <span className="text-xs text-muted-foreground animate-pulse">
            Загрузка состояния доверенных зон...
          </span>
        )}

        {!loading && layers.length === 0 && (
          <span className="text-sm text-destructive">Нет данных</span>
        )}

        {layers.map(layer => (
          <motion.div
            key={layer.id}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            className={cn(
              'flex items-center justify-between px-3 py-2 rounded border shadow-sm',
              COLORS[layer.state]
            )}
          >
            <div className="flex items-center gap-2">
              {ICONS[layer.state]}
              <div className="flex flex-col text-sm leading-tight">
                <span className="font-medium">{layer.name}</span>
                <span className="text-xs text-muted-foreground">
                  Зона: {layer.zone}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant="outline"
                    className={cn(
                      'text-xs',
                      {
                        'text-emerald-600 border-emerald-600': layer.state === 'trusted',
                        'text-yellow-600 border-yellow-600': layer.state === 'warning',
                        'text-red-600 border-red-600': layer.state === 'blocked',
                        'text-blue-600 border-blue-600': layer.state === 'verifying',
                      }
                    )}
                  >
                    {layer.state.toUpperCase()}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent className="max-w-sm">
                  <p>{layer.details || 'Описание недоступно'}</p>
                </TooltipContent>
              </Tooltip>
              <span className="text-xs text-muted-foreground">
                {layer.lastVerified}
              </span>
            </div>
          </motion.div>
        ))}
      </CardContent>
    </Card>
  )
}

export default ZeroTrustLayerInfo
