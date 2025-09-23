import React, { useEffect, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { useSystemLoadStats } from '@/services/monitoring/useSystemLoadStats'
import { Progress } from '@/components/ui/progress'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/shared/utils/classNames'
import { AlertTriangle, Zap, Cpu, Activity } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { useHeartbeat } from '@/services/infra/useHeartbeat'
import { useAIHeuristicRisk } from '@/services/ai/useAIHeuristicRisk'

const getLoadColor = (value: number): string => {
  if (value < 40) return 'bg-green-600'
  if (value < 75) return 'bg-yellow-500'
  return 'bg-red-600'
}

export const SystemLoadBalancerIndicator: React.FC = () => {
  const { cpuLoad, memoryLoad, ioLoad, fetchStatus, refreshTimestamp } = useSystemLoadStats()
  const { heartbeatStatus } = useHeartbeat()
  const { overloadRisk } = useAIHeuristicRisk()

  const formatLoad = useCallback((val?: number) => {
    return typeof val === 'number' ? `${val.toFixed(1)}%` : '—'
  }, [])

  const isHealthy = heartbeatStatus === 'active' && overloadRisk < 0.7

  return (
    <Card className="bg-background border border-border shadow-md h-full min-h-[180px]">
      <CardHeader className="flex items-center justify-between">
        <CardTitle className="text-base font-semibold flex items-center gap-2">
          <Cpu className="w-5 h-5 text-primary" />
          Балансировщик системной нагрузки
        </CardTitle>
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge
                variant={isHealthy ? 'success' : 'destructive'}
                className="text-xs px-2 py-0.5"
              >
                {isHealthy ? 'Работает стабильно' : 'Высокая нагрузка'}
              </Badge>
            </TooltipTrigger>
            <TooltipContent>
              <div className="text-xs">
                <div>AI риск: {(overloadRisk * 100).toFixed(0)}%</div>
                <div>Хартбит: {heartbeatStatus}</div>
                <div>Обновлено: {new Date(refreshTimestamp).toLocaleTimeString()}</div>
              </div>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </CardHeader>

      <CardContent className="space-y-5">
        <div className="flex flex-col gap-2">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Zap className="w-4 h-4" /> CPU
            </span>
            <span>{formatLoad(cpuLoad)}</span>
          </div>
          <Progress
            value={cpuLoad}
            className={cn('h-2 rounded-full', getLoadColor(cpuLoad || 0))}
          />
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Activity className="w-4 h-4" /> Память
            </span>
            <span>{formatLoad(memoryLoad)}</span>
          </div>
          <Progress
            value={memoryLoad}
            className={cn('h-2 rounded-full', getLoadColor(memoryLoad || 0))}
          />
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <AlertTriangle className="w-4 h-4" /> I/O
            </span>
            <span>{formatLoad(ioLoad)}</span>
          </div>
          <Progress
            value={ioLoad}
            className={cn('h-2 rounded-full', getLoadColor(ioLoad || 0))}
          />
        </div>

        {fetchStatus === 'error' && (
          <div className="text-xs text-destructive font-mono mt-2">
            Ошибка получения метрик. Перезапуск системы мониторинга...
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default SystemLoadBalancerIndicator
