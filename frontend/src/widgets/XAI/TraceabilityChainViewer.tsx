import React from 'react'
import { Panel, PanelHeader, PanelContent } from '@/components/ui/panel'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Timeline } from '@/components/traceability/Timeline'
import { CheckCircle2, XCircle, ShieldCheck, ShieldX, RefreshCcw, Link, Bug, Lock } from 'lucide-react'
import { cn } from '@/lib/utils'

type TraceStep = {
  id: string
  label: string
  timestamp: string
  type: 'input' | 'preprocessing' | 'model' | 'decision' | 'action' | 'postprocess'
  subsystem: string
  status: 'ok' | 'error' | 'warning'
  integrityCheck?: boolean
  zkVerified?: boolean
  anomalyDetected?: boolean
  overrideTraceId?: string
}

interface Props {
  traceId: string
  steps: TraceStep[]
  className?: string
}

export const TraceabilityChainViewer: React.FC<Props> = ({ traceId, steps, className }) => {
  return (
    <Panel className={cn('shadow-md border border-primary/30 rounded-xl bg-background', className)}>
      <PanelHeader>
        <div className="flex items-center justify-between">
          <div className="font-semibold text-base">
            Traceability Chain
            <Badge variant="outline" className="ml-2 text-xs bg-muted">
              Trace ID: {traceId}
            </Badge>
          </div>
        </div>
        <Separator className="my-2" />
      </PanelHeader>

      <PanelContent className="px-3 py-2">
        <ScrollArea className="h-[480px] pr-1">
          <Timeline>
            {steps.map((step, idx) => (
              <Timeline.Item key={step.id} active={step.status === 'ok'}>
                <div className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm text-primary">
                      {step.label}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {new Date(step.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Badge variant="secondary">{step.type}</Badge>
                    <Badge>{step.subsystem}</Badge>

                    {step.integrityCheck && (
                      <Tooltip>
                        <TooltipTrigger>
                          <ShieldCheck className="w-4 h-4 text-green-600" />
                        </TooltipTrigger>
                        <TooltipContent>Проверка целостности пройдена</TooltipContent>
                      </Tooltip>
                    )}

                    {step.zkVerified && (
                      <Tooltip>
                        <TooltipTrigger>
                          <Lock className="w-4 h-4 text-blue-600" />
                        </TooltipTrigger>
                        <TooltipContent>Zero-Knowledge доказательство подтверждено</TooltipContent>
                      </Tooltip>
                    )}

                    {step.anomalyDetected && (
                      <Tooltip>
                        <TooltipTrigger>
                          <Bug className="w-4 h-4 text-red-600" />
                        </TooltipTrigger>
                        <TooltipContent>Обнаружена аномалия</TooltipContent>
                      </Tooltip>
                    )}

                    {step.overrideTraceId && (
                      <Tooltip>
                        <TooltipTrigger>
                          <Link className="w-4 h-4 text-orange-600" />
                        </TooltipTrigger>
                        <TooltipContent>
                          Пользователь вмешался, связанный Trace ID: {step.overrideTraceId}
                        </TooltipContent>
                      </Tooltip>
                    )}

                    {step.status === 'ok' && (
                      <CheckCircle2 className="w-4 h-4 text-green-500" />
                    )}

                    {step.status === 'error' && (
                      <XCircle className="w-4 h-4 text-red-500" />
                    )}

                    {step.status === 'warning' && (
                      <ShieldX className="w-4 h-4 text-yellow-600" />
                    )}
                  </div>
                </div>
              </Timeline.Item>
            ))}
          </Timeline>
        </ScrollArea>
      </PanelContent>
    </Panel>
  )
}
