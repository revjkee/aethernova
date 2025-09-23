import React, { useMemo } from 'react'
import { cn } from '@/lib/utils'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { ArrowRight, AlertTriangle, Brain, Hand, Eye, RefreshCcw } from 'lucide-react'

type AgentIntent = {
  agentId: string
  role: string
  intent: string
  confidence: number
  source: 'policy' | 'goal' | 'reaction'
  wasOverridden?: boolean
  conflictWith?: string[]
  timestamp: string
}

interface Props {
  intents: AgentIntent[]
  comparisonStrategy?: 'confidence' | 'priority' | 'compliance'
  onSelectIntent?: (intent: AgentIntent) => void
}

export const XAIIntentComparator: React.FC<Props> = ({
  intents,
  comparisonStrategy = 'confidence',
  onSelectIntent
}) => {
  const sortedIntents = useMemo(() => {
    return [...intents].sort((a, b) => b.confidence - a.confidence)
  }, [intents])

  return (
    <Card className="w-full bg-background border border-border shadow-xl rounded-xl">
      <CardHeader className="flex items-center justify-between px-4 pt-4 pb-2">
        <CardTitle className="text-lg font-semibold tracking-tight text-primary">
          Сравнение намерений агентов
        </CardTitle>
        <div className="flex gap-2 text-xs text-muted-foreground">
          <span className="text-[11px] uppercase">Strategy:</span>
          <Badge variant="outline">{comparisonStrategy}</Badge>
        </div>
      </CardHeader>

      <CardContent className="px-4 pb-4 pt-0">
        <ScrollArea className="h-[440px] pr-2">
          <ul className="space-y-3">
            {sortedIntents.map((intent, idx) => {
              const isPrimary = idx === 0
              return (
                <li
                  key={intent.agentId}
                  className={cn(
                    'border border-muted rounded-lg px-3 py-2 transition-all duration-300',
                    isPrimary && 'border-green-600 bg-green-50 dark:bg-green-900/20'
                  )}
                >
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2 font-mono text-sm">
                      <Brain className="w-4 h-4 text-primary" />
                      {intent.intent}
                      {intent.wasOverridden && (
                        <Tooltip>
                          <TooltipTrigger>
                            <Hand className="w-4 h-4 text-orange-600" />
                          </TooltipTrigger>
                          <TooltipContent>
                            Намерение было переопределено пользователем
                          </TooltipContent>
                        </Tooltip>
                      )}
                      {intent.conflictWith?.length && (
                        <Tooltip>
                          <TooltipTrigger>
                            <AlertTriangle className="w-4 h-4 text-red-600" />
                          </TooltipTrigger>
                          <TooltipContent>
                            Конфликт с: {intent.conflictWith.join(', ')}
                          </TooltipContent>
                        </Tooltip>
                      )}
                    </div>
                    <span className="text-xs text-muted-foreground font-mono">
                      {new Date(intent.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                    <Badge variant="secondary">{intent.role}</Badge>
                    <Badge>{intent.source}</Badge>
                    <Badge variant="outline">
                      Доверие: {(intent.confidence * 100).toFixed(1)}%
                    </Badge>
                    <Tooltip>
                      <TooltipTrigger>
                        <Eye className="w-4 h-4 text-blue-500" />
                      </TooltipTrigger>
                      <TooltipContent>
                        Источник намерения: {intent.source}
                      </TooltipContent>
                    </Tooltip>
                    {onSelectIntent && (
                      <button
                        onClick={() => onSelectIntent(intent)}
                        className="ml-auto text-xs text-accent hover:underline"
                      >
                        Выбрать
                      </button>
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
        </ScrollArea>
      </CardContent>
    </Card>
  )
}
