import React, { useMemo } from 'react'
import { Card, CardHeader, CardContent, CardTitle } from '@/components/ui/card'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { BarChart, LineChart } from 'lucide-react'
import { cn } from '@/lib/utils'
import { RuleConfidenceMeter } from './_shared/RuleConfidenceMeter'
import { ActionPathExplanation } from './_shared/ActionPathExplanation'
import { HeatmapRenderer } from './_shared/HeatmapRenderer'
import { ExplanationTimeline } from './_shared/ExplanationTimeline'

interface PolicyRule {
  stateFeature: string
  value: number | string
  operator: string
  weight: number
  influence: number // between -1 and 1
}

interface ActionExplanation {
  action: string
  probability: number
  confidence: number
  rewardEstimate: number
  rules: PolicyRule[]
  causalPath?: string[]
  auditNotes?: string[]
}

interface Props {
  explanations: ActionExplanation[]
  agentId: string
  episodeId: string
  timestamp?: string
}

export const TransparentPolicyRenderer: React.FC<Props> = ({ explanations, agentId, episodeId, timestamp }) => {
  const sorted = useMemo(
    () => explanations.sort((a, b) => b.probability - a.probability),
    [explanations]
  )

  return (
    <Card className="w-full rounded-xl border shadow-sm bg-background">
      <CardHeader className="flex items-center justify-between">
        <CardTitle className="text-base font-semibold flex items-center gap-2">
          Policy-решения RL-агента
          <Tooltip>
            <TooltipTrigger>
              <BarChart className="w-4 h-4 text-muted-foreground" />
            </TooltipTrigger>
            <TooltipContent className="text-xs max-w-sm">
              Интерпретируемое отображение выбранных действий, вероятностей, весов правил и причинности.
              Поддержка мультиагентных систем и аудита ISO/IEEE XAI.
            </TooltipContent>
          </Tooltip>
        </CardTitle>
        <Badge variant="outline" className="text-[10px] font-mono">
          Agent: {agentId} | Ep: {episodeId}
        </Badge>
      </CardHeader>

      <CardContent className="space-y-6">
        {sorted.map((exp, idx) => (
          <div
            key={idx}
            className={cn(
              'p-4 rounded-md border shadow-sm transition-all duration-300',
              exp.confidence > 0.8 ? 'bg-green-50' : exp.confidence < 0.4 ? 'bg-red-50' : 'bg-yellow-50'
            )}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="font-medium text-sm">
                Action: <span className="font-semibold">{exp.action}</span>
              </div>
              <div className="text-xs font-mono text-muted-foreground">
                p={exp.probability.toFixed(2)} | r̂={exp.rewardEstimate.toFixed(2)}
              </div>
            </div>

            <RuleConfidenceMeter confidence={exp.confidence} />

            <div className="mt-2">
              <div className="font-semibold text-sm mb-1 text-muted-foreground">Правила:</div>
              <ul className="list-disc list-inside space-y-1 text-sm">
                {exp.rules.map((rule, ridx) => (
                  <li key={ridx}>
                    если <code className="font-mono">{rule.stateFeature}</code> {rule.operator}{' '}
                    <code className="font-mono">{rule.value}</code> → влияние{' '}
                    <span
                      className={cn(
                        'font-semibold',
                        rule.influence > 0.6
                          ? 'text-green-600'
                          : rule.influence < -0.6
                          ? 'text-red-600'
                          : 'text-yellow-600'
                      )}
                    >
                      {rule.influence.toFixed(2)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {exp.causalPath && exp.causalPath.length > 0 && (
              <div className="mt-3">
                <ActionPathExplanation path={exp.causalPath} />
              </div>
            )}

            {exp.auditNotes && exp.auditNotes.length > 0 && (
              <div className="mt-2 text-xs text-muted-foreground space-y-1">
                {exp.auditNotes.map((note, nidx) => (
                  <p key={nidx}>⏵ {note}</p>
                ))}
              </div>
            )}
          </div>
        ))}

        <div className="pt-6 border-t">
          <ExplanationTimeline
            steps={sorted.map((x, i) => ({
              rule: `Action ${x.action}`,
              confidence: x.confidence,
              outcome: `${x.rewardEstimate.toFixed(2)} reward`,
            }))}
          />
        </div>
      </CardContent>
    </Card>
  )
}
