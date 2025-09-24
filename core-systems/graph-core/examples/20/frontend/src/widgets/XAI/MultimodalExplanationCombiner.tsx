import React, { useState, useMemo } from 'react'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { Image } from 'lucide-react'
import { ExplanationOverlay } from './_shared/ExplanationOverlay'
import { ExplanationTimeline } from './_shared/ExplanationTimeline'

interface VisionExplanation {
  heatmapUrl: string
  regions: { x: number; y: number; w: number; h: number; label: string; confidence: number }[]
}

interface TextExplanation {
  tokens: string[]
  scores: number[]
}

interface LogicTrace {
  steps: {
    rule: string
    confidence: number
    outcome: string
  }[]
}

interface MultimodalExplanation {
  vision?: VisionExplanation
  text?: TextExplanation
  logic?: LogicTrace
  timestamp?: string
  model?: string
}

interface Props {
  explanation: MultimodalExplanation
  isLoading?: boolean
}

export const MultimodalExplanationCombiner: React.FC<Props> = ({ explanation, isLoading = false }) => {
  const [mode, setMode] = useState<'vision' | 'text' | 'logic'>('vision')

  const hasVision = !!explanation.vision
  const hasText = !!explanation.text
  const hasLogic = !!explanation.logic

  const tabs = useMemo(() => {
    const entries = []
    if (hasVision) entries.push('vision')
    if (hasText) entries.push('text')
    if (hasLogic) entries.push('logic')
    return entries
  }, [explanation])

  return (
    <Card className="w-full h-full border rounded-xl shadow-sm bg-background">
      <CardHeader className="flex items-center justify-between">
        <CardTitle className="text-base font-semibold flex gap-2 items-center">
          Мультимодальное объяснение
          <Tooltip>
            <TooltipTrigger>
              <Image className="w-4 h-4 text-muted-foreground" />
            </TooltipTrigger>
            <TooltipContent className="text-xs">
              Комбинированный просмотр объяснений на основе изображений, текста и логики модели.
            </TooltipContent>
          </Tooltip>
        </CardTitle>
        <Badge variant="outline" className="text-[10px] font-mono">
          Модель: {explanation.model ?? 'не указана'}
        </Badge>
      </CardHeader>

      <CardContent className="space-y-4">
        {isLoading ? (
          <Skeleton className="w-full h-32" />
        ) : (
          <Tabs value={mode} onValueChange={(v) => setMode(v as any)}>
            <TabsList className="grid grid-cols-3 w-full">
              {tabs.includes('vision') && <TabsTrigger value="vision">Визуально</TabsTrigger>}
              {tabs.includes('text') && <TabsTrigger value="text">Текст</TabsTrigger>}
              {tabs.includes('logic') && <TabsTrigger value="logic">Логика</TabsTrigger>}
            </TabsList>

            {hasVision && (
              <TabsContent value="vision">
                <ExplanationOverlay heatmapUrl={explanation.vision?.heatmapUrl} regions={explanation.vision?.regions} />
              </TabsContent>
            )}
            {hasText && (
              <TabsContent value="text">
                <div className="flex flex-wrap gap-1 text-sm">
                  {explanation.text?.tokens.map((tok, idx) => {
                    const score = explanation.text?.scores[idx] ?? 0
                    const bg = `rgba(255, 0, 0, ${Math.abs(score)})`
                    return (
                      <span
                        key={idx}
                        className="px-1 rounded"
                        style={{
                          backgroundColor: score > 0 ? `rgba(0, 200, 0, ${score})` : bg,
                          color: score > 0.5 || score < -0.5 ? 'white' : 'black',
                        }}
                      >
                        {tok}
                      </span>
                    )
                  })}
                </div>
              </TabsContent>
            )}
            {hasLogic && (
              <TabsContent value="logic">
                <ExplanationTimeline steps={explanation.logic?.steps ?? []} />
              </TabsContent>
            )}
          </Tabs>
        )}
      </CardContent>
    </Card>
  )
}
