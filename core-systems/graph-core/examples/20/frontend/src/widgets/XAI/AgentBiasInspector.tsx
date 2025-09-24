import React, { useEffect, useState, Suspense, useMemo } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { AnimatePresence, motion } from 'framer-motion'

import { useBiasAnalysis } from '@/hooks/xai/useBiasAnalysis'
import { useZKVerification } from '@/hooks/xai/useZKVerification'
import { BiasRadarChart } from '@/components/graphs/BiasRadarChart'
import { BiasDimensionTable } from '@/components/tables/BiasDimensionTable'
import { ZKBiasVerifier } from '@/components/overlay/ZKBiasVerifier'
import { BiasImpactExplanation } from '@/components/xai/BiasImpactExplanation'
import { BiasSeverityBadge } from '@/components/ui/Badges/BiasSeverityBadge'
import { useUserPreferences } from '@/hooks/preferences/useUserPreferences'

const BiasTimelineGraph = React.lazy(() => import('./internal/BiasTimelineGraph'))
const BiasMitigationSuggestion = React.lazy(() => import('./internal/BiasMitigationSuggestion'))

export const AgentBiasInspector: React.FC<{ agentId: string; actionContextId: string }> = ({
  agentId,
  actionContextId,
}) => {
  const { preferences } = useUserPreferences()
  const { data, loading, error } = useBiasAnalysis(agentId, actionContextId)
  const { isVerified, zkLoading } = useZKVerification(`${agentId}:${actionContextId}`)

  const [highlightedBias, setHighlightedBias] = useState<string | null>(null)

  const sortedBiases = useMemo(() => {
    if (!data?.biasDimensions) return []
    return [...data.biasDimensions].sort((a, b) => b.severity - a.severity)
  }, [data])

  useEffect(() => {
    if (!highlightedBias && sortedBiases.length > 0) {
      setHighlightedBias(sortedBiases[0].id)
    }
  }, [sortedBiases])

  if (loading || zkLoading) {
    return (
      <Card className="w-full h-[420px] flex items-center justify-center">
        <Skeleton className="w-3/4 h-16" />
      </Card>
    )
  }

  if (error || !data) {
    return (
      <Card className="w-full h-[420px] p-6 text-red-600">
        <p>Ошибка загрузки данных смещений ИИ. Проверьте логику модели или обратитесь в поддержку.</p>
      </Card>
    )
  }

  return (
    <Card className="relative bg-background border border-border/30 shadow-md">
      <CardContent className="grid md:grid-cols-7 gap-6 p-5">
        <div className="col-span-4 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-foreground">Обнаруженные bias-факторы</h2>
            <ZKBiasVerifier verified={isVerified} />
          </div>

          <BiasRadarChart
            dimensions={data.biasDimensions}
            activeId={highlightedBias}
            onSelect={setHighlightedBias}
          />

          <Suspense fallback={<Skeleton className="h-56 w-full rounded-lg" />}>
            <BiasTimelineGraph
              actionContextId={actionContextId}
              agentId={agentId}
              dimensions={data.biasDimensions}
              selectedId={highlightedBias}
              onHover={setHighlightedBias}
            />
          </Suspense>
        </div>

        <div className="col-span-3 flex flex-col gap-4">
          <BiasDimensionTable
            data={sortedBiases}
            activeId={highlightedBias}
            onSelect={setHighlightedBias}
            showZKStatus={isVerified}
          />

          <AnimatePresence mode="wait">
            {highlightedBias && (
              <motion.div
                key={highlightedBias}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
              >
                <BiasImpactExplanation biasId={highlightedBias} />
              </motion.div>
            )}
          </AnimatePresence>

          <Suspense fallback={<Skeleton className="h-20 w-full" />}>
            <BiasMitigationSuggestion biasId={highlightedBias} />
          </Suspense>

          <BiasSeverityBadge score={data.totalBiasScore} />
        </div>
      </CardContent>
    </Card>
  )
}
