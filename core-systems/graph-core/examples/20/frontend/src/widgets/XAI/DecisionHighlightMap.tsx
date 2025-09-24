import React, { Suspense, useEffect, useMemo, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useDecisionFactors } from '@/hooks/xai/useDecisionFactors'
import { HighlightOverlay } from '@/components/overlay/HighlightOverlay'
import { FactorHeatLegend } from '@/components/legend/FactorHeatLegend'
import { XAITrustOverlay } from '@/components/overlay/XAITrustOverlay'
import { AnimatePresence, motion } from 'framer-motion'
import { useUserPreferences } from '@/hooks/preferences/useUserPreferences'
import { useZKVerification } from '@/hooks/xai/useZKVerification'

const DecisionDetailPopup = React.lazy(() => import('./internal/DecisionDetailPopup'))
const FactorScoreBadge = React.lazy(() => import('./internal/FactorScoreBadge'))

export const DecisionHighlightMap: React.FC<{ decisionId: string }> = ({ decisionId }) => {
  const { data, loading, error } = useDecisionFactors(decisionId)
  const [selectedFactor, setSelectedFactor] = useState<string | null>(null)
  const { preferences } = useUserPreferences()
  const { isVerified, zkLoading } = useZKVerification(decisionId)

  const sortedFactors = useMemo(() => {
    if (!data?.factors) return []
    return [...data.factors].sort((a, b) => b.importance - a.importance)
  }, [data])

  useEffect(() => {
    if (!selectedFactor && sortedFactors.length > 0) {
      setSelectedFactor(sortedFactors[0].id)
    }
  }, [sortedFactors])

  if (loading || zkLoading) {
    return (
      <Card className="w-full h-[400px] flex items-center justify-center">
        <Skeleton className="w-1/2 h-24" />
      </Card>
    )
  }

  if (error || !data) {
    return (
      <Card className="w-full h-[400px] p-6 text-red-600">
        <p>Не удалось загрузить факторы решения.</p>
      </Card>
    )
  }

  return (
    <Card className="relative overflow-hidden bg-background border border-muted/60">
      <CardContent className="grid md:grid-cols-6 gap-4 p-4">
        <div className="col-span-4 space-y-2">
          <h2 className="text-lg font-semibold text-foreground">Карта влияющих факторов</h2>
          <div className="relative">
            <HighlightOverlay
              highlights={sortedFactors}
              activeId={selectedFactor}
              onSelect={setSelectedFactor}
              intensity={preferences.highlightIntensity}
            />
            <XAITrustOverlay isVerified={isVerified} />
          </div>
        </div>
        <div className="col-span-2 flex flex-col gap-2 overflow-auto max-h-[340px]">
          {sortedFactors.map((factor) => (
            <Suspense fallback={<Skeleton className="h-10 w-full rounded-lg" />} key={factor.id}>
              <FactorScoreBadge
                key={factor.id}
                id={factor.id}
                label={factor.label}
                importance={factor.importance}
                selected={factor.id === selectedFactor}
                onSelect={() => setSelectedFactor(factor.id)}
              />
            </Suspense>
          ))}
        </div>
      </CardContent>

      <AnimatePresence>
        {selectedFactor && (
          <Suspense fallback={null}>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 20 }}
              transition={{ duration: 0.2 }}
              className="absolute bottom-0 left-0 w-full z-30"
            >
              <DecisionDetailPopup factorId={selectedFactor} />
            </motion.div>
          </Suspense>
        )}
      </AnimatePresence>

      <div className="absolute top-4 right-4 z-40">
        <FactorHeatLegend />
      </div>
    </Card>
  )
}
