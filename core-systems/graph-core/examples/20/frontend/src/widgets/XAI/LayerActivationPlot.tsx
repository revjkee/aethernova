import React, { useState, useEffect, Suspense, useMemo } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useLayerActivations } from '@/hooks/xai/useLayerActivations'
import { useZKActivationVerifier } from '@/hooks/xai/useZKActivationVerifier'
import { ZoomableCanvas } from '@/components/charts/ZoomableCanvas'
import { useModelMeta } from '@/hooks/xai/useModelMeta'
import { ActivationLegend } from '@/components/ui/legends/ActivationLegend'
import { LayerSelector } from '@/components/controls/LayerSelector'
import { ActivationGradientBar } from '@/components/ui/ActivationGradientBar'
import { HeatMapMatrix } from '@/components/xai/HeatMapMatrix'
import { ZKProofBadge } from '@/components/ui/Badges/ZKProofBadge'
import { AnimatePresence, motion } from 'framer-motion'

const LayerSummary = React.lazy(() => import('./internal/LayerSummary'))

export const LayerActivationPlot: React.FC<{ modelId: string; inputHash: string }> = ({
  modelId,
  inputHash,
}) => {
  const [selectedLayer, setSelectedLayer] = useState<number>(0)

  const { layers, loading: metaLoading } = useModelMeta(modelId)
  const { activations, loading: actLoading, error } = useLayerActivations(modelId, inputHash)
  const { isVerified, zkLoading } = useZKActivationVerifier(modelId, inputHash)

  const layerData = useMemo(() => {
    if (!activations || !activations[selectedLayer]) return []
    return activations[selectedLayer]
  }, [activations, selectedLayer])

  if (metaLoading || actLoading || zkLoading) {
    return (
      <Card className="w-full h-[420px] flex items-center justify-center">
        <Skeleton className="w-4/5 h-20" />
      </Card>
    )
  }

  if (error || !layerData) {
    return (
      <Card className="w-full h-[420px] p-6 text-red-600">
        <p>Ошибка загрузки активаций слоя модели. Попробуйте позже или проверьте модельные вычисления.</p>
      </Card>
    )
  }

  return (
    <Card className="relative border border-border/30 bg-background shadow-md overflow-hidden">
      <CardContent className="flex flex-col gap-4 p-5">
        <div className="flex justify-between items-center">
          <h2 className="text-lg font-bold text-foreground">Активации слоя #{selectedLayer}</h2>
          <ZKProofBadge verified={isVerified} />
        </div>

        <LayerSelector
          layers={layers}
          selected={selectedLayer}
          onChange={(idx) => setSelectedLayer(idx)}
        />

        <div className="relative w-full h-[320px] rounded-lg bg-muted overflow-hidden">
          <ZoomableCanvas
            data={layerData}
            height={320}
            colorMap="plasma"
            axisLabels={['Нейроны', 'Входные фрагменты']}
            pixelRatio={1.5}
          />
        </div>

        <ActivationGradientBar min={0} max={1} label="Интенсивность активации" />

        <AnimatePresence mode="wait">
          <motion.div
            key={`summary-${selectedLayer}`}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 10 }}
            transition={{ duration: 0.2 }}
          >
            <Suspense fallback={<Skeleton className="h-32 w-full" />}>
              <LayerSummary layerIndex={selectedLayer} modelId={modelId} />
            </Suspense>
          </motion.div>
        </AnimatePresence>

        <div className="mt-4">
          <HeatMapMatrix
            matrix={layerData}
            colorRange="viridis"
            labelLeft="Нейрон"
            labelTop="Фрагмент входа"
            cellTooltip={(value, x, y) => `Нейрон ${y}, вход ${x}: ${value.toFixed(3)}`}
          />
        </div>

        <ActivationLegend />
      </CardContent>
    </Card>
  )
}
