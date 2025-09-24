import React, { useEffect, useMemo, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Slider } from '@/components/ui/slider'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Skeleton } from '@/components/ui/skeleton'
import { ChevronUp, ChevronDown, Info } from 'lucide-react'
import clsx from 'clsx'

interface CausalFactor {
  id: string
  name: string
  impactScore: number // from -1 to +1
  confidence: number // 0–1
  type: 'positive' | 'negative' | 'neutral'
  description?: string
}

interface Props {
  factors: CausalFactor[]
  isLoading?: boolean
  filterThreshold?: number
}

export const CausalImpactMeter: React.FC<Props> = ({
  factors,
  isLoading = false,
  filterThreshold = 0.05,
}) => {
  const [threshold, setThreshold] = useState(filterThreshold)

  const filteredFactors = useMemo(() => {
    return factors
      .filter((f) => Math.abs(f.impactScore) >= threshold)
      .sort((a, b) => Math.abs(b.impactScore) - Math.abs(a.impactScore))
  }, [factors, threshold])

  return (
    <Card className="w-full shadow-md border rounded-xl bg-background">
      <CardHeader>
        <CardTitle className="text-base font-semibold flex items-center gap-2">
          Причинное влияние факторов
          <Tooltip>
            <TooltipTrigger>
              <Info className="w-4 h-4 text-muted-foreground" />
            </TooltipTrigger>
            <TooltipContent className="text-xs max-w-xs">
              Отображает, какие признаки оказали наибольшее влияние на итоговое решение модели. Баланс между значением влияния и уверенностью в причинной связи.
            </TooltipContent>
          </Tooltip>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-3">
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Порог отображения: {threshold.toFixed(2)}</span>
          <Slider
            defaultValue={[threshold]}
            min={0}
            max={1}
            step={0.01}
            onValueChange={(val) => setThreshold(val[0])}
            className="w-[140px]"
          />
        </div>

        {isLoading ? (
          Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-5 w-full" />)
        ) : filteredFactors.length === 0 ? (
          <div className="text-xs text-muted-foreground">Нет значимых факторов.</div>
        ) : (
          <div className="space-y-2">
            {filteredFactors.map((f) => (
              <div key={f.id} className="flex flex-col gap-1">
                <div className="flex justify-between items-center text-sm">
                  <span className="font-mono text-xs">{f.name}</span>
                  <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0.5">
                    Conf: {(f.confidence * 100).toFixed(1)}%
                  </Badge>
                </div>
                <div
                  className={clsx(
                    'relative h-2 rounded bg-muted overflow-hidden transition-all',
                    f.impactScore >= 0 ? 'bg-green-100' : 'bg-red-100'
                  )}
                >
                  <div
                    className={clsx(
                      'absolute top-0 bottom-0',
                      f.impactScore >= 0 ? 'bg-green-500' : 'bg-red-500'
                    )}
                    style={{
                      left: f.impactScore >= 0 ? '50%' : `${50 + f.impactScore * 50}%`,
                      width: `${Math.abs(f.impactScore) * 50}%`,
                    }}
                  />
                </div>
                {f.description && (
                  <div className="text-[11px] text-muted-foreground font-mono italic">
                    {f.description}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
