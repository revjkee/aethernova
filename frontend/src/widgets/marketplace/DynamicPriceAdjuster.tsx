import React, { useEffect, useState } from 'react'
import { Slider } from '@/components/ui/slider'
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card'
import { usePricingAI } from '@/hooks/ai/usePricingAI'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/shared/utils/classNames'
import { useToast } from '@/components/ui/use-toast'
import { Check, RefreshCcw, AlertCircle } from 'lucide-react'

type DynamicPriceAdjusterProps = {
  productId: string
  basePrice: number
  category: string
  demandLevel: number
  competitorPrice: number
}

export const DynamicPriceAdjuster: React.FC<DynamicPriceAdjusterProps> = ({
  productId,
  basePrice,
  category,
  demandLevel,
  competitorPrice,
}) => {
  const { suggestedPrice, trend, refresh, loading, error } = usePricingAI({
    productId,
    basePrice,
    category,
    demandLevel,
    competitorPrice,
  })

  const [overridePrice, setOverridePrice] = useState<number | null>(null)
  const { toast } = useToast()

  const finalPrice = overridePrice ?? suggestedPrice

  const handleManualSet = () => {
    toast({
      title: 'Цена установлена вручную',
      description: `Вы установили цену: ${finalPrice?.toFixed(2)} ₽`,
    })
  }

  const handleReset = () => {
    setOverridePrice(null)
    refresh()
  }

  useEffect(() => {
    if (overridePrice === null && !loading && !error) {
      setOverridePrice(null)
    }
  }, [suggestedPrice])

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="text-base">AI ценообразование</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col">
          <span className="text-sm text-muted-foreground">Рекомендованная цена</span>
          <div className="text-2xl font-bold">
            {loading ? '...' : `${finalPrice?.toFixed(2)} ₽`}
          </div>
          {error && (
            <div className="text-sm text-red-600 flex items-center gap-2 mt-2">
              <AlertCircle className="w-4 h-4" /> Не удалось получить прогноз
            </div>
          )}
        </div>

        <ResponsiveContainer width="100%" height={160}>
          <LineChart data={trend}>
            <XAxis dataKey="timestamp" hide />
            <YAxis hide domain={['dataMin', 'dataMax']} />
            <Tooltip formatter={(v: number) => `${v.toFixed(2)} ₽`} />
            <Line type="monotone" dataKey="value" stroke="#4f46e5" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>

        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Ручная корректировка</span>
          <Badge variant={overridePrice ? 'default' : 'outline'}>
            {overridePrice ? `Переопределено` : `AI контроль`}
          </Badge>
        </div>

        <Slider
          min={basePrice * 0.5}
          max={basePrice * 2}
          step={1}
          value={[overridePrice ?? suggestedPrice]}
          onValueChange={(v) => setOverridePrice(v[0])}
        />
      </CardContent>

      <CardFooter className="flex gap-2 justify-end">
        <Button
          onClick={handleReset}
          size="sm"
          variant="ghost"
          disabled={loading}
        >
          <RefreshCcw className="w-4 h-4 mr-1" /> Сбросить
        </Button>
        <Button
          onClick={handleManualSet}
          size="sm"
          variant="default"
          disabled={loading}
        >
          <Check className="w-4 h-4 mr-1" /> Применить цену
        </Button>
      </CardFooter>
    </Card>
  )
}

export default DynamicPriceAdjuster
