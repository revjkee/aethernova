import React, { useEffect, useMemo, useState } from 'react'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Button } from '@/components/ui/button'
import { Check, ChevronDown } from 'lucide-react'
import { useMetricSettingsStore } from '@/state/metricSettings'
import { motion, AnimatePresence } from 'framer-motion'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/shared/utils/classNames'

type AggregationType =
  | 'mean'
  | 'sum'
  | 'median'
  | 'min'
  | 'max'
  | 'p95'
  | 'p99'
  | 'count'
  | 'none'

const AGGREGATION_LABELS: Record<AggregationType, string> = {
  mean: 'Среднее',
  sum: 'Сумма',
  median: 'Медиана',
  min: 'Мин.',
  max: 'Макс.',
  p95: '95-й процентиль',
  p99: '99-й процентиль',
  count: 'Количество',
  none: 'Без агрегации',
}

const AGGREGATION_DESCRIPTIONS: Record<AggregationType, string> = {
  mean: 'Среднее арифметическое значений метрики',
  sum: 'Общая сумма значений за период',
  median: 'Центральное значение отсортированных данных',
  min: 'Минимальное значение',
  max: 'Максимальное значение',
  p95: '95% значений меньше или равны',
  p99: '99% значений меньше или равны',
  count: 'Количество измерений',
  none: 'Исходные значения без агрегации',
}

const AGGREGATION_ORDER: AggregationType[] = [
  'mean', 'sum', 'median', 'min', 'max', 'p95', 'p99', 'count', 'none',
]

export const MetricAggregationSelector: React.FC = () => {
  const {
    selectedAggregation,
    setAggregation,
    availableAggregations,
    fetchAvailableAggregations,
  } = useMetricSettingsStore()

  const [open, setOpen] = useState(false)

  useEffect(() => {
    fetchAvailableAggregations()
  }, [])

  const sortedAggregations = useMemo(
    () =>
      AGGREGATION_ORDER.filter(agg =>
        availableAggregations.includes(agg)
      ),
    [availableAggregations]
  )

  const handleSelect = (agg: AggregationType) => {
    setAggregation(agg)
    setOpen(false)
  }

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" role="combobox" aria-haspopup="listbox" aria-expanded={open}>
          <span className="truncate">
            {AGGREGATION_LABELS[selectedAggregation]}
          </span>
          <ChevronDown className="ml-2 h-4 w-4 opacity-60" />
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent className="w-72" side="bottom" align="start">
        <DropdownMenuLabel className="text-sm text-muted-foreground">
          Тип агрегации метрик
        </DropdownMenuLabel>
        <DropdownMenuSeparator />

        {sortedAggregations.map((agg) => (
          <DropdownMenuItem
            key={agg}
            className="flex items-start gap-2 py-2"
            onSelect={() => handleSelect(agg)}
            role="option"
            aria-selected={agg === selectedAggregation}
          >
            <div className="flex items-center justify-center w-4">
              {agg === selectedAggregation && <Check className="w-4 h-4 text-green-500" />}
            </div>
            <div className="flex flex-col">
              <span className={cn('text-sm font-medium', agg === selectedAggregation && 'text-green-600')}>
                {AGGREGATION_LABELS[agg]}
              </span>
              <span className="text-xs text-muted-foreground">
                {AGGREGATION_DESCRIPTIONS[agg]}
              </span>
            </div>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export default MetricAggregationSelector
