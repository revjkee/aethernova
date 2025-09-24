// src/widgets/XAI/ExplanationConfidenceMeter.tsx

import React, { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { useConfidenceService } from '@/services/xaiConfidenceService'
import { Tooltip } from '@/shared/components/Tooltip'
import { ShieldAlert, Info, Sparkles } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'

interface Props {
  explanationId: string
}

interface ConfidenceData {
  score: number // 0.0–1.0
  method: string
  uncertainty: number // стандартное отклонение
  instabilityIndex: number // индекс волатильности объяснения (0-1)
  lastVerified: string
  auditLogLink?: string
  sourceModels: string[]
}

export const ExplanationConfidenceMeter: React.FC<Props> = ({ explanationId }) => {
  const [data, setData] = useState<ConfidenceData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { fetchConfidence } = useConfidenceService()
  const { theme } = useTheme()

  useEffect(() => {
    const load = async () => {
      try {
        const result = await fetchConfidence(explanationId)
        setData(result)
      } catch (err) {
        setError('Не удалось получить надёжность объяснения.')
      }
    }

    load()
  }, [explanationId, fetchConfidence])

  if (error) return <div className="text-red-500 text-center text-sm">{error}</div>
  if (!data) return <div className="text-center text-gray-400 text-sm">Загрузка...</div>

  const confidenceColor = (score: number) => {
    if (score > 0.85) return 'bg-green-500'
    if (score > 0.65) return 'bg-yellow-500'
    if (score > 0.4) return 'bg-orange-500'
    return 'bg-red-500'
  }

  const labelForScore = (score: number) => {
    if (score > 0.85) return 'Высокая надёжность'
    if (score > 0.65) return 'Умеренная надёжность'
    if (score > 0.4) return 'Низкая надёжность'
    return 'Сомнительное объяснение'
  }

  return (
    <div
      className={cn(
        'p-4 border rounded-lg shadow-sm space-y-3',
        theme === 'dark' ? 'bg-zinc-900 border-zinc-700 text-white' : 'bg-white border-zinc-200 text-black'
      )}
    >
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-base">Надёжность объяснения</h3>
        <Tooltip content="Confidence Score — агрегированный уровень доверия к объяснению от всех XAI-модулей">
          <Info size={16} className="text-gray-400" />
        </Tooltip>
      </div>

      <div className="relative w-full h-6 bg-gray-200 rounded">
        <motion.div
          className={cn('absolute h-6 rounded transition-all', confidenceColor(data.score))}
          initial={{ width: 0 }}
          animate={{ width: `${(data.score * 100).toFixed(1)}%` }}
        />
        <div className="absolute w-full h-6 flex justify-center items-center text-xs font-medium text-white">
          {labelForScore(data.score)} ({(data.score * 100).toFixed(1)}%)
        </div>
      </div>

      <div className="text-sm space-y-1">
        <div>
          <span className="text-gray-500">Метод оценки:</span> {data.method}
        </div>
        <div>
          <span className="text-gray-500">Стандартное отклонение:</span> {data.uncertainty.toFixed(3)}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-gray-500">Индекс нестабильности:</span>
          <span
            className={cn(
              'rounded-full h-3 w-3 inline-block',
              data.instabilityIndex > 0.7
                ? 'bg-red-500'
                : data.instabilityIndex > 0.4
                ? 'bg-yellow-500'
                : 'bg-green-500'
            )}
          ></span>
          <span>{(data.instabilityIndex * 100).toFixed(1)}%</span>
          {data.instabilityIndex > 0.8 && (
            <Tooltip content="Объяснение может быть непоследовательным при повторном вызове">
              <ShieldAlert size={14} className="text-red-600" />
            </Tooltip>
          )}
        </div>
        <div>
          <span className="text-gray-500">Последняя верификация:</span> {data.lastVerified}
        </div>
        <div className="text-xs text-gray-500">
          Модели: {data.sourceModels.join(', ')}
        </div>
        {data.auditLogLink && (
          <a
            href={data.auditLogLink}
            className="text-xs underline text-blue-500"
            target="_blank"
            rel="noreferrer"
          >
            Аудит лог →
          </a>
        )}
      </div>

      {data.score > 0.9 && (
        <div className="flex items-center gap-2 text-sm text-green-600">
          <Sparkles size={16} /> Объяснение подтверждено несколькими методами
        </div>
      )}
    </div>
  )
}
