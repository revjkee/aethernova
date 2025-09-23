// src/widgets/XAI/ExplainabilityScoreBadge.tsx

import React, { useEffect, useState } from 'react'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { Info, ShieldCheck, AlertCircle } from 'lucide-react'
import { Tooltip } from '@/shared/components/Tooltip'

interface Props {
  moduleId: string
  size?: 'sm' | 'md' | 'lg'
}

interface ExplainabilityScore {
  score: number // 0.0 - 1.0
  label: string
  verified: boolean
  metrics: {
    faithfulness: number
    clarity: number
    stability: number
    compactness: number
    redundancy: number
  }
  lastAudit: string
  evaluator: string
}

export const ExplainabilityScoreBadge: React.FC<Props> = ({ moduleId, size = 'md' }) => {
  const { theme } = useTheme()
  const [scoreData, setScoreData] = useState<ExplainabilityScore | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch(`/api/xai/score/${moduleId}`)
      .then((res) => res.json())
      .then(setScoreData)
      .catch(() => setError('Ошибка загрузки XAI-оценки'))
  }, [moduleId])

  if (error || !scoreData) {
    return (
      <div className={cn('text-xs', theme === 'dark' ? 'text-red-400' : 'text-red-600')}>
        {error || 'Загрузка...'}
      </div>
    )
  }

  const colorByScore = (score: number) => {
    if (score > 0.85) return 'bg-green-600 text-white'
    if (score > 0.65) return 'bg-yellow-500 text-white'
    if (score > 0.45) return 'bg-orange-500 text-white'
    return 'bg-red-600 text-white'
  }

  const sizeClass = {
    sm: 'px-2 py-0.5 text-xs rounded-sm',
    md: 'px-3 py-1 text-sm rounded',
    lg: 'px-4 py-1.5 text-base rounded-lg'
  }

  return (
    <div className={cn('inline-flex items-center gap-1', sizeClass[size], colorByScore(scoreData.score))}>
      <span>
        XAI: {(scoreData.score * 100).toFixed(1)}%
      </span>
      {scoreData.verified ? (
        <Tooltip content="Аудит подтверждён">
          <ShieldCheck size={14} className="text-white" />
        </Tooltip>
      ) : (
        <Tooltip content="Оценка не верифицирована">
          <AlertCircle size={14} className="text-white" />
        </Tooltip>
      )}
      <Tooltip
        content={
          <div className="text-xs space-y-1">
            <div><strong>{scoreData.label}</strong></div>
            <div>Faithfulness: {(scoreData.metrics.faithfulness * 100).toFixed(1)}%</div>
            <div>Clarity: {(scoreData.metrics.clarity * 100).toFixed(1)}%</div>
            <div>Stability: {(scoreData.metrics.stability * 100).toFixed(1)}%</div>
            <div>Compactness: {(scoreData.metrics.compactness * 100).toFixed(1)}%</div>
            <div>Redundancy: {(scoreData.metrics.redundancy * 100).toFixed(1)}%</div>
            <div className="text-gray-300">Аудитор: {scoreData.evaluator}</div>
            <div className="text-gray-300">Проверено: {scoreData.lastAudit}</div>
          </div>
        }
      >
        <Info size={14} className="text-white" />
      </Tooltip>
    </div>
  )
}
