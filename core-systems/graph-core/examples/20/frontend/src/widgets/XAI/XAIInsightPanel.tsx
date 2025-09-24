// src/widgets/XAI/XAIInsightPanel.tsx

import React, { useEffect, useState } from 'react'
import { useExplainabilityEngine } from '@/services/xaiService'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'
import { Flame, Brain, HelpCircle, Eye } from 'lucide-react'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { motion, AnimatePresence } from 'framer-motion'

interface FeatureWeight {
  name: string
  weight: number
  type: 'positive' | 'negative' | 'neutral'
}

interface InsightPayload {
  decisionSummary: string
  topInfluences: FeatureWeight[]
  ruleChains: string[]
  explanationLevel: 'basic' | 'advanced'
  agentName: string
  timestamp: number
  confidence: number
}

interface Props {
  inputId: string // Идентификатор объекта, к которому относится объяснение
}

export const XAIInsightPanel: React.FC<Props> = ({ inputId }) => {
  const [insight, setInsight] = useState<InsightPayload | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const { fetchInsights } = useExplainabilityEngine()
  const { theme } = useTheme()

  useEffect(() => {
    const load = async () => {
      try {
        const result = await fetchInsights(inputId)
        setInsight(result)
      } catch (e) {
        setError('Не удалось загрузить объяснение модели.')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [inputId, fetchInsights])

  if (loading) {
    return (
      <div className="flex justify-center items-center p-4">
        <Spinner />
      </div>
    )
  }

  if (error || !insight) {
    return (
      <div className="text-sm text-center text-red-500">{error || 'Объяснение не найдено'}</div>
    )
  }

  const barColor = (type: FeatureWeight['type']) => {
    switch (type) {
      case 'positive': return 'bg-green-500'
      case 'negative': return 'bg-red-500'
      case 'neutral': return 'bg-gray-500'
    }
  }

  return (
    <motion.div
      className={cn(
        'border rounded-md p-4 shadow-sm space-y-4',
        theme === 'dark' ? 'bg-gray-900 border-gray-700 text-white' : 'bg-white border-gray-200 text-black'
      )}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <div className="flex items-center gap-2 text-xl font-semibold">
        <Eye className="w-6 h-6" />
        Объяснение решения AI
      </div>

      <div className="text-sm opacity-80">
        <p className="mb-1">
          <Brain className="inline-block w-4 h-4 mr-1" />
          <strong>Агент:</strong> {insight.agentName}
        </p>
        <p className="mb-1">
          <Flame className="inline-block w-4 h-4 mr-1" />
          <strong>Уверенность:</strong> {Math.round(insight.confidence * 100)}%
        </p>
        <p className="mb-1">
          <HelpCircle className="inline-block w-4 h-4 mr-1" />
          <strong>Обзор:</strong> {insight.decisionSummary}
        </p>
        <p className="text-xs text-gray-500 mt-1">
          Время: {new Date(insight.timestamp).toLocaleString()}
        </p>
      </div>

      <div>
        <h4 className="font-semibold text-sm mb-2">Топ факторов влияния:</h4>
        <ul className="space-y-2">
          {insight.topInfluences.map((f, i) => (
            <li key={i}>
              <div className="flex justify-between text-sm">
                <span>{f.name}</span>
                <span className="opacity-70">{(f.weight * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full h-2 rounded bg-gray-200 dark:bg-gray-700 mt-1 overflow-hidden">
                <div
                  className={cn(barColor(f.type), 'h-2')}
                  style={{ width: `${Math.abs(f.weight * 100)}%` }}
                />
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h4 className="font-semibold text-sm mt-4 mb-2">Логическая цепочка:</h4>
        <ul className="text-xs pl-4 list-disc opacity-90 space-y-1">
          {insight.ruleChains.map((rule, idx) => (
            <li key={idx}>{rule}</li>
          ))}
        </ul>
      </div>
    </motion.div>
  )
}
