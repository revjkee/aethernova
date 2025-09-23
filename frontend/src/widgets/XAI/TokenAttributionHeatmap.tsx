// src/widgets/XAI/TokenAttributionHeatmap.tsx

import React, { useEffect, useState } from 'react'
import { useTokenAttributionService } from '@/services/xaiAttributionService'
import { Tooltip } from '@/shared/components/Tooltip'
import { Switch } from '@/shared/components/Switch'
import { Select } from '@/shared/components/Select'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { AnimatePresence, motion } from 'framer-motion'

interface TokenAttribution {
  token: string
  score: number
  attention?: number
}

interface AttributionPayload {
  tokens: TokenAttribution[]
  method: 'integrated-gradients' | 'shap' | 'attention' | 'gradcam'
  confidence: number
  predictedClass: string
}

interface Props {
  messageId: string
}

export const TokenAttributionHeatmap: React.FC<Props> = ({ messageId }) => {
  const [data, setData] = useState<AttributionPayload | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showScores, setShowScores] = useState(false)
  const [mode, setMode] = useState<'score' | 'attention'>('score')
  const { fetchAttribution } = useTokenAttributionService()
  const { theme } = useTheme()

  useEffect(() => {
    const load = async () => {
      try {
        const result = await fetchAttribution(messageId)
        setData(result)
      } catch {
        setError('Не удалось загрузить карту влияния токенов.')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [messageId, fetchAttribution])

  const colorScale = (val: number) => {
    const clamped = Math.max(-1, Math.min(1, val))
    const alpha = Math.abs(clamped)
    const color = clamped >= 0 ? 'rgba(0, 200, 0,' : 'rgba(200, 0, 0,'
    return `${color} ${alpha.toFixed(2)})`
  }

  if (loading) {
    return <div className="p-4 flex justify-center"><Spinner /></div>
  }

  if (error || !data) {
    return <div className="text-red-500 text-sm text-center">{error || 'Нет данных'}</div>
  }

  const tokens = data.tokens

  return (
    <div
      className={cn(
        'p-4 border rounded shadow-sm space-y-4 max-w-full',
        theme === 'dark' ? 'bg-zinc-900 border-zinc-700 text-white' : 'bg-white border-zinc-200 text-black'
      )}
    >
      <div className="flex flex-wrap justify-between items-center gap-4">
        <div className="font-semibold text-base">
          Влияние токенов (Method: {data.method}, Class: {data.predictedClass})
        </div>
        <div className="flex gap-4 items-center">
          <Select
            label="Режим"
            options={[
              { label: 'Score', value: 'score' },
              { label: 'Attention', value: 'attention' }
            ]}
            value={mode}
            onChange={(val) => setMode(val as any)}
          />
          <Switch
            checked={showScores}
            onChange={setShowScores}
            label="Показать значения"
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-1 justify-start items-center">
        {tokens.map((tok, idx) => {
          const value = mode === 'score' ? tok.score : tok.attention ?? 0
          return (
            <Tooltip
              key={idx}
              content={`${tok.token} → ${value.toFixed(3)}`}
              className="cursor-default"
            >
              <motion.span
                initial={{ opacity: 0.6 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.2 }}
                style={{
                  backgroundColor: colorScale(value),
                  padding: '4px 6px',
                  borderRadius: '4px',
                  fontFamily: 'monospace',
                  fontSize: '0.875rem'
                }}
              >
                {tok.token}{showScores && ` (${value.toFixed(2)})`}
              </motion.span>
            </Tooltip>
          )
        })}
      </div>

      <div className="text-xs text-gray-400 mt-2">
        Уверенность модели: {(data.confidence * 100).toFixed(1)}%
      </div>
    </div>
  )
}
