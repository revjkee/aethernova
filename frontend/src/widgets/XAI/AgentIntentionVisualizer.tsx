// src/widgets/XAI/AgentIntentionVisualizer.tsx

import React, { useEffect, useState } from 'react'
import { useIntentionService } from '@/services/xaiIntentionService'
import { Spinner } from '@/shared/components/Spinner'
import { Tooltip } from '@/shared/components/Tooltip'
import { motion } from 'framer-motion'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { AgentIntention } from '@/types/xai'
import { IntentionTree } from './IntentionTree'
import { ConflictMarker } from './ConflictMarker'

interface Props {
  agentId: string
  traceDepth?: number
}

export const AgentIntentionVisualizer: React.FC<Props> = ({ agentId, traceDepth = 3 }) => {
  const [intentions, setIntentions] = useState<AgentIntention[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { fetchIntentionTree } = useIntentionService()
  const { theme } = useTheme()

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchIntentionTree(agentId, traceDepth)
        setIntentions(data)
      } catch (e) {
        setError('Не удалось загрузить намерения агента.')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [agentId, traceDepth, fetchIntentionTree])

  if (loading) return <div className="p-4 flex justify-center"><Spinner /></div>
  if (error) return <div className="text-red-500 text-center">{error}</div>
  if (!intentions || intentions.length === 0) return <div className="text-center text-gray-400 text-sm">Намерений не обнаружено</div>

  return (
    <div
      className={cn(
        'rounded border shadow-sm p-4 space-y-4 overflow-x-auto max-w-full',
        theme === 'dark' ? 'bg-zinc-900 border-zinc-700 text-white' : 'bg-white border-zinc-200 text-black'
      )}
    >
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold">Намерения агента</h2>
        <div className="text-xs text-gray-400">
          Глубина анализа: {traceDepth}
        </div>
      </div>

      {intentions.map((intent, idx) => (
        <motion.div
          key={idx}
          className="p-3 border rounded-lg space-y-2"
          initial={{ opacity: 0.7, y: 5 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
        >
          <div className="flex justify-between items-center">
            <div>
              <span className="font-medium">{intent.action}</span>
              <span className="ml-2 text-xs text-gray-500">→ {intent.target}</span>
            </div>
            <div className="text-xs text-right text-gray-400">
              Вероятность: {(intent.confidence * 100).toFixed(1)}%
            </div>
          </div>

          {intent.conflict && (
            <ConflictMarker level={intent.conflict.severity} reason={intent.conflict.reason} />
          )}

          <IntentionTree trace={intent.reasoning} maxDepth={traceDepth} />
        </motion.div>
      ))}
    </div>
  )
}
