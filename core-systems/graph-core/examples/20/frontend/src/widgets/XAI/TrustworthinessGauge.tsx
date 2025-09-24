// src/widgets/XAI/TrustworthinessGauge.tsx

import React, { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { fetchTrustScoreForDecision } from '@/services/xai/api'
import { useXAIContext } from '@/shared/context/XAIContext'
import { Gauge, GaugeLabel, GaugeValue, GaugeTrack } from '@/shared/ui/Gauge'
import { Tooltip } from '@/shared/ui/Tooltip'
import { cn } from '@/shared/utils/cn'
import './TrustworthinessGauge.css'

type Props = {
  decisionId: string
  compact?: boolean
}

type TrustMeta = {
  score: number // 0–100
  explainabilityScore: number // 0–100
  riskFactors: string[]
  confidenceComment?: string
}

export const TrustworthinessGauge: React.FC<Props> = ({ decisionId, compact = false }) => {
  const [data, setData] = useState<TrustMeta | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const { triggerGlobalAlert } = useXAIContext()

  useEffect(() => {
    if (!decisionId) return
    setLoading(true)
    fetchTrustScoreForDecision(decisionId)
      .then(setData)
      .catch(() => {
        triggerGlobalAlert('Ошибка загрузки доверительного индекса', 'error')
        setData(null)
      })
      .finally(() => setLoading(false))
  }, [decisionId])

  const scoreColor = (score: number) => {
    if (score >= 80) return 'var(--xai-green)'
    if (score >= 50) return 'var(--xai-yellow)'
    return 'var(--xai-red)'
  }

  return (
    <div className={cn('trust-gauge-container', compact && 'compact')}>
      <Tooltip content="Общий уровень доверия к решению на основе XAI-анализа, факторов риска и прозрачности.">
        <div className="trust-gauge-label">Уровень доверия</div>
      </Tooltip>

      {loading || !data ? (
        <div className="trust-loading">Загрузка...</div>
      ) : (
        <motion.div
          className="gauge-wrapper"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6 }}
        >
          <Gauge
            value={data.score}
            color={scoreColor(data.score)}
            size={compact ? 80 : 120}
            trackColor="#2e2e2e"
          >
            <GaugeValue value={data.score} suffix="%" />
            <GaugeLabel>Trust Index</GaugeLabel>
          </Gauge>

          <div className="trust-meta">
            <Tooltip content="Насколько хорошо объяснено это решение пользователю">
              <span className="meta-label">Explainability:</span>
            </Tooltip>
            <span className="meta-value">{data.explainabilityScore}%</span>

            <Tooltip content="Факторы риска, влияющие на доверие">
              <span className="meta-label">Риски:</span>
            </Tooltip>
            <ul className="risk-list">
              {data.riskFactors.map((risk, idx) => (
                <li key={idx} className="risk-item">– {risk}</li>
              ))}
            </ul>

            {data.confidenceComment && (
              <div className="ai-comment">
                <Tooltip content="Комментарий модели по достоверности">
                  <span className="meta-label">Комментарий AI:</span>
                </Tooltip>
                <p className="ai-text">{data.confidenceComment}</p>
              </div>
            )}
          </div>
        </motion.div>
      )}
    </div>
  )
}
