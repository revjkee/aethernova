// Clean ExplanationDeltaViewer component
import React, { useEffect, useMemo, useState } from 'react'
import { Panel } from '@/shared/ui/Panel'
import { useXAIContext } from '@/shared/context/XAIContext'
import { ExplanationComparison, ExplanationPayload } from '@/types/xai/ExplanationTypes'
import { fetchExplanationDiff } from '@/services/xai/explanationDiffService'
import { DeltaHeatmap } from './DeltaHeatmap'
import { FeedbackTimeline } from './FeedbackTimeline'
import { Alert } from '@/shared/ui/Alert'
import { ExplanationDetailsCard } from './ExplanationDetailsCard'
import { useAsync } from '@/shared/hooks/useAsync'
import './ExplanationDeltaViewer.css'

interface Props {
  currentVersion: string
  previousVersion: string
  inputId: string
}

export const ExplanationDeltaViewer: React.FC<Props> = ({ currentVersion, previousVersion, inputId }) => {
  const { modelRegistry } = useXAIContext()
  const [delta, setDelta] = useState<ExplanationComparison | null>(null)
  const [error, setError] = useState<string | null>(null)

  const currentModel = useMemo(() => modelRegistry[currentVersion], [modelRegistry, currentVersion])
  const previousModel = useMemo(() => modelRegistry[previousVersion], [modelRegistry, previousVersion])

  const { execute: loadDiff, isLoading } = useAsync(async () => {
    setError(null)
    try {
      const diff = await fetchExplanationDiff({
        currentModelId: currentVersion,
        previousModelId: previousVersion,
        inputId,
      })
      setDelta(diff)
    } catch (err: any) {
      setError('Ошибка при загрузке различий объяснений.')
    }
  })

  useEffect(() => {
    if (currentVersion && previousVersion && inputId) {
      loadDiff()
    }
  }, [currentVersion, previousVersion, inputId, loadDiff])

  return (
    <Panel title="Сравнение объяснений версий модели (XAI Delta)">
      {isLoading && <p>Загрузка различий...</p>}
      {error && <Alert type="error">{error}</Alert>}
      {delta && (
        <div className="explanation-delta-viewer">
          <div className="version-header">
            <span className="model-version old">v{previousVersion}</span>
            <span className="arrow">→</span>
            <span className="model-version new">v{currentVersion}</span>
          </div>

          <div className="xai-diff-panels">
            <ExplanationDetailsCard
              title="Предыдущее объяснение"
              explanation={delta.previous as ExplanationPayload}
              version={previousVersion}
              type="old"
            />
            <ExplanationDetailsCard
              title="Текущее объяснение"
              explanation={delta.current as ExplanationPayload}
              version={currentVersion}
              type="new"
            />
          </div>

          <DeltaHeatmap changes={delta.deltaMap} />

          <FeedbackTimeline feedback={delta.feedbackTimeline} />

          {delta.deltaScore > 0.7 && (
            <Alert type="warning">{">70%"} значительное изменение объяснения: возможна деградация reasoning.</Alert>
          )}

          {delta.deltaScore < 0.1 && (
            <Alert type="success">Объяснения стабильны между версиями (разница менее 10%).</Alert>
          )}
        </div>
      )}
    </Panel>
  )
}

