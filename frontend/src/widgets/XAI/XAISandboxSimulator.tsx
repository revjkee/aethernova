// src/widgets/XAI/XAISandboxSimulator.tsx

import React, { useState, useEffect, useCallback } from 'react'
import { Panel } from '@/shared/ui/Panel'
import { SimulatorControlPanel } from './controls/SimulatorControlPanel'
import { SimulationOutputPanel } from './output/SimulationOutputPanel'
import { ExplainabilityOverlay } from './explainability/ExplainabilityOverlay'
import { useXAIContext } from '@/shared/context/XAIContext'
import { runModelSimulation, SimulationInput, SimulationResult } from '@/services/xai/simulationService'
import { XAIFrameworkSelector } from './controls/XAIFrameworkSelector'
import { Alert } from '@/shared/ui/Alert'
import './XAISandboxSimulator.css'

export const XAISandboxSimulator: React.FC = () => {
  const { selectedModel, triggerGlobalAlert } = useXAIContext()

  const [inputScenario, setInputScenario] = useState<SimulationInput | null>(null)
  const [result, setResult] = useState<SimulationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [framework, setFramework] = useState<'SHAP' | 'LIME' | 'IG' | 'LocalRules'>('SHAP')

  const runSimulation = useCallback(async () => {
    if (!selectedModel || !inputScenario) return

    setLoading(true)
    setError(null)
    try {
      const simResult = await runModelSimulation(selectedModel.id, inputScenario, framework)
      setResult(simResult)
    } catch (err) {
      setError('Симуляция не удалась. Проверьте параметры.')
      triggerGlobalAlert('Ошибка симуляции модели', 'error')
    } finally {
      setLoading(false)
    }
  }, [selectedModel, inputScenario, framework, triggerGlobalAlert])

  useEffect(() => {
    if (inputScenario) runSimulation()
  }, [inputScenario, runSimulation])

  return (
    <Panel title="XAI Sandbox — симуляция решений модели">
      <div className="xai-sandbox-container">
        <div className="xai-sandbox-controls">
          <SimulatorControlPanel
            onSubmit={setInputScenario}
            disabled={loading}
            defaultModel={selectedModel}
          />
          <XAIFrameworkSelector
            current={framework}
            onChange={setFramework}
          />
        </div>

        {error && <Alert type="error">{error}</Alert>}

        <div className="xai-sandbox-output">
          <SimulationOutputPanel
            result={result}
            loading={loading}
            framework={framework}
          />
          {result && result.explanation && (
            <ExplainabilityOverlay
              explanation={result.explanation}
              input={inputScenario}
              framework={framework}
            />
          )}
        </div>
      </div>
    </Panel>
  )
}
