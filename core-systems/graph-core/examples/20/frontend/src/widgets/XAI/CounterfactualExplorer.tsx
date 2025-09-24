// src/widgets/XAI/CounterfactualExplorer.tsx

import React, { useEffect, useState } from 'react'
import { useCounterfactualEngine } from '@/services/xaiCounterfactualService'
import { Spinner } from '@/shared/components/Spinner'
import { Slider } from '@/shared/components/Slider'
import { CheckCircle, AlertCircle, RefreshCcw } from 'lucide-react'
import { motion } from 'framer-motion'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useTelegramTheme'

interface InputFeature {
  name: string
  value: number
  min: number
  max: number
  step: number
  type: 'continuous' | 'binary'
}

interface DecisionResult {
  decision: string
  confidence: number
  reason: string
}

interface CounterfactualPayload {
  inputFeatures: InputFeature[]
  originalDecision: DecisionResult
  modifiedDecision: DecisionResult
}

interface Props {
  caseId: string
}

export const CounterfactualExplorer: React.FC<Props> = ({ caseId }) => {
  const [data, setData] = useState<CounterfactualPayload | null>(null)
  const [features, setFeatures] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { fetchCounterfactual, simulate } = useCounterfactualEngine()
  const { theme } = useTheme()

  useEffect(() => {
    const load = async () => {
      try {
        const result = await fetchCounterfactual(caseId)
        setData(result)
        const initialValues = Object.fromEntries(result.inputFeatures.map(f => [f.name, f.value]))
        setFeatures(initialValues)
      } catch (e) {
        setError('Ошибка загрузки контрфактического анализа.')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [caseId, fetchCounterfactual])

  const handleChange = (name: string, value: number) => {
    setFeatures((prev) => ({
      ...prev,
      [name]: value,
    }))
  }

  const [simulated, setSimulated] = useState<DecisionResult | null>(null)
  const [simulating, setSimulating] = useState(false)

  const runSimulation = async () => {
    setSimulating(true)
    try {
      const result = await simulate(features)
      setSimulated(result)
    } catch {
      setError('Не удалось симулировать изменения.')
    } finally {
      setSimulating(false)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center p-4">
        <Spinner />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="text-sm text-center text-red-500">
        {error || 'Нет данных для контрфактического анализа'}
      </div>
    )
  }

  return (
    <div
      className={cn(
        'border rounded-md p-4 shadow-sm space-y-6',
        theme === 'dark' ? 'bg-gray-900 border-gray-700 text-white' : 'bg-white border-gray-200 text-black'
      )}
    >
      <div className="text-base font-semibold flex items-center gap-2">
        <RefreshCcw className="w-5 h-5" />
        Контрфактический анализ
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {data.inputFeatures.map((f) => (
          <div key={f.name}>
            <div className="text-sm font-medium mb-1">{f.name}</div>
            <Slider
              min={f.min}
              max={f.max}
              step={f.step}
              value={features[f.name]}
              onChange={(val) => handleChange(f.name, val)}
            />
            <div className="text-xs text-gray-500 mt-1">
              Текущее значение: {features[f.name].toFixed(2)}
            </div>
          </div>
        ))}
      </div>

      <div className="flex justify-between mt-4 items-center">
        <button
          onClick={runSimulation}
          disabled={simulating}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm"
        >
          {simulating ? 'Симуляция...' : 'Провести симуляцию'}
        </button>
        <div className="text-xs text-gray-400">
          Исходное решение: <strong>{data.originalDecision.decision}</strong> ({(data.originalDecision.confidence * 100).toFixed(1)}%)
        </div>
      </div>

      {simulated && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="mt-6 border-t pt-4"
        >
          <div className="text-sm font-semibold flex items-center gap-2">
            {simulated.decision === data.originalDecision.decision ? (
              <CheckCircle className="text-green-500 w-4 h-4" />
            ) : (
              <AlertCircle className="text-yellow-500 w-4 h-4" />
            )}
            Новое решение: <span>{simulated.decision}</span> ({(simulated.confidence * 100).toFixed(1)}%)
          </div>
          <div className="text-xs mt-1 text-gray-400">{simulated.reason}</div>
        </motion.div>
      )}
    </div>
  )
}
