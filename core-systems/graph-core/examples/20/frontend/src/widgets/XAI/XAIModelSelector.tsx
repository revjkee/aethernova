// src/widgets/XAI/XAIModelSelector.tsx

import React, { useEffect, useState, useCallback } from 'react'
import { Select, SelectItem } from '@/shared/ui/Select'
import { Tooltip } from '@/shared/ui/Tooltip'
import { useXAIContext } from '@/shared/context/XAIContext'
import { validateXAIFramework, getAvailableXAIModels, loadModelMeta } from '@/services/xai/modelRegistry'
import { motion } from 'framer-motion'
import { cn } from '@/shared/utils/cn'
import './XAIModelSelector.css'

export type XAIFramework =
  | 'SHAP'
  | 'LIME'
  | 'IntegratedGradients'
  | 'Anchors'
  | 'DeepLift'
  | 'LayerwiseRelevancePropagation'
  | 'CustomXAI'

interface XAIModelSelectorProps {
  currentModel?: XAIFramework
  onChange: (framework: XAIFramework) => void
  disabled?: boolean
  decisionId?: string
}

interface ModelMeta {
  name: XAIFramework
  description: string
  recommendedFor: string[]
  verified: boolean
  experimental?: boolean
}

export const XAIModelSelector: React.FC<XAIModelSelectorProps> = ({
  currentModel,
  onChange,
  disabled = false,
  decisionId
}) => {
  const { triggerGlobalAlert } = useXAIContext()
  const [models, setModels] = useState<ModelMeta[]>([])
  const [loading, setLoading] = useState(false)

  const fetchModels = useCallback(async () => {
    setLoading(true)
    try {
      const available = await getAvailableXAIModels()
      const withMeta = await Promise.all(available.map(loadModelMeta))
      setModels(withMeta)
    } catch (err) {
      triggerGlobalAlert('Ошибка загрузки XAI моделей', 'error')
    } finally {
      setLoading(false)
    }
  }, [triggerGlobalAlert])

  useEffect(() => {
    fetchModels()
  }, [fetchModels])

  const handleChange = async (value: string) => {
    const framework = value as XAIFramework
    const isValid = await validateXAIFramework(framework, decisionId)
    if (!isValid) {
      triggerGlobalAlert(`Модель ${framework} не поддерживает текущий тип решения`, 'warning')
      return
    }
    onChange(framework)
  }

  const renderItem = (model: ModelMeta): SelectItem => ({
    value: model.name,
    label: model.name,
    description: model.description,
    disabled: model.experimental,
    icon: model.verified ? '✅' : '⚠️',
    meta: model.recommendedFor.includes('NLP') ? 'NLP' : 'Vision',
    tooltip: model.experimental
      ? 'Экспериментальная модель — использовать с осторожностью'
      : model.description
  })

  return (
    <motion.div
      className={cn('xai-model-selector', disabled && 'disabled')}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <Tooltip content="Выберите фреймворк интерпретации, наиболее подходящий для вашего AI-вывода">
        <label className="selector-label">XAI Framework</label>
      </Tooltip>

      {loading ? (
        <div className="selector-loading">Загрузка моделей...</div>
      ) : (
        <Select
          value={currentModel || ''}
          onChange={handleChange}
          items={models.map(renderItem)}
          disabled={disabled}
          searchable
          className="xai-select"
        />
      )}
    </motion.div>
  )
}
