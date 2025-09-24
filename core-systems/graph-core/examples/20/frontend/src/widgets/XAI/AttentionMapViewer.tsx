// src/widgets/XAI/AttentionMapViewer.tsx

import React, { useEffect, useState } from 'react'
import { useAttentionMapService } from '@/services/xaiAttentionService'
import { Select } from '@/shared/components/Select'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useTelegramTheme'
import { motion } from 'framer-motion'

interface AttentionMap {
  tokens: string[]                // Входные токены
  matrix: number[][]             // Attention веса [head][token_i][token_j]
  layers: number                 // Кол-во слоёв
  headsPerLayer: number          // Кол-во attention-голов
}

interface Props {
  sampleId: string               // ID входного текста / изображения
  modelType: 'nlp' | 'vision'    // Тип модели (для масштаба и цветов)
}

export const AttentionMapViewer: React.FC<Props> = ({ sampleId, modelType }) => {
  const [attention, setAttention] = useState<AttentionMap | null>(null)
  const [selectedLayer, setSelectedLayer] = useState(0)
  const [selectedHead, setSelectedHead] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { theme } = useTheme()
  const { fetchAttentionMap } = useAttentionMapService()

  useEffect(() => {
    const load = async () => {
      try {
        const result = await fetchAttentionMap(sampleId)
        setAttention(result)
      } catch {
        setError('Ошибка загрузки attention-карты.')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [sampleId, fetchAttentionMap])

  if (loading) {
    return <div className="flex justify-center items-center p-4"><Spinner /></div>
  }

  if (error || !attention) {
    return <div className="text-red-500 text-sm text-center">{error || 'Нет карты внимания'}</div>
  }

  const matrix = attention.matrix?.[selectedLayer * attention.headsPerLayer + selectedHead] || []

  const colorScale = (value: number) => {
    const alpha = Math.min(1, Math.max(0, value))
    return modelType === 'nlp'
      ? `rgba(0, 120, 255, ${alpha})`
      : `rgba(255, 100, 0, ${alpha})`
  }

  return (
    <div
      className={cn(
        'rounded-lg p-4 border shadow-sm overflow-x-auto max-w-full space-y-4',
        theme === 'dark' ? 'bg-zinc-900 border-zinc-700 text-white' : 'bg-white border-zinc-200 text-black'
      )}
    >
      <div className="flex flex-wrap gap-4 justify-between items-center">
        <div className="text-base font-semibold">
          Attention Map (Layer {selectedLayer}, Head {selectedHead})
        </div>
        <div className="flex gap-4">
          <Select
            label="Слой"
            options={Array.from({ length: attention.layers }, (_, i) => ({
              label: `Layer ${i}`,
              value: i.toString(),
            }))}
            value={selectedLayer.toString()}
            onChange={(val) => setSelectedLayer(Number(val))}
          />
          <Select
            label="Голова"
            options={Array.from({ length: attention.headsPerLayer }, (_, i) => ({
              label: `Head ${i}`,
              value: i.toString(),
            }))}
            value={selectedHead.toString()}
            onChange={(val) => setSelectedHead(Number(val))}
          />
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="border-collapse">
          <thead>
            <tr>
              <th />
              {attention.tokens.map((tok, i) => (
                <th key={i} className="px-2 text-xs text-gray-500 whitespace-nowrap">{tok}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.map((row, i) => (
              <tr key={i}>
                <td className="text-xs pr-2 text-gray-500">{attention.tokens[i]}</td>
                {row.map((val, j) => (
                  <td key={j} className="w-6 h-6 relative">
                    <motion.div
                      className="w-6 h-6"
                      style={{ backgroundColor: colorScale(val) }}
                      initial={{ scale: 0.8 }}
                      animate={{ scale: 1 }}
                      transition={{ duration: 0.2 }}
                      title={`(${attention.tokens[i]} → ${attention.tokens[j]}): ${val.toFixed(2)}`}
                    />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
