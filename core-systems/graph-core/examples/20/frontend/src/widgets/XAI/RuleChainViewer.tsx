// src/widgets/XAI/RuleChainViewer.tsx

import React, { useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, AlertTriangle, ShieldCheck } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'
import { Tooltip } from '@/shared/components/Tooltip'
import { useTheme } from '@/shared/hooks/useTelegramTheme'

interface RuleNode {
  id: string
  label: string
  source: string
  confidence: number // 0.0 - 1.0
  children?: RuleNode[]
  conflicted?: boolean
  verified?: boolean
}

interface RuleChainViewerProps {
  moduleId: string
  rootLabel?: string
}

const RuleNodeComponent: React.FC<{ node: RuleNode; depth: number }> = ({ node, depth }) => {
  const [expanded, setExpanded] = useState(false)

  const confidenceColor = (confidence: number) => {
    if (confidence > 0.85) return 'bg-green-600'
    if (confidence > 0.6) return 'bg-yellow-600'
    return 'bg-red-600'
  }

  return (
    <div className="pl-4 relative">
      <div
        className={cn(
          'flex items-center gap-2 py-1',
          node.conflicted && 'border-l-2 border-red-600'
        )}
      >
        {node.children && (
          <button onClick={() => setExpanded((v) => !v)} className="focus:outline-none">
            {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </button>
        )}
        <div
          className={cn(
            'flex items-center gap-1 text-sm px-2 py-0.5 rounded-md',
            confidenceColor(node.confidence),
            'text-white'
          )}
        >
          <span className="font-medium">{node.label}</span>
          <Tooltip content={`Источник: ${node.source}`}>
            <span className="opacity-70 text-xs">({node.source})</span>
          </Tooltip>
          {node.verified && (
            <Tooltip content="Правило верифицировано">
              <ShieldCheck size={14} />
            </Tooltip>
          )}
          {node.conflicted && (
            <Tooltip content="Конфликт логики">
              <AlertTriangle size={14} />
            </Tooltip>
          )}
        </div>
      </div>
      {expanded && node.children && (
        <div className="pl-3 border-l border-gray-400">
          {node.children.map((child) => (
            <RuleNodeComponent key={child.id} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  )
}

export const RuleChainViewer: React.FC<RuleChainViewerProps> = ({ moduleId, rootLabel = 'Логическая цепочка' }) => {
  const [rootNode, setRootNode] = useState<RuleNode | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { theme } = useTheme()

  useEffect(() => {
    fetch(`/api/xai/rules/${moduleId}`)
      .then((res) => res.json())
      .then(setRootNode)
      .catch(() => setError('Ошибка загрузки цепочки правил'))
  }, [moduleId])

  if (error) return <div className="text-red-600 text-sm">{error}</div>
  if (!rootNode) return <div className="text-sm text-gray-500">Загрузка логики...</div>

  return (
    <div className={cn('rounded-lg p-4 shadow-md', theme === 'dark' ? 'bg-gray-800' : 'bg-white')}>
      <h3 className="text-base font-semibold mb-2">{rootLabel}</h3>
      <RuleNodeComponent node={rootNode} depth={0} />
    </div>
  )
}
