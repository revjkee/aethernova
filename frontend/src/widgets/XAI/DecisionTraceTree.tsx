// src/widgets/XAI/DecisionTraceTree.tsx

import React, { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { ChevronDown, ChevronRight, Zap, Clock, Code, BookOpen } from 'lucide-react'
import { useReasoningEngine } from '@/services/xaiReasoningService'
import { Spinner } from '@/shared/components/Spinner'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useTelegramTheme'

interface TraceNode {
  id: string
  label: string
  description: string
  weight: number
  timestamp: number
  children?: TraceNode[]
}

interface Props {
  sessionId: string
  rootNodeId?: string
}

export const DecisionTraceTree: React.FC<Props> = ({ sessionId, rootNodeId }) => {
  const { theme } = useTheme()
  const { fetchTraceTree } = useReasoningEngine()
  const [traceRoot, setTraceRoot] = useState<TraceNode | null>(null)
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const loadTree = async () => {
      try {
        const result = await fetchTraceTree(sessionId, rootNodeId)
        setTraceRoot(result)
      } catch (e) {
        setError('Не удалось загрузить reasoning дерево.')
      } finally {
        setLoading(false)
      }
    }

    loadTree()
  }, [sessionId, rootNodeId, fetchTraceTree])

  const toggleNode = (id: string) => {
    setExpanded((prev) => ({
      ...prev,
      [id]: !prev[id],
    }))
  }

  const renderNode = (node: TraceNode, depth = 0) => {
    const isOpen = expanded[node.id] || false
    const hasChildren = node.children && node.children.length > 0
    const nodeColor = node.weight > 0.5 ? 'text-green-500' : node.weight < -0.5 ? 'text-red-500' : 'text-gray-400'

    return (
      <div key={node.id} className="pl-4">
        <div
          className={cn(
            'flex items-start gap-2 py-1 px-2 rounded-md cursor-pointer group',
            theme === 'dark' ? 'hover:bg-white/10' : 'hover:bg-gray-100'
          )}
          onClick={() => hasChildren && toggleNode(node.id)}
        >
          <div className="flex items-center pt-1">
            {hasChildren ? (
              isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />
            ) : (
              <span className="w-4 h-4 inline-block" />
            )}
          </div>
          <div className="flex-1">
            <div className="flex items-center justify-between text-sm">
              <span className={cn('font-medium', nodeColor)}>{node.label}</span>
              <span className="text-xs text-gray-400">{new Date(node.timestamp).toLocaleTimeString()}</span>
            </div>
            <div className="text-xs text-gray-500">{node.description}</div>
          </div>
          <div className="text-xs font-mono text-gray-400">
            {(node.weight * 100).toFixed(1)}%
          </div>
        </div>

        {isOpen && node.children && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            transition={{ duration: 0.2 }}
            className="pl-2 border-l border-dashed border-gray-300 dark:border-gray-600 ml-2"
          >
            {node.children.map((child) => renderNode(child, depth + 1))}
          </motion.div>
        )}
      </div>
    )
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center p-4">
        <Spinner />
      </div>
    )
  }

  if (error || !traceRoot) {
    return (
      <div className="text-sm text-center text-red-500">
        {error || 'Дерево reasoning отсутствует'}
      </div>
    )
  }

  return (
    <div
      className={cn(
        'border rounded-md p-4 shadow-sm text-sm',
        theme === 'dark' ? 'bg-zinc-900 border-zinc-700 text-white' : 'bg-white border-zinc-200 text-black'
      )}
    >
      <div className="flex items-center gap-2 text-base font-semibold mb-2">
        <BookOpen className="w-5 h-5" />
        Reasoning дерево AI
      </div>

      {renderNode(traceRoot)}
    </div>
  )
}
