import React from 'react'
import { TraceNode } from '@/types/xai'

interface Props {
  trace: TraceNode
  depth?: number
  maxDepth: number
}

export const IntentionTree: React.FC<Props> = ({ trace, depth = 0, maxDepth }) => {
  if (depth >= maxDepth) return null

  return (
    <ul className="ml-4 border-l pl-2">
      <li className="text-sm">
        <span className="font-semibold">{trace.node}</span>: {trace.reason}
      </li>
      {trace.children?.map((child, idx) => (
        <IntentionTree key={idx} trace={child} depth={depth + 1} maxDepth={maxDepth} />
      ))}
    </ul>
  )
}
