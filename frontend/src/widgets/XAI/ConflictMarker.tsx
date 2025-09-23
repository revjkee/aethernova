import React from 'react'

interface Props {
  level: 'low' | 'medium' | 'high'
  reason: string
}

export const ConflictMarker: React.FC<Props> = ({ level, reason }) => {
  const colors = {
    low: 'bg-yellow-100 text-yellow-800',
    medium: 'bg-orange-100 text-orange-800',
    high: 'bg-red-100 text-red-800',
  }

  return (
    <div className={`text-xs p-2 rounded mt-1 ${colors[level]}`}>
      Конфликт: {reason}
    </div>
  )
}
