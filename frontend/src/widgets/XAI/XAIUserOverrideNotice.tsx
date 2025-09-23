import React from 'react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { UserCheck, Info, Lock, Terminal } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface OverrideData {
  userId: string
  timestamp: string
  aiDecision: string
  userDecision: string
  justification?: string
  riskScore: number
  tags?: string[]
  overrideType: 'soft' | 'hard'
  auditId?: string
  complianceFlag?: boolean
}

interface Props {
  data: OverrideData
  compact?: boolean
}

export const XAIUserOverrideNotice: React.FC<Props> = ({ data, compact = false }) => {
  const {
    userId,
    timestamp,
    aiDecision,
    userDecision,
    justification,
    riskScore,
    tags,
    overrideType,
    auditId,
    complianceFlag
  } = data

  const riskColor =
    riskScore >= 0.75
      ? 'text-red-700'
      : riskScore >= 0.4
      ? 'text-yellow-600'
      : 'text-green-600'

  const overrideIcon =
    overrideType === 'hard' ? <Lock className="w-4 h-4 text-muted-foreground" /> : <UserCheck className="w-4 h-4" />

  return (
    <Alert className={cn('border shadow-sm transition-all', overrideType === 'hard' && 'border-red-500')}>
      <div className="flex items-center gap-3 mb-1">
        {overrideIcon}
        <AlertTitle className="text-sm font-semibold">
          Пользователь <span className="text-blue-600 font-mono">{userId}</span> переопределил AI-решение
        </AlertTitle>
        {auditId && (
          <Badge variant="outline" className="text-[10px] ml-auto">
            Audit ID: {auditId}
          </Badge>
        )}
      </div>

      <AlertDescription className="space-y-1 text-xs font-mono text-muted-foreground">
        <div>
          <strong className="text-foreground">Время:</strong> {new Date(timestamp).toLocaleString()}
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-foreground">AI:</span>
          <code className="px-1 bg-muted rounded">{aiDecision}</code>
          <span>→</span>
          <code className="px-1 bg-muted rounded">{userDecision}</code>
        </div>

        {justification && (
          <div className="pt-1">
            <span className="text-foreground">Обоснование:</span> <span className="italic">{justification}</span>
          </div>
        )}

        <div>
          <span className="text-foreground">Риск переопределения:</span>{' '}
          <span className={cn('font-bold', riskColor)}>{(riskScore * 100).toFixed(0)}%</span>
        </div>

        {tags && tags.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {tags.map((tag, idx) => (
              <Badge key={idx} variant="secondary" className="text-[10px]">
                {tag}
              </Badge>
            ))}
          </div>
        )}

        {complianceFlag === false && (
          <div className="flex items-center text-xs text-red-600 pt-2">
            <Terminal className="w-3 h-3 mr-1" />
            Нарушение XAI-комплаенса: отсутствует объяснение или превышен лимит вмешательств
          </div>
        )}
      </AlertDescription>
    </Alert>
  )
}
