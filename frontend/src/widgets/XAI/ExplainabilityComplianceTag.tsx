import React, { useMemo } from 'react'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { CheckCircle2, AlertTriangle, XCircle, Info } from 'lucide-react'
import clsx from 'clsx'

export type ComplianceLevel = 'compliant' | 'partial' | 'non-compliant' | 'unknown'

interface ExplainabilityComplianceTagProps {
  level: ComplianceLevel
  standard?: 'ISO/IEC 24029-1' | 'IEEE P7001' | 'GXP-AI' | string
  lastAudit?: string
  rationale?: string
}

export const ExplainabilityComplianceTag: React.FC<ExplainabilityComplianceTagProps> = ({
  level,
  standard = 'ISO/IEC 24029-1',
  lastAudit,
  rationale,
}) => {
  const { label, icon, color, description } = useMemo(() => {
    switch (level) {
      case 'compliant':
        return {
          label: 'Соответствует',
          icon: <CheckCircle2 className="text-green-600 w-4 h-4" />,
          color: 'green',
          description: 'Полное соответствие утверждённому стандарту объяснимости.',
        }
      case 'partial':
        return {
          label: 'Частичное',
          icon: <AlertTriangle className="text-yellow-600 w-4 h-4" />,
          color: 'yellow',
          description: 'Найдены частичные несоответствия требованиям XAI.',
        }
      case 'non-compliant':
        return {
          label: 'Нарушение',
          icon: <XCircle className="text-red-600 w-4 h-4" />,
          color: 'red',
          description: 'Серьёзное нарушение критериев объяснимости.',
        }
      case 'unknown':
      default:
        return {
          label: 'Не проверено',
          icon: <Info className="text-gray-500 w-4 h-4" />,
          color: 'gray',
          description: 'Уровень соответствия пока не установлен.',
        }
    }
  }, [level])

  return (
    <TooltipProvider delayDuration={100}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            className={clsx(
              'inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-md',
              level === 'compliant' && 'bg-green-100 text-green-800',
              level === 'partial' && 'bg-yellow-100 text-yellow-800',
              level === 'non-compliant' && 'bg-red-100 text-red-800',
              level === 'unknown' && 'bg-gray-100 text-gray-700'
            )}
          >
            {icon}
            {label}
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="max-w-sm text-xs">
          <div className="font-semibold mb-1">Стандарт: {standard}</div>
          <div>{description}</div>
          {rationale && (
            <div className="mt-1 text-muted-foreground">Комментарий: {rationale}</div>
          )}
          {lastAudit && (
            <div className="mt-1 text-[10px] text-muted-foreground">
              Последняя проверка: {lastAudit}
            </div>
          )}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
