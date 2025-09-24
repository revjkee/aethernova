import React from 'react'
import { CheckCircle, XCircle, Loader, Shield, AlertTriangle, Eye } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/shared/utils/classNames'
import { useAIValidationStatus } from '@/hooks/ai/useAIValidationStatus'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'

type Props = {
  productId: string
  compact?: boolean
  className?: string
}

export const MarketplaceAIValidatorStatus: React.FC<Props> = ({ productId, compact = false, className }) => {
  const { status, loading, reason, confidence, lastChecked, logsLink } = useAIValidationStatus(productId)

  const statusConfig = {
    pending: {
      label: 'Ожидает проверки',
      icon: <Loader className="animate-spin w-4 h-4 mr-1" />,
      color: 'bg-muted text-muted-foreground',
    },
    approved: {
      label: 'AI подтверждено',
      icon: <CheckCircle className="text-green-600 w-4 h-4 mr-1" />,
      color: 'bg-green-100 text-green-800',
    },
    rejected: {
      label: 'Отклонено AI',
      icon: <XCircle className="text-red-600 w-4 h-4 mr-1" />,
      color: 'bg-red-100 text-red-800',
    },
    manual_required: {
      label: 'Нужна проверка',
      icon: <AlertTriangle className="text-yellow-600 w-4 h-4 mr-1" />,
      color: 'bg-yellow-100 text-yellow-800',
    },
  }

  if (loading) {
    return compact ? (
      <Skeleton className="h-4 w-24 rounded-md" />
    ) : (
      <div className="flex flex-col gap-2">
        <Skeleton className="h-4 w-32" />
        <Progress value={30} className="w-full h-2" />
      </div>
    )
  }

  const config = statusConfig[status] || statusConfig['pending']
  const label = config.label
  const icon = config.icon
  const badgeClass = cn(
    'inline-flex items-center px-2.5 py-1 text-xs font-semibold rounded-full transition-colors duration-200',
    config.color,
    className
  )

  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge className={badgeClass}>
            {icon}
            {label}
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="max-w-sm text-left text-sm space-y-1">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-muted-foreground" />
            <span>Уровень доверия: <strong>{confidence}%</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <Eye className="w-4 h-4 text-muted-foreground" />
            <span>Последняя проверка: {lastChecked ? new Date(lastChecked).toLocaleString() : '—'}</span>
          </div>
          {reason && (
            <div className="text-muted-foreground mt-1">
              <strong>Причина:</strong> {reason}
            </div>
          )}
          {logsLink && (
            <div className="mt-1">
              <a
                href={logsLink}
                className="text-blue-600 underline"
                target="_blank"
                rel="noopener noreferrer"
              >
                Смотреть лог AI-проверки
              </a>
            </div>
          )}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

export default MarketplaceAIValidatorStatus
