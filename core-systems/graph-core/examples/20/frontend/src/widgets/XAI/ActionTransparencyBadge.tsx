import React, { useMemo } from 'react'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { IconEye, IconEyeOff, IconShieldCheck, IconLockCog } from '@tabler/icons-react'
import clsx from 'clsx'

type TransparencyLevel = 'opaque' | 'partial' | 'high' | 'zk-certified'

export interface ActionTransparencyProps {
  level: TransparencyLevel
  source: 'XAI' | 'Ruleset' | 'Human-in-the-loop' | 'RLAgent' | 'DAO'
  confidence: number // 0–1
  zkVerified?: boolean
  rationale?: string
  timestamp?: string
  showTooltip?: boolean
}

export const ActionTransparencyBadge: React.FC<ActionTransparencyProps> = ({
  level,
  source,
  confidence,
  zkVerified,
  rationale,
  timestamp,
  showTooltip = true
}) => {
  const icon = useMemo(() => {
    switch (level) {
      case 'opaque':
        return <IconEyeOff size={14} className="text-red-600" />
      case 'partial':
        return <IconEye size={14} className="text-yellow-500" />
      case 'high':
        return <IconEye size={14} className="text-green-600" />
      case 'zk-certified':
        return <IconShieldCheck size={14} className="text-blue-600" />
      default:
        return <IconEyeOff size={14} />
    }
  }, [level])

  const badgeColor = useMemo(() => {
    switch (level) {
      case 'opaque':
        return 'bg-red-100 text-red-800'
      case 'partial':
        return 'bg-yellow-100 text-yellow-800'
      case 'high':
        return 'bg-green-100 text-green-800'
      case 'zk-certified':
        return 'bg-blue-100 text-blue-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }, [level])

  const content = useMemo(() => {
    const percent = (confidence * 100).toFixed(1) + '%'
    return (
      <div className="text-xs leading-snug">
        <div><strong>Источник:</strong> {source}</div>
        <div><strong>Уровень:</strong> {level.toUpperCase()}</div>
        <div><strong>Доверие:</strong> {percent}</div>
        {zkVerified && <div className="flex items-center gap-1 text-blue-600"><IconLockCog size={12} /> ZK-подтверждено</div>}
        {rationale && <div className="mt-1 text-muted-foreground">{rationale}</div>}
        {timestamp && <div className="text-[10px] mt-2 opacity-70">{new Date(timestamp).toLocaleString()}</div>}
      </div>
    )
  }, [source, level, confidence, zkVerified, rationale, timestamp])

  const badgeContent = (
    <Badge className={clsx('gap-1 px-2 py-1 rounded-full font-medium', badgeColor)}>
      {icon}
      {level === 'zk-certified' ? 'ZK-Audit' : level.charAt(0).toUpperCase() + level.slice(1)}
    </Badge>
  )

  return (
    <TooltipProvider>
      {showTooltip ? (
        <Tooltip delayDuration={200}>
          <TooltipTrigger asChild>{badgeContent}</TooltipTrigger>
          <TooltipContent className="p-3 max-w-xs">{content}</TooltipContent>
        </Tooltip>
      ) : (
        badgeContent
      )}
    </TooltipProvider>
  )
}
