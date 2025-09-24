import React from 'react'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/shared/utils/classNames'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { ShieldCheck, Sparkles } from 'lucide-react'
import { useTheme } from '@/hooks/theme/useTheme'
import { useUser } from '@/hooks/auth/useUser'
import { useFeatureFlag } from '@/hooks/experiments/useFeatureFlag'

type MarketplaceZeroFeeBadgeProps = {
  variant?: 'default' | 'vip' | 'campaign' | 'partner'
  reason?: string
  className?: string
}

export const MarketplaceZeroFeeBadge: React.FC<MarketplaceZeroFeeBadgeProps> = ({
  variant = 'default',
  reason = 'Без комиссии благодаря акции или статусу',
  className,
}) => {
  const { theme } = useTheme()
  const { user } = useUser()
  const isVIP = useFeatureFlag('marketplace.vipZeroFee')
  const isCampaignActive = useFeatureFlag('marketplace.campaignZeroFee')

  const colorMap: Record<string, string> = {
    default: 'bg-green-600 text-white',
    vip: 'bg-purple-700 text-white',
    campaign: 'bg-indigo-600 text-white',
    partner: 'bg-yellow-600 text-white',
  }

  const iconMap: Record<string, JSX.Element> = {
    default: <ShieldCheck className="w-4 h-4 mr-1" />,
    vip: <Sparkles className="w-4 h-4 mr-1" />,
    campaign: <ShieldCheck className="w-4 h-4 mr-1" />,
    partner: <Sparkles className="w-4 h-4 mr-1" />,
  }

  const labelMap: Record<string, string> = {
    default: '0% комиссия',
    vip: 'VIP: 0%',
    campaign: 'Акция: 0%',
    partner: 'Партнёр: 0%',
  }

  const badgeStyle = cn(
    'inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full shadow-sm animate-pulse transition-colors duration-300',
    colorMap[variant],
    className,
  )

  if (!user || (!isVIP && !isCampaignActive && variant === 'default')) return null

  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge className={badgeStyle}>
            {iconMap[variant]}
            {labelMap[variant]}
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="text-sm max-w-xs text-left">
          <span>{reason}</span>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

export default MarketplaceZeroFeeBadge
