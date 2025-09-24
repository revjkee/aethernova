// src/widgets/Marketplace/ProductTagBadge.tsx

import React, { FC, memo, useMemo } from 'react';
import { cn } from '@/shared/utils/classNames';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Sparkles, BadgePercent, LockKeyhole, ShieldCheck, Brain, Ticket } from 'lucide-react';
import { TagType, getTagStyle, getTagIcon, getTagLabel, PRIORITY_TAGS } from '@/shared/constants/tags';
import { useTheme } from '@/shared/hooks/useTelegramTheme';
import { useTelemetry } from '@/shared/hooks/useTelemetry';

interface ProductTagBadgeProps {
  tag: TagType;
  withTooltip?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const SIZE_MAP = {
  sm: 'text-xs px-2 py-0.5',
  md: 'text-sm px-2.5 py-1',
  lg: 'text-base px-3 py-1.5',
};

export const ProductTagBadge: FC<ProductTagBadgeProps> = memo(
  ({ tag, withTooltip = true, size = 'md', className }) => {
    const theme = useTheme();
    const telemetry = useTelemetry();

    const { label, icon: Icon, colorClass } = useMemo(() => {
      return {
        label: getTagLabel(tag),
        icon: getTagIcon(tag),
        colorClass: getTagStyle(tag, theme),
      };
    }, [tag, theme]);

    const sizeClass = SIZE_MAP[size];

    const content = (
      <span
        className={cn(
          'inline-flex items-center gap-1 rounded-full font-medium tracking-tight transition-all select-none',
          sizeClass,
          colorClass,
          className
        )}
      >
        {Icon && <Icon size={14} className="shrink-0" />}
        {label}
      </span>
    );

    if (!withTooltip) return content;

    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            role="button"
            onClick={() => telemetry.send({ type: 'tag_click', payload: tag })}
          >
            {content}
          </div>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-xs text-muted-foreground">
          {`Тег: ${label} — ${TAG_DESCRIPTIONS[tag] ?? 'Описание отсутствует'}`}
        </TooltipContent>
      </Tooltip>
    );
  }
);

ProductTagBadge.displayName = 'ProductTagBadge';

// Типы тегов и описание — расширяются централизованно
// src/shared/constants/tags.ts

export type TagType =
  | 'nft'
  | 'ai'
  | 'exclusive'
  | 'subscription'
  | 'discount'
  | 'access'
  | 'verified'
  | 'ticket';

export const PRIORITY_TAGS: TagType[] = [
  'exclusive',
  'discount',
  'access',
  'nft',
  'verified',
];

export const TAG_DESCRIPTIONS: Record<TagType, string> = {
  nft: 'Цифровой актив, представленный в виде NFT',
  ai: 'Создано или улучшено с использованием искусственного интеллекта',
  exclusive: 'Эксклюзивный контент — доступ ограничен',
  subscription: 'Доступно только по подписке',
  discount: 'Специальное предложение со скидкой',
  access: 'Ограниченный доступ или защищённый товар',
  verified: 'Подтверждённый источник или автор',
  ticket: 'Электронный билет на событие',
};

export const getTagLabel = (tag: TagType): string => {
  switch (tag) {
    case 'nft':
      return 'NFT';
    case 'ai':
      return 'AI';
    case 'exclusive':
      return 'Эксклюзив';
    case 'subscription':
      return 'Подписка';
    case 'discount':
      return 'Скидка';
    case 'access':
      return 'Доступ';
    case 'verified':
      return 'Проверено';
    case 'ticket':
      return 'Билет';
    default:
      return 'Тег';
  }
};

export const getTagStyle = (tag: TagType, theme: 'light' | 'dark'): string => {
  const base = 'border text-background';
  switch (tag) {
    case 'nft':
      return cn(base, 'bg-purple-500');
    case 'ai':
      return cn(base, 'bg-cyan-600');
    case 'exclusive':
      return cn(base, 'bg-rose-600');
    case 'subscription':
      return cn(base, 'bg-indigo-600');
    case 'discount':
      return cn(base, 'bg-emerald-500');
    case 'access':
      return cn(base, 'bg-yellow-600');
    case 'verified':
      return cn(base, 'bg-blue-500');
    case 'ticket':
      return cn(base, 'bg-orange-500');
    default:
      return cn(base, 'bg-muted');
  }
};

export const getTagIcon = (tag: TagType): React.FC<{ size?: number }> | null => {
  switch (tag) {
    case 'nft':
      return Sparkles;
    case 'ai':
      return Brain;
    case 'exclusive':
      return LockKeyhole;
    case 'subscription':
      return Ticket;
    case 'discount':
      return BadgePercent;
    case 'access':
      return ShieldCheck;
    case 'verified':
      return ShieldCheck;
    case 'ticket':
      return Ticket;
    default:
      return null;
  }
};
