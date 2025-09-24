import React, { useMemo } from 'react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import {
  Bot,
  Sparkles,
  Cpu,
  BookOpen,
  Brain,
  ShieldCheck,
  ScanFace,
  Settings,
  Globe2,
  PenTool,
} from 'lucide-react';

type AIProductCategory =
  | 'text'
  | 'image'
  | 'video'
  | 'voice'
  | 'agent'
  | 'security'
  | 'design'
  | 'avatar'
  | 'automation'
  | 'education'
  | 'unknown';

interface AIProductTypeIconProps {
  category?: AIProductCategory;
  size?: number;
  className?: string;
}

const iconMap: Record<AIProductCategory, React.ReactNode> = {
  text: <BookOpen className="text-blue-600 dark:text-blue-400" />,
  image: <PenTool className="text-pink-500 dark:text-pink-400" />,
  video: <Sparkles className="text-purple-500 dark:text-purple-400" />,
  voice: <ScanFace className="text-green-500 dark:text-green-400" />,
  agent: <Bot className="text-amber-500 dark:text-amber-400" />,
  security: <ShieldCheck className="text-red-500 dark:text-red-400" />,
  design: <Settings className="text-teal-500 dark:text-teal-400" />,
  avatar: <Globe2 className="text-cyan-500 dark:text-cyan-400" />,
  automation: <Cpu className="text-indigo-500 dark:text-indigo-400" />,
  education: <Brain className="text-orange-500 dark:text-orange-400" />,
  unknown: <Bot className="text-muted-foreground" />,
};

const tooltipMap: Record<AIProductCategory, string> = {
  text: 'AI-сгенерированный текст',
  image: 'AI-сгенерированное изображение',
  video: 'AI-видеоконтент',
  voice: 'AI-голос/озвучка',
  agent: 'AI-агент или ассистент',
  security: 'AI-система безопасности',
  design: 'AI-дизайн/верстка',
  avatar: 'AI-аватар/персонаж',
  automation: 'AI-автоматизация',
  education: 'AI-обучение/наставник',
  unknown: 'AI-продукт',
};

export const AIProductTypeIcon: React.FC<AIProductTypeIconProps> = ({
  category = 'unknown',
  size = 20,
  className,
}) => {
  const icon = useMemo(() => {
    const rawIcon = iconMap[category] || iconMap.unknown;
    return React.cloneElement(rawIcon as React.ReactElement, {
      size,
      className: cn('transition-transform hover:scale-105', (rawIcon as any).props?.className, className),
    });
  }, [category, size, className]);

  const label = tooltipMap[category] || tooltipMap.unknown;

  return (
    <TooltipProvider delayDuration={100}>
      <Tooltip>
        <TooltipTrigger
          aria-label={`AI Product Icon: ${label}`}
          role="img"
          className="focus:outline-none"
        >
          {icon}
        </TooltipTrigger>
        <TooltipContent className="text-sm font-medium max-w-xs text-center">
          {label}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
};
