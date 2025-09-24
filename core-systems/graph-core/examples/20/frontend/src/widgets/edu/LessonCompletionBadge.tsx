import React, { useEffect, useState } from 'react';
import { CheckCircle2, Clock, AlertTriangle } from 'lucide-react';
import { Tooltip } from '@/shared/components/Tooltip';
import { cn } from '@/shared/utils/cn';
import { useTranslation } from 'react-i18next';

interface Props {
  progressPercent: number; // 0-100
  lastCompletedDate?: string;
  className?: string;
}

type CompletionStatus = 'completed' | 'partial' | 'not_completed';

const getStatus = (progress: number): CompletionStatus => {
  if (progress >= 95) return 'completed';
  if (progress > 0) return 'partial';
  return 'not_completed';
};

const LessonCompletionBadge: React.FC<Props> = ({ progressPercent, lastCompletedDate, className }) => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<CompletionStatus>(getStatus(progressPercent));

  useEffect(() => {
    setStatus(getStatus(progressPercent));
  }, [progressPercent]);

  const statusConfig = {
    completed: {
      icon: <CheckCircle2 className="text-green-600" size={20} />,
      label: t('edu.lessonBadge.completed'),
      color: 'bg-green-100 text-green-800',
    },
    partial: {
      icon: <Clock className="text-yellow-600" size={20} />,
      label: t('edu.lessonBadge.inProgress'),
      color: 'bg-yellow-100 text-yellow-800',
    },
    not_completed: {
      icon: <AlertTriangle className="text-red-600" size={20} />,
      label: t('edu.lessonBadge.notStarted'),
      color: 'bg-red-100 text-red-800',
    },
  };

  const { icon, label, color } = statusConfig[status];

  return (
    <Tooltip
      content={
        lastCompletedDate
          ? t('edu.lessonBadge.tooltip', { date: new Date(lastCompletedDate).toLocaleDateString() })
          : t('edu.lessonBadge.noCompletionDate')
      }
    >
      <div
        className={cn(
          'inline-flex items-center gap-2 px-3 py-1 rounded-full font-semibold select-none',
          color,
          className
        )}
        aria-label={`${label}: ${progressPercent.toFixed(0)}%`}
        role="img"
      >
        {icon}
        <span>{label}</span>
      </div>
    </Tooltip>
  );
};

export default React.memo(LessonCompletionBadge);
