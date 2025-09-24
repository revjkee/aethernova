import React, { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/shared/components/Badge';
import { Button } from '@/shared/components/Button';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { RatingStars } from '@/shared/components/RatingStars';
import { cn } from '@/shared/utils/cn';

interface Props {
  id: string;
  title: string;
  description: string;
  thumbnailUrl?: string;
  instructor: string;
  durationHours: number;
  progressPercent?: number;
  rating?: number; // 0..5
  lessonsCount: number;
  onOpenDetails: (id: string) => void;
  onEnroll: (id: string) => void;
  isEnrolled?: boolean;
}

const CourseCard: React.FC<Props> = ({
  id,
  title,
  description,
  thumbnailUrl,
  instructor,
  durationHours,
  progressPercent = 0,
  rating = 0,
  lessonsCount,
  onOpenDetails,
  onEnroll,
  isEnrolled = false,
}) => {
  const { t } = useTranslation();

  const truncatedDescription = useMemo(() => {
    if (description.length > 160) return description.slice(0, 157) + '...';
    return description;
  }, [description]);

  return (
    <article
      role="region"
      aria-labelledby={`course-title-${id}`}
      className={cn(
        'flex flex-col md:flex-row bg-white dark:bg-zinc-900 rounded-lg shadow-md overflow-hidden',
        'hover:shadow-lg transition-shadow duration-300 ease-in-out'
      )}
    >
      <div className="flex-shrink-0 w-full md:w-48 h-32 md:h-auto relative">
        {thumbnailUrl ? (
          <img
            src={thumbnailUrl}
            alt={t('edu.courseThumbnailAlt', { title })}
            loading="lazy"
            className="w-full h-full object-cover"
          />
        ) : (
          <div className="w-full h-full bg-zinc-300 dark:bg-zinc-700 flex items-center justify-center text-zinc-500 dark:text-zinc-400">
            {t('edu.noThumbnail')}
          </div>
        )}
      </div>
      <div className="flex flex-col flex-grow p-4 space-y-2">
        <h3
          id={`course-title-${id}`}
          className="text-lg font-semibold text-gray-900 dark:text-gray-100 truncate"
          title={title}
        >
          {title}
        </h3>

        <p className="text-sm text-muted-foreground line-clamp-3" title={description}>
          {truncatedDescription}
        </p>

        <div className="flex flex-wrap gap-3 items-center">
          <Badge variant="outline" className="text-xs">
            {t('edu.instructor')}: {instructor}
          </Badge>
          <Badge variant="outline" className="text-xs">
            {t('edu.duration')}: {durationHours} {t('edu.hours')}
          </Badge>
          <Badge variant="outline" className="text-xs">
            {lessonsCount} {t('edu.lessons')}
          </Badge>
        </div>

        <div className="flex items-center gap-4">
          <RatingStars rating={rating} max={5} />
          <div className="flex-grow">
            <ProgressBar value={progressPercent} />
          </div>
          <span className="text-xs text-muted-foreground">
            {isEnrolled
              ? t('edu.progress', { percent: progressPercent })
              : t('edu.notEnrolled')}
          </span>
        </div>

        <div className="flex gap-3 mt-2">
          <Button variant="primary" onClick={() => onOpenDetails(id)}>
            {t('edu.details')}
          </Button>
          {!isEnrolled && (
            <Button variant="outline" onClick={() => onEnroll(id)}>
              {t('edu.enroll')}
            </Button>
          )}
        </div>
      </div>
    </article>
  );
};

export default React.memo(CourseCard);
