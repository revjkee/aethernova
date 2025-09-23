import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchCourseProgress } from '@/services/api/courseAPI';
import { Tooltip } from '@/shared/components/Tooltip';
import { cn } from '@/shared/utils/cn';

interface ProgressStage {
  id: string;
  label: string;
  completed: boolean;
  percentage: number; // Процент в рамках курса (0-100)
  description?: string;
}

interface Props {
  userId: string;
  courseId: string;
  className?: string;
}

const CourseCompletionProgressBar: React.FC<Props> = ({
  userId,
  courseId,
  className,
}) => {
  const { t } = useTranslation();
  const [progressStages, setProgressStages] = useState<ProgressStage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const loadProgress = async () => {
      setLoading(true);
      setError(null);
      try {
        const stages = await fetchCourseProgress(userId, courseId);
        if (!cancelled) setProgressStages(stages);
      } catch {
        if (!cancelled) setError(t('edu.progressBar.loadError'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    loadProgress();
    return () => {
      cancelled = true;
    };
  }, [userId, courseId, t]);

  const totalCompletedPercentage = useMemo(() => {
    if (progressStages.length === 0) return 0;
    return progressStages.reduce((acc, stage) => (stage.completed ? acc + stage.percentage : acc), 0);
  }, [progressStages]);

  if (loading) {
    return (
      <div className="py-12 flex justify-center">
        <span className="animate-spin rounded-full h-10 w-10 border-b-2 border-gray-900 dark:border-gray-100" aria-label={t('edu.progressBar.loading')} />
      </div>
    );
  }

  if (error) {
    return (
      <div role="alert" className="text-center text-red-600 dark:text-red-400">
        {error}
      </div>
    );
  }

  if (progressStages.length === 0) {
    return (
      <div className="text-center text-muted-foreground">
        {t('edu.progressBar.noProgress')}
      </div>
    );
  }

  return (
    <section
      aria-label={t('edu.progressBar.ariaLabel')}
      className={cn('max-w-4xl mx-auto', className)}
    >
      <div className="mb-4 flex justify-between items-center">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
          {t('edu.progressBar.title')}
        </h2>
        <div className="text-sm font-medium text-indigo-600 dark:text-indigo-400" aria-live="polite" aria-atomic="true">
          {t('edu.progressBar.overallProgress', { percentage: totalCompletedPercentage.toFixed(0) })}
        </div>
      </div>

      <div className="relative h-8 bg-gray-300 dark:bg-zinc-700 rounded-full overflow-hidden">
        <div
          className="absolute top-0 left-0 h-full bg-indigo-600 dark:bg-indigo-400 transition-all duration-500 ease-in-out"
          style={{ width: `${totalCompletedPercentage}%` }}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={totalCompletedPercentage}
          role="progressbar"
          aria-label={t('edu.progressBar.progressbarAriaLabel')}
        />
      </div>

      <ul className="mt-4 flex justify-between">
        {progressStages.map((stage) => (
          <li key={stage.id} className="relative flex flex-col items-center flex-1 text-center">
            <Tooltip content={stage.description || stage.label} placement="top" delay={200}>
              <div
                className={cn(
                  'w-6 h-6 rounded-full mb-1 transition-colors',
                  stage.completed ? 'bg-indigo-600 dark:bg-indigo-400' : 'bg-gray-400 dark:bg-zinc-600'
                )}
                aria-label={`${stage.label} - ${stage.completed ? t('edu.progressBar.completed') : t('edu.progressBar.incomplete')}`}
                role="img"
              />
            </Tooltip>
            <span
              className={cn(
                'text-xs font-medium',
                stage.completed ? 'text-indigo-600 dark:text-indigo-400' : 'text-muted-foreground'
              )}
            >
              {stage.label}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
};

export default React.memo(CourseCompletionProgressBar);
