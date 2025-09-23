import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { fetchLessonProgress, saveLessonProgress } from '@/services/api/eduAPI';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { Spinner } from '@/shared/components/Spinner';
import { useDebounce } from '@/shared/hooks/useDebounce';
import { useTranslation } from 'react-i18next';

interface LessonProgress {
  lessonId: string;
  userId: string;
  progressPercent: number; // 0-100
  lastUpdated: string;
  timeSpentSeconds: number;
  completed: boolean;
}

interface Props {
  lessonId: string;
  userId: string;
  onComplete?: () => void;
}

const SAVE_DEBOUNCE_MS = 2000;

const LessonProgressTracker: React.FC<Props> = ({ lessonId, userId, onComplete }) => {
  const { t } = useTranslation();
  const [progress, setProgress] = useState<LessonProgress | null>(null);
  const [localProgress, setLocalProgress] = useState<number>(0);
  const [timeSpent, setTimeSpent] = useState<number>(0);
  const [isSaving, setIsSaving] = useState(false);

  const debouncedProgress = useDebounce(localProgress, SAVE_DEBOUNCE_MS);

  const { data, isLoading, refetch } = useQuery(
    ['lessonProgress', lessonId, userId],
    () => fetchLessonProgress(lessonId, userId),
    { staleTime: 30000 }
  );

  const saveMutation = useMutation(saveLessonProgress, {
    onSuccess: () => {
      setIsSaving(false);
      refetch();
      if (localProgress >= 100 && onComplete) onComplete();
    },
    onError: () => {
      setIsSaving(false);
    },
  });

  useEffect(() => {
    if (data) {
      setProgress(data);
      setLocalProgress(data.progressPercent);
      setTimeSpent(data.timeSpentSeconds);
    }
  }, [data]);

  // Авто-сохранение прогресса
  useEffect(() => {
    if (debouncedProgress > (progress?.progressPercent || 0)) {
      setIsSaving(true);
      saveMutation.mutate({
        lessonId,
        userId,
        progressPercent: debouncedProgress,
        timeSpentSeconds: timeSpent,
        completed: debouncedProgress >= 100,
      });
    }
  }, [debouncedProgress, lessonId, userId, saveMutation, progress, timeSpent, onComplete]);

  // Симуляция наращивания времени и прогресса (можно заменить на реальные события)
  useEffect(() => {
    const interval = setInterval(() => {
      setTimeSpent((prev) => prev + 1);
      setLocalProgress((prev) => Math.min(100, prev + 0.1));
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  if (isLoading || !progress) {
    return (
      <div className="flex justify-center py-8">
        <Spinner size="lg" />
      </div>
    );
  }

  return (
    <div className="w-full max-w-lg mx-auto p-4 border rounded-md bg-white dark:bg-zinc-900 shadow-md">
      <h3 className="text-lg font-semibold mb-3">{t('edu.progressTracker.title')}</h3>
      <ProgressBar value={localProgress} />
      <div className="mt-2 flex justify-between text-sm text-muted-foreground">
        <span>{t('edu.progressTracker.timeSpent', { seconds: timeSpent })}</span>
        <span>{t('edu.progressTracker.completion', { percent: localProgress.toFixed(1) })}</span>
      </div>
      {isSaving && (
        <div className="mt-2 text-xs text-blue-500">{t('edu.progressTracker.saving')}</div>
      )}
    </div>
  );
};

export default React.memo(LessonProgressTracker);
