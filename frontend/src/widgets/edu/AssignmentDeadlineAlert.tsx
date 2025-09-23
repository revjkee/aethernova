import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchAssignmentDeadline, sendDeadlineReminder } from '@/services/api/assignmentAPI';
import { Button } from '@/shared/components/Button';
import { cn } from '@/shared/utils/cn';

interface Props {
  userId: string;
  assignmentId: string;
  className?: string;
}

const AssignmentDeadlineAlert: React.FC<Props> = ({ userId, assignmentId, className }) => {
  const { t } = useTranslation();
  const [deadline, setDeadline] = useState<Date | null>(null);
  const [timeLeft, setTimeLeft] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reminderSent, setReminderSent] = useState(false);
  const timerRef = useRef<number | null>(null);

  // Загрузка дедлайна
  useEffect(() => {
    let cancelled = false;
    const loadDeadline = async () => {
      setLoading(true);
      setError(null);
      try {
        const dl = await fetchAssignmentDeadline(userId, assignmentId);
        if (!cancelled && dl) {
          setDeadline(new Date(dl));
        }
      } catch {
        if (!cancelled) setError(t('edu.assignmentDeadline.loadError'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    loadDeadline();
    return () => {
      cancelled = true;
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [userId, assignmentId, t]);

  // Таймер обратного отсчёта
  useEffect(() => {
    if (!deadline) return;

    const updateTimer = () => {
      const now = new Date();
      const diff = deadline.getTime() - now.getTime();
      setTimeLeft(diff > 0 ? diff : 0);
    };

    updateTimer();
    timerRef.current = window.setInterval(updateTimer, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [deadline]);

  // Отправка напоминания
  const handleSendReminder = useCallback(async () => {
    setReminderSent(true);
    try {
      await sendDeadlineReminder(userId, assignmentId);
    } catch {
      setReminderSent(false);
    }
  }, [userId, assignmentId]);

  // Форматирование времени
  const formatTimeLeft = (ms: number) => {
    const totalSeconds = Math.floor(ms / 1000);
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    return (
      <>
        {days > 0 && `${days} ${t('edu.assignmentDeadline.days')} `}
        {hours} {t('edu.assignmentDeadline.hours')} {minutes} {t('edu.assignmentDeadline.minutes')} {seconds} {t('edu.assignmentDeadline.seconds')}
      </>
    );
  };

  if (loading) {
    return (
      <div className={cn('flex justify-center p-6', className)}>
        <span className="animate-spin rounded-full h-10 w-10 border-b-2 border-indigo-600" aria-label={t('edu.assignmentDeadline.loading')} />
      </div>
    );
  }

  if (error) {
    return (
      <div role="alert" className={cn('text-red-600 dark:text-red-400 p-4 text-center', className)}>
        {error}
      </div>
    );
  }

  if (!deadline) {
    return (
      <div className={cn('text-center text-muted-foreground p-4', className)}>
        {t('edu.assignmentDeadline.noDeadline')}
      </div>
    );
  }

  if (timeLeft === 0) {
    return (
      <div
        role="alert"
        className={cn('bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded p-4 text-center', className)}
      >
        {t('edu.assignmentDeadline.passed')}
      </div>
    );
  }

  // Определяем уровень предупреждения
  const alertLevel = timeLeft < 3600000 ? 'critical' : timeLeft < 86400000 ? 'warning' : 'normal'; // <1ч, <24ч, иначе

  return (
    <div
      role="alert"
      aria-live="polite"
      className={cn(
        'rounded p-4 text-center',
        alertLevel === 'critical'
          ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
          : alertLevel === 'warning'
          ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200'
          : 'bg-indigo-100 dark:bg-indigo-900 text-indigo-800 dark:text-indigo-200',
        className
      )}
    >
      <p className="mb-2 font-semibold text-lg">
        {t('edu.assignmentDeadline.upcoming')}
      </p>
      <p className="mb-4">
        {t('edu.assignmentDeadline.timeLeft')}: <strong>{formatTimeLeft(timeLeft)}</strong>
      </p>
      <Button
        variant="secondary"
        onClick={handleSendReminder}
        disabled={reminderSent}
        aria-disabled={reminderSent}
        aria-label={reminderSent ? t('edu.assignmentDeadline.reminderSent') : t('edu.assignmentDeadline.sendReminder')}
      >
        {reminderSent ? t('edu.assignmentDeadline.reminderSent') : t('edu.assignmentDeadline.sendReminder')}
      </Button>
    </div>
  );
};

export default React.memo(AssignmentDeadlineAlert);
