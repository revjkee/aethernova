import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/shared/components/Button';
import { cn } from '@/shared/utils/cn';

interface Props {
  sessionId: string;
  userId: string;
  initialDurationSec?: number; // по умолчанию 25 минут (1500 секунд)
  onSessionComplete?: () => void;
}

enum TimerStatus {
  Idle = 'idle',
  Running = 'running',
  Paused = 'paused',
  Completed = 'completed',
}

const DEFAULT_SESSION_DURATION_SEC = 1500; // 25 минут

const formatTime = (totalSeconds: number) => {
  const minutes = Math.floor(totalSeconds / 60)
    .toString()
    .padStart(2, '0');
  const seconds = (totalSeconds % 60).toString().padStart(2, '0');
  return `${minutes}:${seconds}`;
};

const StudySessionTimer: React.FC<Props> = ({
  sessionId,
  userId,
  initialDurationSec = DEFAULT_SESSION_DURATION_SEC,
  onSessionComplete,
}) => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<TimerStatus>(TimerStatus.Idle);
  const [remainingSeconds, setRemainingSeconds] = useState(initialDurationSec);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  // Автосохранение прогресса в localStorage
  const storageKey = `study-session-${sessionId}-${userId}`;

  // Загрузка прогресса
  useEffect(() => {
    const saved = localStorage.getItem(storageKey);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (typeof parsed.remainingSeconds === 'number' && parsed.status) {
          setRemainingSeconds(parsed.remainingSeconds);
          setStatus(parsed.status);
        }
      } catch {}
    }
  }, [storageKey]);

  // Сохраняем прогресс при изменении таймера или статуса
  useEffect(() => {
    localStorage.setItem(
      storageKey,
      JSON.stringify({ remainingSeconds, status, timestamp: Date.now() })
    );
  }, [remainingSeconds, status, storageKey]);

  const tick = useCallback(() => {
    setRemainingSeconds((prev) => {
      if (prev <= 1) {
        setStatus(TimerStatus.Completed);
        onSessionComplete && onSessionComplete();
        return 0;
      }
      return prev - 1;
    });
  }, [onSessionComplete]);

  useEffect(() => {
    if (status === TimerStatus.Running) {
      intervalRef.current = setInterval(tick, 1000);
    }
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [status, tick]);

  const handleStartPause = () => {
    if (status === TimerStatus.Running) {
      setStatus(TimerStatus.Paused);
    } else if (status === TimerStatus.Paused || status === TimerStatus.Idle) {
      if (remainingSeconds === 0) {
        setRemainingSeconds(initialDurationSec);
      }
      setStatus(TimerStatus.Running);
    }
  };

  const handleReset = () => {
    setStatus(TimerStatus.Idle);
    setRemainingSeconds(initialDurationSec);
  };

  return (
    <section
      aria-label={t('edu.studyTimer.ariaLabel')}
      className="max-w-xs mx-auto p-6 bg-white dark:bg-zinc-900 rounded-md shadow-md text-center select-none"
    >
      <div
        className={cn(
          'text-6xl font-mono mb-6',
          status === TimerStatus.Completed ? 'text-green-600' : 'text-gray-900 dark:text-gray-100'
        )}
        role="timer"
        aria-live="polite"
        aria-atomic="true"
      >
        {formatTime(remainingSeconds)}
      </div>

      <div className="flex justify-center gap-4">
        <Button
          variant={status === TimerStatus.Running ? 'destructive' : 'primary'}
          onClick={handleStartPause}
          aria-pressed={status === TimerStatus.Running}
          aria-label={status === TimerStatus.Running ? t('edu.studyTimer.pause') : t('edu.studyTimer.start')}
          autoFocus
        >
          {status === TimerStatus.Running ? t('edu.studyTimer.pause') : t('edu.studyTimer.start')}
        </Button>
        <Button onClick={handleReset} variant="outline" aria-label={t('edu.studyTimer.reset')}>
          {t('edu.studyTimer.reset')}
        </Button>
      </div>

      {status === TimerStatus.Completed && (
        <div
          role="alert"
          className="mt-4 text-green-700 dark:text-green-400 font-semibold"
        >
          {t('edu.studyTimer.completed')}
        </div>
      )}
    </section>
  );
};

export default React.memo(StudySessionTimer);
