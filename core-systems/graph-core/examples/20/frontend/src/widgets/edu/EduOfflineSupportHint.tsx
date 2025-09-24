import React, { useEffect, useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/shared/utils/cn';

interface Props {
  courseId: string;
  className?: string;
}

type OfflineStatus = 'supported' | 'unsupported' | 'no-cache' | 'checking' | 'offline';

const EduOfflineSupportHint: React.FC<Props> = ({ courseId, className }) => {
  const { t } = useTranslation();

  const [offlineStatus, setOfflineStatus] = useState<OfflineStatus>('checking');
  const [lastCacheUpdate, setLastCacheUpdate] = useState<Date | null>(null);
  const [isOnline, setIsOnline] = useState<boolean>(navigator.onLine);

  // Обработчик изменений состояния сети
  const updateOnlineStatus = useCallback(() => {
    setIsOnline(navigator.onLine);
  }, []);

  // Проверка поддержки офлайн и состояния кеша
  const checkOfflineSupport = useCallback(async () => {
    setOfflineStatus('checking');
    try {
      if (!('caches' in window)) {
        setOfflineStatus('unsupported');
        return;
      }
      const cache = await caches.open(`course-cache-${courseId}`);
      const keys = await cache.keys();
      if (keys.length === 0) {
        setOfflineStatus('no-cache');
        setLastCacheUpdate(null);
      } else {
        // Можно усовершенствовать, анализируя время последнего обновления
        setOfflineStatus('supported');
        setLastCacheUpdate(new Date()); // заглушка, надо брать реальное время из метаданных кеша
      }
    } catch {
      setOfflineStatus('unsupported');
      setLastCacheUpdate(null);
    }
  }, [courseId]);

  useEffect(() => {
    updateOnlineStatus();
    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);
    checkOfflineSupport();
    return () => {
      window.removeEventListener('online', updateOnlineStatus);
      window.removeEventListener('offline', updateOnlineStatus);
    };
  }, [updateOnlineStatus, checkOfflineSupport]);

  if (offlineStatus === 'checking') {
    return (
      <div
        className={cn(
          'p-4 rounded bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-300',
          className
        )}
        role="status"
        aria-live="polite"
      >
        {t('edu.offlineSupport.checking')}
      </div>
    );
  }

  if (offlineStatus === 'unsupported') {
    return (
      <div
        className={cn(
          'p-4 rounded bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300',
          className
        )}
        role="alert"
        aria-live="assertive"
      >
        {t('edu.offlineSupport.unsupported')}
      </div>
    );
  }

  if (offlineStatus === 'no-cache') {
    return (
      <div
        className={cn(
          'p-4 rounded bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300',
          className
        )}
        role="alert"
        aria-live="polite"
      >
        {t('edu.offlineSupport.noCache')}
      </div>
    );
  }

  if (offlineStatus === 'supported') {
    return (
      <div
        className={cn(
          'p-4 rounded bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 flex flex-col md:flex-row md:justify-between items-center',
          className
        )}
        role="status"
        aria-live="polite"
      >
        <p>
          {isOnline
            ? t('edu.offlineSupport.onlineWithCache', {
                lastUpdate: lastCacheUpdate ? lastCacheUpdate.toLocaleString() : t('edu.offlineSupport.unknownDate'),
              })
            : t('edu.offlineSupport.offlineMode')}
        </p>
        <button
          onClick={checkOfflineSupport}
          className="mt-2 md:mt-0 px-3 py-1 bg-indigo-600 dark:bg-indigo-400 text-white dark:text-zinc-900 rounded hover:bg-indigo-700 dark:hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          aria-label={t('edu.offlineSupport.refresh')}
        >
          {t('edu.offlineSupport.refresh')}
        </button>
      </div>
    );
  }

  return null;
};

export default React.memo(EduOfflineSupportHint);
