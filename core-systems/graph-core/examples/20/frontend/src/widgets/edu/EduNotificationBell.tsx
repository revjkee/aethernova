import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchNotificationsPage, markNotificationRead, subscribeToNotifications, unsubscribeFromNotifications } from '@/services/api/notificationAPI';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { cn } from '@/shared/utils/cn';

interface Notification {
  id: string;
  title: string;
  message: string;
  timestamp: string; // ISO string
  read: boolean;
  type: 'info' | 'warning' | 'success' | 'error';
}

interface Props {
  userId: string;
  courseId: string;
  className?: string;
}

const PAGE_SIZE = 20;

const EduNotificationBell: React.FC<Props> = ({ userId, courseId, className }) => {
  const { t } = useTranslation();

  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement | null>(null);

  const unreadCount = notifications.filter((n) => !n.read).length;

  // Загрузка уведомлений
  const loadNotifications = useCallback(async (pageNum: number) => {
    setLoading(true);
    setError(null);
    try {
      const { entries, totalCount } = await fetchNotificationsPage(userId, courseId, pageNum, PAGE_SIZE);
      if (pageNum === 1) {
        setNotifications(entries);
      } else {
        setNotifications((prev) => [...prev, ...entries]);
      }
      setTotalCount(totalCount);
      setPage(pageNum);
    } catch {
      setError(t('edu.notificationBell.loadError'));
    } finally {
      setLoading(false);
    }
  }, [userId, courseId, t]);

  useEffect(() => {
    if (dropdownOpen) loadNotifications(1);
  }, [dropdownOpen, loadNotifications]);

  // Подписка на новые уведомления
  useEffect(() => {
    const handleNewNotification = (notification: Notification) => {
      setNotifications((prev) => [notification, ...prev]);
    };
    subscribeToNotifications(userId, courseId, handleNewNotification);
    return () => {
      unsubscribeFromNotifications(userId, courseId);
    };
  }, [userId, courseId]);

  // Маркировка уведомления как прочитанного
  const markAsRead = useCallback(async (id: string) => {
    try {
      await markNotificationRead(userId, id);
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, read: true } : n))
      );
    } catch {
      // Ошибки можно логировать или показывать уведомления
    }
  }, [userId]);

  // Закрытие дропдауна при клике вне
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setDropdownOpen(false);
      }
    };
    if (dropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [dropdownOpen]);

  const totalPages = totalCount ? Math.ceil(totalCount / PAGE_SIZE) : 1;

  return (
    <div className={cn('relative inline-block', className)}>
      <button
        aria-label={t('edu.notificationBell.ariaLabel')}
        aria-haspopup="true"
        aria-expanded={dropdownOpen}
        onClick={() => setDropdownOpen((open) => !open)}
        className="relative p-2 rounded-full hover:bg-gray-200 dark:hover:bg-zinc-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
      >
        <svg
          className="w-6 h-6 text-gray-700 dark:text-gray-300"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9"></path>
          <path d="M13.73 21a2 2 0 01-3.46 0"></path>
        </svg>
        {unreadCount > 0 && (
          <span
            className="absolute top-0 right-0 inline-flex items-center justify-center px-2 py-1 text-xs font-bold leading-none text-white bg-red-600 rounded-full"
            aria-label={t('edu.notificationBell.unreadCount', { count: unreadCount })}
          >
            {unreadCount}
          </span>
        )}
      </button>

      {dropdownOpen && (
        <div
          ref={dropdownRef}
          className="absolute right-0 mt-2 w-96 max-h-96 overflow-y-auto bg-white dark:bg-zinc-900 border border-gray-300 dark:border-zinc-700 rounded-md shadow-lg z-50"
          role="dialog"
          aria-modal="true"
          aria-labelledby="notification-bell-title"
        >
          <h3
            id="notification-bell-title"
            className="p-4 font-semibold text-gray-900 dark:text-gray-100 border-b border-gray-200 dark:border-zinc-700"
          >
            {t('edu.notificationBell.title')}
          </h3>

          {loading && (
            <div className="flex justify-center py-8">
              <Spinner size="lg" />
            </div>
          )}

          {error && (
            <div role="alert" className="text-center text-red-600 dark:text-red-400 p-4">
              {error}
            </div>
          )}

          {!loading && !error && notifications.length === 0 && (
            <div className="text-center text-muted-foreground p-6">
              {t('edu.notificationBell.noNotifications')}
            </div>
          )}

          <ul className="divide-y divide-gray-200 dark:divide-zinc-700 max-h-72 overflow-y-auto">
            {notifications.map(({ id, title, message, timestamp, read, type }) => (
              <li
                key={id}
                className={cn(
                  'p-4 cursor-pointer hover:bg-indigo-50 dark:hover:bg-indigo-900 flex flex-col',
                  !read ? 'bg-indigo-100 dark:bg-indigo-800' : ''
                )}
                onClick={() => {
                  if (!read) markAsRead(id);
                }}
                tabIndex={0}
                role="button"
                aria-pressed={read}
                aria-label={`${title}: ${message}. ${read ? t('edu.notificationBell.read') : t('edu.notificationBell.unread')}`}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    if (!read) markAsRead(id);
                  }
                }}
              >
                <div className="flex justify-between items-center">
                  <h4 className="font-semibold text-gray-900 dark:text-gray-100 truncate max-w-[75%]">
                    {title}
                  </h4>
                  <time
                    dateTime={timestamp}
                    className="text-xs text-gray-500 dark:text-gray-400"
                  >
                    {new Date(timestamp).toLocaleString()}
                  </time>
                </div>
                <p className="text-sm text-gray-700 dark:text-gray-300 mt-1 truncate">
                  {message}
                </p>
              </li>
            ))}
          </ul>

          {totalPages > 1 && (
            <div className="flex justify-between p-4 border-t border-gray-200 dark:border-zinc-700">
              <Button
                variant="outline"
                onClick={() => loadNotifications(page - 1)}
                disabled={page <= 1}
                aria-disabled={page <= 1}
                aria-label={t('edu.notificationBell.prevPage')}
              >
                {t('edu.notificationBell.prev')}
              </Button>
              <span className="text-sm text-gray-600 dark:text-gray-400 select-none" aria-live="polite" aria-atomic="true">
                {t('edu.notificationBell.pageInfo', { current: page, total: totalPages })}
              </span>
              <Button
                variant="outline"
                onClick={() => loadNotifications(page + 1)}
                disabled={page >= totalPages}
                aria-disabled={page >= totalPages}
                aria-label={t('edu.notificationBell.nextPage')}
              >
                {t('edu.notificationBell.next')}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default React.memo(EduNotificationBell);
