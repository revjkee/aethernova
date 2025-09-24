import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchLeaderboardPage } from '@/services/api/leaderboardAPI';
import { Spinner } from '@/shared/components/Spinner';
import { Button } from '@/shared/components/Button';
import { cn } from '@/shared/utils/cn';

interface StudentEntry {
  userId: string;
  userName: string;
  avatarUrl?: string;
  rank: number;
  activityScore: number; // 0-1000, например
  completedCourses: number;
}

interface Props {
  courseId: string;
  pageSize?: number;
  className?: string;
}

const StudentLeaderboard: React.FC<Props> = ({
  courseId,
  pageSize = 20,
  className,
}) => {
  const { t } = useTranslation();

  const [page, setPage] = useState(1);
  const [students, setStudents] = useState<StudentEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadPage = useCallback(async (pageNumber: number) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchLeaderboardPage(courseId, pageNumber, pageSize);
      setStudents(response.entries);
      setTotalCount(response.totalCount);
      setPage(pageNumber);
    } catch {
      setError(t('edu.leaderboard.loadError'));
    } finally {
      setLoading(false);
    }
  }, [courseId, pageSize, t]);

  useEffect(() => {
    loadPage(1);
  }, [loadPage]);

  const totalPages = useMemo(() => {
    if (!totalCount) return 1;
    return Math.ceil(totalCount / pageSize);
  }, [totalCount, pageSize]);

  const handlePrev = () => {
    if (page > 1) loadPage(page - 1);
  };

  const handleNext = () => {
    if (page < totalPages) loadPage(page + 1);
  };

  return (
    <section
      aria-label={t('edu.leaderboard.ariaLabel')}
      className={cn('max-w-5xl mx-auto p-4 bg-white dark:bg-zinc-900 rounded-md shadow-md', className)}
    >
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
        {t('edu.leaderboard.title')}
      </h2>

      {loading ? (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      ) : error ? (
        <div role="alert" className="text-center text-red-600 dark:text-red-400">
          {error}
        </div>
      ) : students.length === 0 ? (
        <div className="text-center text-muted-foreground">{t('edu.leaderboard.noEntries')}</div>
      ) : (
        <>
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-gray-100 dark:bg-zinc-800 text-gray-700 dark:text-gray-300">
                <th className="text-left p-3">#{t('edu.leaderboard.rank')}</th>
                <th className="text-left p-3">{t('edu.leaderboard.student')}</th>
                <th className="text-right p-3">{t('edu.leaderboard.activityScore')}</th>
                <th className="text-right p-3">{t('edu.leaderboard.completedCourses')}</th>
              </tr>
            </thead>
            <tbody>
              {students.map(({ userId, userName, avatarUrl, rank, activityScore, completedCourses }) => (
                <tr
                  key={userId}
                  className="border-b border-gray-200 dark:border-zinc-700 hover:bg-indigo-50 dark:hover:bg-indigo-900"
                >
                  <td className="p-3 font-mono">{rank}</td>
                  <td className="p-3 flex items-center gap-3">
                    <img
                      src={avatarUrl || '/assets/default-avatar.png'}
                      alt={t('edu.leaderboard.avatarAlt', { name: userName })}
                      className="w-8 h-8 rounded-full object-cover"
                      loading="lazy"
                    />
                    <span className="truncate max-w-[200px]">{userName}</span>
                  </td>
                  <td className="p-3 text-right">{activityScore}</td>
                  <td className="p-3 text-right">{completedCourses}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="mt-6 flex justify-between items-center">
            <Button
              variant="outline"
              onClick={handlePrev}
              disabled={page <= 1}
              aria-disabled={page <= 1}
              aria-label={t('edu.leaderboard.prevPage')}
            >
              {t('edu.leaderboard.prev')}
            </Button>
            <div className="text-sm text-gray-600 dark:text-gray-400 select-none" aria-live="polite" aria-atomic="true">
              {t('edu.leaderboard.pageInfo', { current: page, total: totalPages })}
            </div>
            <Button
              variant="outline"
              onClick={handleNext}
              disabled={page >= totalPages}
              aria-disabled={page >= totalPages}
              aria-label={t('edu.leaderboard.nextPage')}
            >
              {t('edu.leaderboard.next')}
            </Button>
          </div>
        </>
      )}
    </section>
  );
};

export default React.memo(StudentLeaderboard);
