import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { fetchCourses } from '@/services/api/eduAPI';
import CourseCard from './CourseCard';
import { Input } from '@/shared/components/Input';
import { Pagination } from '@/shared/components/Pagination';
import { Spinner } from '@/shared/components/Spinner';

interface Course {
  id: string;
  title: string;
  description: string;
  thumbnailUrl?: string;
  instructor: string;
  durationHours: number;
  progressPercent?: number;
  rating?: number;
  lessonsCount: number;
  isEnrolled?: boolean;
}

const PAGE_SIZE = 10;

const CourseListView: React.FC = () => {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState(search);

  // Debounce search input
  useEffect(() => {
    const handler = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(handler);
  }, [search]);

  const { data, isLoading, error } = useQuery(
    ['courses', debouncedSearch, page],
    () => fetchCourses({ query: debouncedSearch, page, limit: PAGE_SIZE }),
    {
      keepPreviousData: true,
      staleTime: 60000,
    }
  );

  const totalPages = useMemo(() => {
    if (!data || !data.total) return 1;
    return Math.ceil(data.total / PAGE_SIZE);
  }, [data]);

  const onOpenDetails = useCallback((id: string) => {
    // реализация открытия деталей курса
    console.log('Open course details', id);
  }, []);

  const onEnroll = useCallback((id: string) => {
    // реализация записи на курс
    console.log('Enroll course', id);
  }, []);

  return (
    <section aria-label={t('edu.courseListTitle')} className="space-y-6 px-4 py-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-center gap-4 mb-4">
        <h1 className="text-2xl font-bold">{t('edu.courseListTitle')}</h1>
        <Input
          type="search"
          placeholder={t('edu.searchPlaceholder')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label={t('edu.searchCourses')}
          className="max-w-sm"
        />
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      ) : error ? (
        <div className="text-red-600 text-center">{t('edu.loadError')}</div>
      ) : (
        <>
          {data && data.courses.length === 0 ? (
            <p className="text-center text-muted-foreground">{t('edu.noCoursesFound')}</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
              {data?.courses.map((course: Course) => (
                <CourseCard
                  key={course.id}
                  id={course.id}
                  title={course.title}
                  description={course.description}
                  thumbnailUrl={course.thumbnailUrl}
                  instructor={course.instructor}
                  durationHours={course.durationHours}
                  progressPercent={course.progressPercent}
                  rating={course.rating}
                  lessonsCount={course.lessonsCount}
                  isEnrolled={course.isEnrolled}
                  onOpenDetails={onOpenDetails}
                  onEnroll={onEnroll}
                />
              ))}
            </div>
          )}

          <Pagination
            currentPage={page}
            totalPages={totalPages}
            onPageChange={setPage}
            className="mt-6 flex justify-center"
          />
        </>
      )}
    </section>
  );
};

export default React.memo(CourseListView);
