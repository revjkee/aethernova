import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchLearningPaths, updateUserLearningPaths } from '@/services/api/eduAPI';
import { useTranslation } from 'react-i18next';
import { Input } from '@/shared/components/Input';
import { Button } from '@/shared/components/Button';
import { Checkbox } from '@/shared/components/Checkbox';
import { Spinner } from '@/shared/components/Spinner';
import { cn } from '@/shared/utils/cn';

interface LearningPath {
  id: string;
  title: string;
  description: string;
  totalCourses: number;
  completedCourses: number;
}

interface Props {
  userId: string;
  onSelectionChange?: (selectedIds: string[]) => void;
}

const LearningPathSelector: React.FC<Props> = ({ userId, onSelectionChange }) => {
  const { t } = useTranslation();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());

  const { data, isLoading, error } = useQuery(['learningPaths', userId], () =>
    fetchLearningPaths(userId)
  );

  // Фильтрация по поиску
  const filteredPaths = useMemo(() => {
    if (!data) return [];
    const lowerSearch = searchTerm.toLowerCase();
    return data.filter(
      (path) =>
        path.title.toLowerCase().includes(lowerSearch) ||
        path.description.toLowerCase().includes(lowerSearch)
    );
  }, [data, searchTerm]);

  const togglePath = useCallback(
    (id: string) => {
      setSelectedPaths((prev) => {
        const newSet = new Set(prev);
        if (newSet.has(id)) newSet.delete(id);
        else newSet.add(id);
        onSelectionChange && onSelectionChange(Array.from(newSet));
        return newSet;
      });
    },
    [onSelectionChange]
  );

  const handleSelectAll = () => {
    if (!data) return;
    const allIds = data.map((p) => p.id);
    setSelectedPaths(new Set(allIds));
    onSelectionChange && onSelectionChange(allIds);
  };

  const handleClearAll = () => {
    setSelectedPaths(new Set());
    onSelectionChange && onSelectionChange([]);
  };

  const handleSave = async () => {
    if (!data) return;
    try {
      await updateUserLearningPaths(userId, Array.from(selectedPaths));
    } catch (e) {
      // Ошибки можно обработать или показать уведомление
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <Spinner size="lg" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-center text-red-600">{t('edu.learningPath.loadError')}</div>
    );
  }

  return (
    <section aria-label={t('edu.learningPath.selectorTitle')} className="max-w-5xl mx-auto p-6 bg-white dark:bg-zinc-900 rounded-md shadow-md">
      <h2 className="text-2xl font-semibold mb-4 text-gray-900 dark:text-gray-100">
        {t('edu.learningPath.selectorTitle')}
      </h2>

      <div className="mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <Input
          type="search"
          placeholder={t('edu.learningPath.searchPlaceholder')}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          aria-label={t('edu.learningPath.searchAriaLabel')}
          className="max-w-md"
        />
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleSelectAll}>
            {t('edu.learningPath.selectAll')}
          </Button>
          <Button variant="outline" size="sm" onClick={handleClearAll}>
            {t('edu.learningPath.clearAll')}
          </Button>
        </div>
      </div>

      <ul className="grid grid-cols-1 md:grid-cols-2 gap-6 max-h-[480px] overflow-y-auto">
        {filteredPaths.length === 0 && (
          <li className="col-span-full text-center text-muted-foreground">
            {t('edu.learningPath.noResults')}
          </li>
        )}
        {filteredPaths.map((path) => {
          const progressPercent = path.totalCourses
            ? Math.round((path.completedCourses / path.totalCourses) * 100)
            : 0;
          const isSelected = selectedPaths.has(path.id);

          return (
            <li
              key={path.id}
              className={cn(
                'border rounded-md p-4 cursor-pointer select-none',
                isSelected ? 'border-indigo-600 bg-indigo-50 dark:bg-indigo-900' : 'border-gray-300 dark:border-zinc-700',
                'hover:bg-indigo-100 dark:hover:bg-indigo-800'
              )}
              onClick={() => togglePath(path.id)}
              role="checkbox"
              aria-checked={isSelected}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  togglePath(path.id);
                }
              }}
            >
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold truncate text-gray-900 dark:text-gray-100" title={path.title}>
                  {path.title}
                </h3>
                <Checkbox
                  checked={isSelected}
                  onChange={() => togglePath(path.id)}
                  ariaLabel={`${t('edu.learningPath.select')} ${path.title}`}
                />
              </div>
              <p className="mt-1 text-sm text-muted-foreground line-clamp-3" title={path.description}>
                {path.description}
              </p>
              <div className="mt-3">
                <progress
                  value={progressPercent}
                  max={100}
                  className="w-full h-2 rounded bg-gray-200 dark:bg-zinc-700"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={progressPercent}
                  aria-label={t('edu.learningPath.progressAria', { progress: progressPercent })}
                />
                <div className="text-xs mt-1 text-muted-foreground flex justify-between">
                  <span>{t('edu.learningPath.coursesCompleted', { completed: path.completedCourses })}</span>
                  <span>{t('edu.learningPath.totalCourses', { total: path.totalCourses })}</span>
                </div>
              </div>
            </li>
          );
        })}
      </ul>

      <div className="mt-6 flex justify-end">
        <Button variant="primary" onClick={handleSave} disabled={selectedPaths.size === 0}>
          {t('edu.learningPath.saveSelection')}
        </Button>
      </div>
    </section>
  );
};

export default React.memo(LearningPathSelector);
