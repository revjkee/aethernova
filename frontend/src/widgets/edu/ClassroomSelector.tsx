import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchUserClassrooms, selectClassroom } from '@/services/api/classroomAPI';
import { cn } from '@/shared/utils/cn';
import { Spinner } from '@/shared/components/Spinner';

interface Classroom {
  id: string;
  name: string;
  description?: string;
  memberCount: number;
}

interface Props {
  userId: string;
  onSelect?: (classroomId: string) => void;
  className?: string;
}

const ClassroomSelector: React.FC<Props> = ({ userId, onSelect, className }) => {
  const { t } = useTranslation();
  const [classrooms, setClassrooms] = useState<Classroom[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  // Загрузка списка групп пользователя
  useEffect(() => {
    let cancelled = false;
    const loadClassrooms = async () => {
      setLoading(true);
      setError(null);
      try {
        const list = await fetchUserClassrooms(userId);
        if (!cancelled) {
          setClassrooms(list);
          if (list.length > 0) {
            setSelectedId(list[0].id);
            onSelect?.(list[0].id);
          }
        }
      } catch {
        if (!cancelled) setError(t('edu.classroomSelector.loadError'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    loadClassrooms();
    return () => {
      cancelled = true;
    };
  }, [userId, onSelect, t]);

  // Обработка выбора группы
  const handleSelect = useCallback(
    async (id: string) => {
      setSelectedId(id);
      onSelect?.(id);
      try {
        await selectClassroom(userId, id);
      } catch {
        // Ошибки можно логировать или показывать уведомления
      }
    },
    [userId, onSelect]
  );

  // Фильтрация групп по поиску
  const filteredClassrooms = classrooms.filter((c) =>
    c.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <section
      aria-label={t('edu.classroomSelector.ariaLabel')}
      className={cn(
        'max-w-3xl mx-auto bg-white dark:bg-zinc-900 rounded-md shadow-md p-4',
        className
      )}
    >
      <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
        {t('edu.classroomSelector.title')}
      </h2>

      {loading ? (
        <div className="flex justify-center py-10" aria-live="polite" aria-busy="true">
          <Spinner size="lg" />
        </div>
      ) : error ? (
        <div role="alert" className="text-red-600 dark:text-red-400 text-center p-4">
          {error}
        </div>
      ) : classrooms.length === 0 ? (
        <div className="text-center text-muted-foreground p-6">
          {t('edu.classroomSelector.noGroups')}
        </div>
      ) : (
        <>
          <label htmlFor="classroom-search" className="sr-only">
            {t('edu.classroomSelector.searchLabel')}
          </label>
          <input
            id="classroom-search"
            type="search"
            placeholder={t('edu.classroomSelector.searchPlaceholder')}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            ref={searchInputRef}
            className="w-full mb-4 p-2 rounded border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            aria-label={t('edu.classroomSelector.searchAria')}
            autoComplete="off"
          />

          <ul role="listbox" aria-activedescendant={selectedId ?? undefined} tabIndex={0} className="space-y-2 max-h-72 overflow-y-auto">
            {filteredClassrooms.length === 0 ? (
              <li className="text-center text-muted-foreground p-4">
                {t('edu.classroomSelector.noResults')}
              </li>
            ) : (
              filteredClassrooms.map(({ id, name, description, memberCount }) => {
                const isSelected = id === selectedId;
                return (
                  <li
                    key={id}
                    id={id}
                    role="option"
                    aria-selected={isSelected}
                    tabIndex={-1}
                    className={cn(
                      'cursor-pointer rounded p-3 flex justify-between items-center',
                      isSelected
                        ? 'bg-indigo-600 text-white'
                        : 'hover:bg-indigo-100 dark:hover:bg-indigo-900 text-gray-900 dark:text-gray-100'
                    )}
                    onClick={() => handleSelect(id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        handleSelect(id);
                      }
                    }}
                  >
                    <div className="flex flex-col">
                      <span className="font-semibold truncate max-w-xs">{name}</span>
                      {description && (
                        <span className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">
                          {description}
                        </span>
                      )}
                    </div>
                    <span className="text-sm text-gray-600 dark:text-gray-400 whitespace-nowrap">
                      {t('edu.classroomSelector.membersCount', { count: memberCount })}
                    </span>
                  </li>
                );
              })
            )}
          </ul>
        </>
      )}
    </section>
  );
};

export default React.memo(ClassroomSelector);
