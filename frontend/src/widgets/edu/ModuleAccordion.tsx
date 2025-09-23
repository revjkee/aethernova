import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronDownIcon, ChevronRightIcon } from 'lucide-react';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { cn } from '@/shared/utils/cn';

interface Lesson {
  id: string;
  title: string;
  durationMinutes: number;
  isCompleted: boolean;
}

interface Module {
  id: string;
  title: string;
  description?: string;
  lessons: Lesson[];
}

interface Props {
  modules: Module[];
  onLessonSelect: (lessonId: string) => void;
  expandedModules?: string[]; // controlled expanded state
  onExpandChange?: (expandedIds: string[]) => void;
}

const ModuleAccordion: React.FC<Props> = ({
  modules,
  onLessonSelect,
  expandedModules,
  onExpandChange,
}) => {
  const { t } = useTranslation();
  const [localExpanded, setLocalExpanded] = useState<string[]>([]);

  const isControlled = expandedModules !== undefined;

  const expanded = isControlled ? expandedModules! : localExpanded;

  const toggleModule = useCallback(
    (id: string) => {
      let newExpanded;
      if (expanded.includes(id)) {
        newExpanded = expanded.filter((mId) => mId !== id);
      } else {
        newExpanded = [...expanded, id];
      }
      if (isControlled && onExpandChange) {
        onExpandChange(newExpanded);
      } else {
        setLocalExpanded(newExpanded);
      }
    },
    [expanded, isControlled, onExpandChange]
  );

  const moduleProgress = useCallback((lessons: Lesson[]) => {
    if (lessons.length === 0) return 0;
    const completed = lessons.filter((l) => l.isCompleted).length;
    return Math.round((completed / lessons.length) * 100);
  }, []);

  return (
    <div className="w-full space-y-4">
      {modules.map((module) => {
        const isExpanded = expanded.includes(module.id);
        const progress = moduleProgress(module.lessons);

        return (
          <section
            key={module.id}
            aria-labelledby={`module-header-${module.id}`}
            className="border rounded-md bg-white dark:bg-zinc-900 shadow-sm"
          >
            <header
              id={`module-header-${module.id}`}
              role="button"
              tabIndex={0}
              aria-expanded={isExpanded}
              aria-controls={`module-panel-${module.id}`}
              onClick={() => toggleModule(module.id)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  toggleModule(module.id);
                }
              }}
              className="flex items-center justify-between px-4 py-3 cursor-pointer select-none focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
            >
              <div className="flex items-center gap-3">
                {isExpanded ? (
                  <ChevronDownIcon size={20} />
                ) : (
                  <ChevronRightIcon size={20} />
                )}
                <div>
                  <h3 className="text-base font-semibold text-gray-900 dark:text-gray-100">
                    {module.title}
                  </h3>
                  {module.description && (
                    <p className="text-xs text-muted-foreground truncate max-w-xl">
                      {module.description}
                    </p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-4 min-w-[100px]">
                <span className="text-xs text-muted-foreground">{progress}% {t('edu.completed')}</span>
                <div className="w-24">
                  <ProgressBar value={progress} />
                </div>
              </div>
            </header>

            <div
              id={`module-panel-${module.id}`}
              role="region"
              aria-labelledby={`module-header-${module.id}`}
              className={cn(
                'px-6 pb-4 overflow-hidden transition-max-height duration-300 ease-in-out',
                isExpanded ? 'max-h-[2000px]' : 'max-h-0'
              )}
            >
              <ul className="space-y-2 mt-2">
                {module.lessons.map((lesson) => (
                  <li key={lesson.id}>
                    <button
                      type="button"
                      onClick={() => onLessonSelect(lesson.id)}
                      className={cn(
                        'w-full text-left px-3 py-2 rounded-md focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500',
                        lesson.isCompleted
                          ? 'bg-indigo-100 dark:bg-indigo-700 text-indigo-900 dark:text-indigo-100'
                          : 'text-gray-800 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-800'
                      )}
                      aria-pressed={lesson.isCompleted}
                    >
                      <div className="flex justify-between items-center">
                        <span className="truncate">{lesson.title}</span>
                        <span className="text-xs text-muted-foreground">
                          {lesson.durationMinutes} {t('edu.minutes')}
                        </span>
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </section>
        );
      })}
    </div>
  );
};

export default React.memo(ModuleAccordion);
