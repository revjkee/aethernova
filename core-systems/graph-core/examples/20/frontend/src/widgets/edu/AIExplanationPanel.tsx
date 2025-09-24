import React, { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Spinner } from '@/shared/components/Spinner';
import { Tooltip } from '@/shared/components/Tooltip';
import { cn } from '@/shared/utils/cn';

interface Props {
  content?: string | null; // JSON или markdown с многоуровневым текстом
  maxHeight?: number;
  className?: string;
}

interface ExplanationSection {
  title: string;
  details: string;
  recommendations?: string[];
  importanceScore?: number; // 0-1
}

const parseContent = (content?: string | null): ExplanationSection[] => {
  if (!content) return [];
  try {
    const parsed = JSON.parse(content);
    if (Array.isArray(parsed)) {
      return parsed;
    }
    return [];
  } catch {
    // fallback: plain text or markdown parsing
    return [{
      title: '',
      details: content,
    }];
  }
};

const AIExplanationPanel: React.FC<Props> = ({ content, maxHeight = 320, className }) => {
  const { t } = useTranslation();
  const [sections, setSections] = useState<ExplanationSection[]>([]);

  useEffect(() => {
    setSections(parseContent(content));
  }, [content]);

  const totalImportance = useMemo(() => {
    return sections.reduce((sum, sec) => sum + (sec.importanceScore ?? 0), 0);
  }, [sections]);

  if (!content) {
    return (
      <div className={cn('text-sm text-muted-foreground', className)}>
        {t('edu.xai.noExplanation')}
      </div>
    );
  }

  if (sections.length === 0) {
    return (
      <div className={cn('text-sm text-muted-foreground', className)}>
        {t('edu.xai.invalidExplanation')}
      </div>
    );
  }

  return (
    <div
      className={cn('overflow-y-auto', className)}
      style={{ maxHeight }}
      role="region"
      aria-label={t('edu.xai.explanationRegion')}
    >
      {sections.map((sec, idx) => (
        <section
          key={idx}
          className="mb-4 border-l-4 border-indigo-500 pl-4"
          aria-labelledby={`xai-section-title-${idx}`}
        >
          {sec.title && (
            <h4
              id={`xai-section-title-${idx}`}
              className="text-md font-semibold mb-1 text-indigo-700 dark:text-indigo-400"
            >
              {sec.title}
              {sec.importanceScore !== undefined && (
                <Tooltip content={t('edu.xai.importanceTooltip', { score: (sec.importanceScore * 100).toFixed(0) })}>
                  <span className="ml-2 text-xs text-indigo-500 cursor-help">({(sec.importanceScore * 100).toFixed(0)}%)</span>
                </Tooltip>
              )}
            </h4>
          )}
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-gray-800 dark:text-gray-300">
            {sec.details}
          </p>
          {sec.recommendations && sec.recommendations.length > 0 && (
            <ul className="list-disc list-inside mt-2 text-sm text-gray-700 dark:text-gray-400">
              {sec.recommendations.map((rec, i) => (
                <li key={i}>{rec}</li>
              ))}
            </ul>
          )}
        </section>
      ))}
      {totalImportance > 0 && (
        <div className="text-xs text-muted-foreground mt-2 italic">
          {t('edu.xai.totalImportance', { score: (totalImportance * 100).toFixed(0) })}
        </div>
      )}
    </div>
  );
};

export default React.memo(AIExplanationPanel);
