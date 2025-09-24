import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchAIHint } from '@/services/api/aiHintAPI';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { Tooltip } from '@/shared/components/Tooltip';

interface Props {
  lessonId: string;
  questionId: string;
  userId: string;
  onHintReceived?: (hint: string) => void;
  className?: string;
}

const AIHintButton: React.FC<Props> = ({
  lessonId,
  questionId,
  userId,
  onHintReceived,
  className,
}) => {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [hint, setHint] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const requestHint = useCallback(async () => {
    if (loading) return;
    setLoading(true);
    setError(null);
    setHint(null);

    abortControllerRef.current = new AbortController();

    try {
      const response = await fetchAIHint({
        lessonId,
        questionId,
        userId,
        signal: abortControllerRef.current.signal,
      });
      setHint(response.hint);
      onHintReceived && onHintReceived(response.hint);
    } catch (err: any) {
      if (err.name === 'AbortError') {
        // Request cancelled by user
      } else {
        setError(t('edu.aiHintError'));
      }
    } finally {
      setLoading(false);
      abortControllerRef.current = null;
    }
  }, [lessonId, questionId, userId, loading, onHintReceived, t]);

  const cancelRequest = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    return () => {
      // Cleanup on unmount
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  return (
    <div className={className}>
      <Tooltip content={t('edu.aiHintTooltip')}>
        <Button
          onClick={loading ? cancelRequest : requestHint}
          variant={loading ? 'destructive' : 'primary'}
          aria-live="polite"
          aria-busy={loading}
          aria-label={loading ? t('edu.cancelHintRequest') : t('edu.requestHint')}
          disabled={loading && !abortControllerRef.current}
        >
          {loading ? (
            <>
              <Spinner size="sm" /> {t('edu.loadingHint')}
            </>
          ) : (
            t('edu.getHint')
          )}
        </Button>
      </Tooltip>
      {error && (
        <div role="alert" className="mt-2 text-sm text-red-600">
          {error}
        </div>
      )}
      {hint && (
        <div
          className="mt-3 p-3 bg-indigo-50 dark:bg-indigo-900 rounded-md text-indigo-900 dark:text-indigo-100 whitespace-pre-wrap"
          aria-live="polite"
        >
          {hint}
        </div>
      )}
    </div>
  );
};

export default React.memo(AIHintButton);
