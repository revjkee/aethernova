import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchAdaptivePlan, submitUserFeedback } from '@/services/api/aiPlannerAPI';
import { Spinner } from '@/shared/components/Spinner';
import { Button } from '@/shared/components/Button';
import { Select } from '@/shared/components/Select';
import { Textarea } from '@/shared/components/Textarea';
import { cn } from '@/shared/utils/cn';

interface LessonStep {
  id: string;
  title: string;
  description: string;
  estimatedTimeMinutes: number;
  confidenceScore: number; // 0-1, AI confidence in recommendation
}

interface Props {
  userId: string;
  courseId: string;
}

const confidenceColor = (score: number): string => {
  if (score > 0.8) return 'text-green-600';
  if (score > 0.5) return 'text-yellow-600';
  return 'text-red-600';
};

const AIAdaptiveLessonPlanner: React.FC<Props> = ({ userId, courseId }) => {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [plan, setPlan] = useState<LessonStep[]>([]);
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState('');
  const [submittingFeedback, setSubmittingFeedback] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);

  const loadPlan = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetchAdaptivePlan(userId, courseId);
      setPlan(response.steps);
    } catch {
      setPlan([]);
    } finally {
      setLoading(false);
    }
  }, [userId, courseId]);

  useEffect(() => {
    loadPlan();
  }, [loadPlan]);

  const selectedStep = useMemo(() => {
    return plan.find((step) => step.id === selectedStepId) || null;
  }, [plan, selectedStepId]);

  const handleFeedbackSubmit = async () => {
    if (!selectedStepId || feedback.trim().length === 0) {
      setFeedbackError(t('edu.aiPlanner.feedbackValidation'));
      return;
    }
    setFeedbackError(null);
    setSubmittingFeedback(true);
    try {
      await submitUserFeedback({ userId, stepId: selectedStepId, feedback });
      setFeedback('');
    } catch (e: any) {
      setFeedbackError(e.message || t('edu.aiPlanner.feedbackSubmitError'));
    } finally {
      setSubmittingFeedback(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner size="lg" />
      </div>
    );
  }

  if (plan.length === 0) {
    return (
      <div className="text-center text-muted-foreground">
        {t('edu.aiPlanner.noRecommendations')}
      </div>
    );
  }

  return (
    <section aria-label={t('edu.aiPlanner.ariaLabel')} className="max-w-5xl mx-auto p-6 bg-white dark:bg-zinc-900 rounded-md shadow-md space-y-6">
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
        {t('edu.aiPlanner.title')}
      </h2>

      <ul className="grid grid-cols-1 md:grid-cols-2 gap-6 max-h-[480px] overflow-y-auto">
        {plan.map((step) => (
          <li
            key={step.id}
            className={cn(
              'border rounded-md p-4 cursor-pointer select-none',
              selectedStepId === step.id
                ? 'border-indigo-600 bg-indigo-50 dark:bg-indigo-900'
                : 'border-gray-300 dark:border-zinc-700',
              'hover:bg-indigo-100 dark:hover:bg-indigo-800'
            )}
            onClick={() => setSelectedStepId(step.id)}
            role="button"
            tabIndex={0}
            aria-pressed={selectedStepId === step.id}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                setSelectedStepId(step.id);
              }
            }}
          >
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 truncate" title={step.title}>
                {step.title}
              </h3>
              <span className={cn('text-sm font-semibold', confidenceColor(step.confidenceScore))}>
                {Math.round(step.confidenceScore * 100)}%
              </span>
            </div>
            <p className="mt-2 text-sm text-muted-foreground line-clamp-3" title={step.description}>
              {step.description}
            </p>
            <div className="mt-3 text-xs text-muted-foreground">
              {t('edu.aiPlanner.estimatedTime', { minutes: step.estimatedTimeMinutes })}
            </div>
          </li>
        ))}
      </ul>

      {selectedStep && (
        <section className="mt-6 p-4 border rounded-md bg-zinc-100 dark:bg-zinc-800">
          <h3 className="text-xl font-semibold mb-3">{t('edu.aiPlanner.selectedStep')}</h3>
          <p className="mb-4">{selectedStep.description}</p>

          <label htmlFor="feedback" className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
            {t('edu.aiPlanner.feedbackLabel')}
          </label>
          <Textarea
            id="feedback"
            value={feedback}
            onChange={(e) => setFeedback(e.target.value)}
            rows={4}
            maxLength={1500}
            placeholder={t('edu.aiPlanner.feedbackPlaceholder')}
            aria-required
          />

          {feedbackError && <p className="text-red-600 text-sm mt-1">{feedbackError}</p>}

          <Button
            variant="primary"
            onClick={handleFeedbackSubmit}
            disabled={submittingFeedback || feedback.trim().length === 0}
            className="mt-3"
          >
            {submittingFeedback ? t('edu.aiPlanner.sending') : t('edu.aiPlanner.sendFeedback')}
          </Button>
        </section>
      )}
    </section>
  );
};

export default React.memo(AIAdaptiveLessonPlanner);
