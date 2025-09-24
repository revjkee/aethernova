import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchQuizResult, fetchAIExplanation } from '@/services/api/quizAPI';
import { Button } from '@/shared/components/Button';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { Spinner } from '@/shared/components/Spinner';
import { AiExplanationPanel } from '@/widgets/Edu/components/AiExplanationPanel';
import { cn } from '@/shared/utils/cn';

interface QuizResultFeedbackProps {
  quizId: string;
  userId: string;
  onRetry: () => void;
  onClose: () => void;
}

interface QuestionResult {
  questionId: string;
  correct: boolean;
  userAnswer: string;
  correctAnswer: string;
  explanationId?: string;
}

interface QuizResult {
  totalQuestions: number;
  correctAnswers: number;
  details: QuestionResult[];
}

const QuizResultFeedback: React.FC<QuizResultFeedbackProps> = ({
  quizId,
  userId,
  onRetry,
  onClose,
}) => {
  const { t } = useTranslation();
  const [result, setResult] = useState<QuizResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedQuestion, setSelectedQuestion] = useState<QuestionResult | null>(null);
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);
  const [loadingExplanation, setLoadingExplanation] = useState(false);

  useEffect(() => {
    setLoading(true);
    fetchQuizResult(quizId, userId)
      .then((res) => {
        setResult(res);
        setLoading(false);
      })
      .catch(() => {
        setResult(null);
        setLoading(false);
      });
  }, [quizId, userId]);

  const fetchExplanation = useCallback(async (explanationId?: string) => {
    if (!explanationId) {
      setAiExplanation(null);
      return;
    }
    setLoadingExplanation(true);
    try {
      const explanation = await fetchAIExplanation(explanationId);
      setAiExplanation(explanation);
    } catch {
      setAiExplanation(null);
    } finally {
      setLoadingExplanation(false);
    }
  }, []);

  const selectQuestion = useCallback(
    (question: QuestionResult) => {
      setSelectedQuestion(question);
      fetchExplanation(question.explanationId);
    },
    [fetchExplanation]
  );

  const scorePercent = useMemo(() => {
    if (!result) return 0;
    return Math.round((result.correctAnswers / result.totalQuestions) * 100);
  }, [result]);

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <Spinner size="lg" />
      </div>
    );
  }

  if (!result) {
    return (
      <div className="text-center text-red-600">{t('quiz.resultLoadError')}</div>
    );
  }

  return (
    <section
      aria-label={t('quiz.resultFeedbackTitle')}
      className="max-w-4xl mx-auto p-6 bg-white dark:bg-zinc-900 rounded-lg shadow-md space-y-6"
    >
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
        {t('quiz.resultScore', { score: scorePercent })}
      </h2>

      <ProgressBar value={scorePercent} className="w-full" />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="col-span-1 overflow-y-auto max-h-[400px] border rounded-md p-4 bg-zinc-50 dark:bg-zinc-800">
          <h3 className="text-lg font-medium mb-4">{t('quiz.questionResults')}</h3>
          <ul className="space-y-3">
            {result.details.map((q) => (
              <li key={q.questionId}>
                <button
                  type="button"
                  onClick={() => selectQuestion(q)}
                  className={cn(
                    'w-full text-left px-3 py-2 rounded-md focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500',
                    q.correct
                      ? 'bg-green-100 dark:bg-green-700 text-green-900 dark:text-green-100'
                      : 'bg-red-100 dark:bg-red-700 text-red-900 dark:text-red-100'
                  )}
                  aria-pressed={selectedQuestion?.questionId === q.questionId}
                >
                  <span className="truncate">
                    {q.correct ? t('quiz.correct') : t('quiz.incorrect')} — {q.userAnswer}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div className="col-span-2 flex flex-col gap-4">
          <h3 className="text-lg font-medium">{t('quiz.explanation')}</h3>
          <div className="min-h-[180px] border rounded-md p-4 bg-white dark:bg-zinc-900 overflow-auto">
            {loadingExplanation ? (
              <Spinner size="md" />
            ) : aiExplanation ? (
              <AiExplanationPanel content={aiExplanation} />
            ) : (
              <p className="text-muted-foreground">{t('quiz.noExplanation')}</p>
            )}
          </div>
          <div className="flex gap-4 mt-auto justify-end">
            <Button variant="outline" onClick={onRetry}>
              {t('quiz.retry')}
            </Button>
            <Button variant="primary" onClick={onClose}>
              {t('quiz.close')}
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default React.memo(QuizResultFeedback);
