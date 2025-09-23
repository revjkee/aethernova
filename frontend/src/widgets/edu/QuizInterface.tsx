import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchQuizQuestions, submitAnswer, fetchAIExplanation } from '@/services/api/quizAPI';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { AiExplanationPanel } from '@/widgets/Edu/components/AiExplanationPanel';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { cn } from '@/shared/utils/cn';

interface AnswerOption {
  id: string;
  text: string;
}

interface Question {
  id: string;
  text: string;
  options: AnswerOption[];
  correctOptionId: string;
  maxAttempts: number;
}

interface Props {
  quizId: string;
  userId: string;
  onComplete?: () => void;
}

const QuizInterface: React.FC<Props> = ({ quizId, userId, onComplete }) => {
  const { t } = useTranslation();
  const [questions, setQuestions] = useState<Question[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [selectedOptionId, setSelectedOptionId] = useState<string | null>(null);
  const [attempts, setAttempts] = useState(0);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [quizCompleted, setQuizCompleted] = useState(false);
  const [progressPercent, setProgressPercent] = useState(0);

  useEffect(() => {
    setLoading(true);
    fetchQuizQuestions(quizId)
      .then((qs) => {
        setQuestions(qs);
        setLoading(false);
        setProgressPercent(0);
        setCurrentIndex(0);
        setSelectedOptionId(null);
        setAttempts(0);
        setFeedback(null);
        setAiExplanation(null);
        setQuizCompleted(false);
      })
      .catch(() => setLoading(false));
  }, [quizId]);

  const currentQuestion = useMemo(() => questions[currentIndex], [questions, currentIndex]);

  const handleSelectOption = (optionId: string) => {
    if (submitting || quizCompleted) return;
    setSelectedOptionId(optionId);
    setFeedback(null);
    setAiExplanation(null);
  };

  const fetchExplanation = useCallback(async (questionId: string, optionId: string) => {
    try {
      const explanation = await fetchAIExplanation({ questionId, optionId, userId });
      setAiExplanation(explanation);
    } catch {
      setAiExplanation(null);
    }
  }, [userId]);

  const handleSubmit = async () => {
    if (!selectedOptionId || !currentQuestion) return;
    setSubmitting(true);

    try {
      const correct = await submitAnswer({
        quizId,
        questionId: currentQuestion.id,
        userId,
        answerId: selectedOptionId,
      });

      setAttempts((a) => a + 1);

      if (correct) {
        setFeedback(t('quiz.correct'));
        fetchExplanation(currentQuestion.id, selectedOptionId);
        if (currentIndex + 1 < questions.length) {
          setTimeout(() => {
            setCurrentIndex((i) => i + 1);
            setSelectedOptionId(null);
            setAttempts(0);
            setFeedback(null);
            setAiExplanation(null);
            setProgressPercent(((currentIndex + 1) / questions.length) * 100);
          }, 1500);
        } else {
          setQuizCompleted(true);
          setProgressPercent(100);
          onComplete && onComplete();
        }
      } else {
        if (attempts + 1 >= currentQuestion.maxAttempts) {
          setFeedback(t('quiz.incorrectMaxAttempts'));
          fetchExplanation(currentQuestion.id, selectedOptionId);
          setTimeout(() => {
            if (currentIndex + 1 < questions.length) {
              setCurrentIndex((i) => i + 1);
              setSelectedOptionId(null);
              setAttempts(0);
              setFeedback(null);
              setAiExplanation(null);
              setProgressPercent(((currentIndex + 1) / questions.length) * 100);
            } else {
              setQuizCompleted(true);
              setProgressPercent(100);
              onComplete && onComplete();
            }
          }, 2000);
        } else {
          setFeedback(t('quiz.incorrectTryAgain'));
          fetchExplanation(currentQuestion.id, selectedOptionId);
        }
      }
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <Spinner size="lg" />
      </div>
    );
  }

  if (!currentQuestion) {
    return (
      <div className="text-center text-muted-foreground">
        {quizCompleted ? t('quiz.completed') : t('quiz.noQuestions')}
      </div>
    );
  }

  return (
    <section
      aria-live="polite"
      className="max-w-3xl mx-auto p-4 bg-white dark:bg-zinc-900 rounded-lg shadow-md"
    >
      <h2 className="text-xl font-semibold mb-4">
        {t('quiz.questionNum', { current: currentIndex + 1, total: questions.length })}
      </h2>

      <div className="mb-6">
        <p className="text-lg font-medium mb-3">{currentQuestion.text}</p>
        <ul className="space-y-3">
          {currentQuestion.options.map((opt) => (
            <li key={opt.id}>
              <button
                type="button"
                onClick={() => handleSelectOption(opt.id)}
                className={cn(
                  'w-full text-left px-4 py-3 rounded-md border',
                  selectedOptionId === opt.id
                    ? 'bg-indigo-600 text-white border-indigo-600'
                    : 'bg-transparent border-gray-300 dark:border-zinc-700 text-gray-900 dark:text-gray-100',
                  'focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500'
                )}
                aria-pressed={selectedOptionId === opt.id}
              >
                {opt.text}
              </button>
            </li>
          ))}
        </ul>
      </div>

      {feedback && (
        <div
          className={cn(
            'mb-4 p-3 rounded-md',
            feedback === t('quiz.correct') ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
          )}
          role="alert"
        >
          {feedback}
        </div>
      )}

      <div className="mb-6">
        <AiExplanationPanel content={aiExplanation} />
      </div>

      <div className="flex justify-between items-center">
        <ProgressBar value={progressPercent} className="flex-grow mr-4" />
        <Button
          variant="primary"
          onClick={handleSubmit}
          disabled={!selectedOptionId || submitting || quizCompleted}
        >
          {t('quiz.submit')}
        </Button>
      </div>
    </section>
  );
};

export default React.memo(QuizInterface);
