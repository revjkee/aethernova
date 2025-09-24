import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { generateQuiz } from '@/services/api/aiQuizAPI';
import { Button } from '@/shared/components/Button';
import { Modal } from '@/shared/components/Modal';
import { Textarea } from '@/shared/components/Textarea';
import { Spinner } from '@/shared/components/Spinner';
import { cn } from '@/shared/utils/cn';

interface QuizQuestion {
  id: string;
  question: string;
  options: string[];
  correctOptionIndex: number;
  explanation?: string;
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
  topic: string;
  onQuizGenerated: (questions: QuizQuestion[]) => void;
}

const AIQuizGeneratorModal: React.FC<Props> = ({ isOpen, onClose, topic, onQuizGenerated }) => {
  const { t } = useTranslation();

  const [numQuestions, setNumQuestions] = useState(5);
  const [difficulty, setDifficulty] = useState<'easy' | 'medium' | 'hard'>('medium');
  const [customPrompt, setCustomPrompt] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [previewQuestions, setPreviewQuestions] = useState<QuizQuestion[] | null>(null);

  const numQuestionsInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!isOpen) {
      setNumQuestions(5);
      setDifficulty('medium');
      setCustomPrompt('');
      setLoading(false);
      setError(null);
      setPreviewQuestions(null);
    }
  }, [isOpen]);

  const validateInputs = () => {
    if (numQuestions < 1 || numQuestions > 50) {
      setError(t('edu.aiQuizGenerator.errorNumQuestions'));
      return false;
    }
    return true;
  };

  const handleGenerate = useCallback(async () => {
    if (!validateInputs()) return;
    setLoading(true);
    setError(null);
    setPreviewQuestions(null);

    try {
      const questions = await generateQuiz({
        topic,
        numQuestions,
        difficulty,
        customPrompt: customPrompt.trim() || undefined,
      });
      setPreviewQuestions(questions);
      onQuizGenerated(questions);
    } catch {
      setError(t('edu.aiQuizGenerator.errorGenerate'));
    } finally {
      setLoading(false);
    }
  }, [topic, numQuestions, difficulty, customPrompt, onQuizGenerated, t]);

  return (
    <Modal isOpen={isOpen} onClose={onClose} ariaLabel={t('edu.aiQuizGenerator.modalAriaLabel')}>
      <div className="max-w-3xl p-6 space-y-6 bg-white dark:bg-zinc-900 rounded-md">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
          {t('edu.aiQuizGenerator.title', { topic })}
        </h2>

        <div className="space-y-4">
          <div>
            <label htmlFor="num-questions" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
              {t('edu.aiQuizGenerator.numQuestions')}
            </label>
            <input
              id="num-questions"
              type="number"
              min={1}
              max={50}
              value={numQuestions}
              onChange={(e) => setNumQuestions(Number(e.target.value))}
              ref={numQuestionsInputRef}
              className="w-24 p-2 rounded border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              aria-describedby="num-questions-help"
            />
            <small id="num-questions-help" className="text-xs text-gray-500 dark:text-gray-400">
              {t('edu.aiQuizGenerator.numQuestionsHelp')}
            </small>
          </div>

          <div>
            <label htmlFor="difficulty-select" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
              {t('edu.aiQuizGenerator.difficulty')}
            </label>
            <select
              id="difficulty-select"
              value={difficulty}
              onChange={(e) => setDifficulty(e.target.value as typeof difficulty)}
              className="w-40 p-2 rounded border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="easy">{t('edu.aiQuizGenerator.difficultyEasy')}</option>
              <option value="medium">{t('edu.aiQuizGenerator.difficultyMedium')}</option>
              <option value="hard">{t('edu.aiQuizGenerator.difficultyHard')}</option>
            </select>
          </div>

          <div>
            <label htmlFor="custom-prompt" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
              {t('edu.aiQuizGenerator.customPrompt')}
            </label>
            <Textarea
              id="custom-prompt"
              value={customPrompt}
              onChange={(e) => setCustomPrompt(e.target.value)}
              rows={4}
              placeholder={t('edu.aiQuizGenerator.customPromptPlaceholder')}
            />
          </div>
        </div>

        {error && (
          <div role="alert" className="text-red-600 dark:text-red-400 p-2 rounded bg-red-50 dark:bg-red-900">
            {error}
          </div>
        )}

        <div className="flex justify-end space-x-4">
          <Button variant="secondary" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={handleGenerate} disabled={loading} aria-disabled={loading}>
            {loading ? (
              <>
                <Spinner size="sm" className="mr-2" />
                {t('edu.aiQuizGenerator.generating')}
              </>
            ) : (
              t('edu.aiQuizGenerator.generate')
            )}
          </Button>
        </div>

        {previewQuestions && previewQuestions.length > 0 && (
          <section aria-label={t('edu.aiQuizGenerator.previewTitle')} className="mt-8 space-y-4 max-h-72 overflow-y-auto border-t border-gray-200 dark:border-zinc-700 pt-4">
            {previewQuestions.map(({ id, question, options }, idx) => (
              <article
                key={id}
                className="bg-gray-50 dark:bg-zinc-800 p-4 rounded"
                tabIndex={0}
                aria-describedby={`question-${id}-desc`}
              >
                <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2">{`${idx + 1}. ${question}`}</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300">
                  {options.map((opt, i) => (
                    <li key={i} id={`question-${id}-desc`}>
                      {opt}
                    </li>
                  ))}
                </ul>
              </article>
            ))}
          </section>
        )}
      </div>
    </Modal>
  );
};

export default React.memo(AIQuizGeneratorModal);
