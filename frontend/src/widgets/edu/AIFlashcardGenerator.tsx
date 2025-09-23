import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { generateFlashcards, cancelGeneration } from '@/services/api/aiFlashcardAPI';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { Textarea } from '@/shared/components/Textarea';
import { Input } from '@/shared/components/Input';
import { Select } from '@/shared/components/Select';
import { cn } from '@/shared/utils/cn';

interface GenerationParams {
  topic: string;
  difficulty: 'easy' | 'medium' | 'hard';
  quantity: number; // число флеш-карт
}

interface Flashcard {
  question: string;
  answer: string;
  id: string;
}

interface Props {}

const difficultyOptions = [
  { label: 'Easy', value: 'easy' },
  { label: 'Medium', value: 'medium' },
  { label: 'Hard', value: 'hard' },
];

const AIFlashcardGenerator: React.FC<Props> = () => {
  const { t } = useTranslation();

  const [params, setParams] = useState<GenerationParams>({
    topic: '',
    difficulty: 'medium',
    quantity: 10,
  });
  const [loading, setLoading] = useState(false);
  const [flashcards, setFlashcards] = useState<Flashcard[]>([]);
  const [error, setError] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const handleParamChange = useCallback(
    <K extends keyof GenerationParams>(key: K, value: GenerationParams[K]) => {
      setParams((prev) => ({ ...prev, [key]: value }));
    },
    []
  );

  const startGeneration = useCallback(async () => {
    if (loading || !params.topic.trim()) {
      setError(params.topic.trim() ? null : t('edu.aiFlashcardGen.errorEmptyTopic'));
      return;
    }
    setError(null);
    setLoading(true);
    abortControllerRef.current = new AbortController();

    try {
      const result = await generateFlashcards(params, abortControllerRef.current.signal);
      setFlashcards(result.flashcards);
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setError(err.message || t('edu.aiFlashcardGen.errorGenerate'));
      }
    } finally {
      setLoading(false);
      abortControllerRef.current = null;
    }
  }, [loading, params, t]);

  const cancelGenerationRequest = useCallback(() => {
    if (abortControllerRef.current) {
      cancelGeneration();
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setLoading(false);
      setError(t('edu.aiFlashcardGen.canceled'));
    }
  }, [t]);

  const handleEditFlashcard = useCallback((id: string, field: 'question' | 'answer', value: string) => {
    setFlashcards((prev) =>
      prev.map((card) =>
        card.id === id ? { ...card, [field]: value } : card
      )
    );
  }, []);

  return (
    <section className="max-w-4xl mx-auto p-6 bg-white dark:bg-zinc-900 rounded-md shadow-md space-y-6">
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
        {t('edu.aiFlashcardGen.title')}
      </h2>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Input
          label={t('edu.aiFlashcardGen.topicLabel')}
          value={params.topic}
          onChange={(e) => handleParamChange('topic', e.target.value)}
          placeholder={t('edu.aiFlashcardGen.topicPlaceholder')}
          required
          autoFocus
        />
        <Select
          label={t('edu.aiFlashcardGen.difficultyLabel')}
          options={difficultyOptions}
          value={params.difficulty}
          onChange={(val) => handleParamChange('difficulty', val as 'easy' | 'medium' | 'hard')}
        />
        <Input
          label={t('edu.aiFlashcardGen.quantityLabel')}
          type="number"
          min={1}
          max={100}
          value={params.quantity}
          onChange={(e) => handleParamChange('quantity', Math.min(100, Math.max(1, Number(e.target.value))))}
        />
      </div>

      <div className="flex gap-4 mt-4">
        {!loading ? (
          <Button variant="primary" onClick={startGeneration}>
            {t('edu.aiFlashcardGen.generate')}
          </Button>
        ) : (
          <Button variant="destructive" onClick={cancelGenerationRequest}>
            {t('edu.aiFlashcardGen.cancel')}
            <Spinner size="sm" className="ml-2" />
          </Button>
        )}
      </div>

      {error && (
        <div role="alert" className="mt-4 text-red-600 dark:text-red-400">
          {error}
        </div>
      )}

      {flashcards.length > 0 && (
        <section className="mt-6 space-y-6 max-h-[600px] overflow-y-auto">
          {flashcards.map(({ id, question, answer }) => (
            <div
              key={id}
              className="border rounded-md p-4 bg-zinc-50 dark:bg-zinc-800"
            >
              <label
                htmlFor={`question-${id}`}
                className="block font-semibold text-gray-900 dark:text-gray-100 mb-1"
              >
                {t('edu.aiFlashcardGen.question')}
              </label>
              <Textarea
                id={`question-${id}`}
                value={question}
                onChange={(e) => handleEditFlashcard(id, 'question', e.target.value)}
                rows={2}
                className="mb-3"
              />
              <label
                htmlFor={`answer-${id}`}
                className="block font-semibold text-gray-900 dark:text-gray-100 mb-1"
              >
                {t('edu.aiFlashcardGen.answer')}
              </label>
              <Textarea
                id={`answer-${id}`}
                value={answer}
                onChange={(e) => handleEditFlashcard(id, 'answer', e.target.value)}
                rows={2}
              />
            </div>
          ))}
        </section>
      )}
    </section>
  );
};

export default React.memo(AIFlashcardGenerator);
