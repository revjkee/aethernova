import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { generateContent, cancelGeneration } from '@/services/api/aiContentAPI';
import { Spinner } from '@/shared/components/Spinner';
import { Button } from '@/shared/components/Button';
import { Textarea } from '@/shared/components/Textarea';
import { Input } from '@/shared/components/Input';
import { Select } from '@/shared/components/Select';
import { cn } from '@/shared/utils/cn';

interface GenerationParams {
  topic: string;
  contentType: 'lesson' | 'test';
  difficulty: 'easy' | 'medium' | 'hard';
  length: number; // количество сгенерированных блоков/вопросов
}

interface GeneratedContent {
  id: string;
  title: string;
  body: string;
  createdAt: string;
  type: 'lesson' | 'test';
}

const contentTypeOptions = [
  { label: 'Lesson', value: 'lesson' },
  { label: 'Test', value: 'test' },
];

const difficultyOptions = [
  { label: 'Easy', value: 'easy' },
  { label: 'Medium', value: 'medium' },
  { label: 'Hard', value: 'hard' },
];

const AIContentGenerationPanel: React.FC = () => {
  const { t } = useTranslation();
  const [params, setParams] = useState<GenerationParams>({
    topic: '',
    contentType: 'lesson',
    difficulty: 'medium',
    length: 5,
  });
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState<GeneratedContent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const handleParamChange = useCallback(
    <K extends keyof GenerationParams>(key: K, value: GenerationParams[K]) => {
      setParams((prev) => ({ ...prev, [key]: value }));
    },
    []
  );

  const startGeneration = useCallback(async () => {
    if (generating || !params.topic.trim()) {
      setError(params.topic.trim() ? null : t('edu.aiContentGen.errorEmptyTopic'));
      return;
    }
    setError(null);
    setGenerating(true);
    abortControllerRef.current = new AbortController();

    try {
      const content = await generateContent(params, abortControllerRef.current.signal);
      setGenerated(content);
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setError(err.message || t('edu.aiContentGen.errorGenerate'));
      }
    } finally {
      setGenerating(false);
      abortControllerRef.current = null;
    }
  }, [generating, params, t]);

  const cancelGenerationRequest = useCallback(() => {
    if (abortControllerRef.current) {
      cancelGeneration();
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setGenerating(false);
      setError(t('edu.aiContentGen.canceled'));
    }
  }, [t]);

  const handleEditContent = (newBody: string) => {
    setGenerated((prev) => (prev ? { ...prev, body: newBody } : null));
  };

  return (
    <section className="max-w-4xl mx-auto p-6 bg-white dark:bg-zinc-900 rounded-md shadow-md space-y-6">
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
        {t('edu.aiContentGen.title')}
      </h2>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Input
          label={t('edu.aiContentGen.topicLabel')}
          value={params.topic}
          onChange={(e) => handleParamChange('topic', e.target.value)}
          placeholder={t('edu.aiContentGen.topicPlaceholder')}
          required
          autoFocus
        />
        <Select
          label={t('edu.aiContentGen.contentTypeLabel')}
          options={contentTypeOptions}
          value={params.contentType}
          onChange={(val) => handleParamChange('contentType', val as 'lesson' | 'test')}
        />
        <Select
          label={t('edu.aiContentGen.difficultyLabel')}
          options={difficultyOptions}
          value={params.difficulty}
          onChange={(val) => handleParamChange('difficulty', val as 'easy' | 'medium' | 'hard')}
        />
      </div>

      <div className="max-w-xs">
        <Input
          label={t('edu.aiContentGen.lengthLabel')}
          type="number"
          min={1}
          max={50}
          value={params.length}
          onChange={(e) => handleParamChange('length', Math.min(50, Math.max(1, Number(e.target.value))))}
        />
      </div>

      <div className="flex gap-4 mt-4">
        {!generating ? (
          <Button variant="primary" onClick={startGeneration}>
            {t('edu.aiContentGen.generate')}
          </Button>
        ) : (
          <Button variant="destructive" onClick={cancelGenerationRequest}>
            {t('edu.aiContentGen.cancel')}
            <Spinner size="sm" className="ml-2" />
          </Button>
        )}
      </div>

      {error && (
        <div role="alert" className="mt-4 text-red-600 dark:text-red-400">
          {error}
        </div>
      )}

      {generated && (
        <section className="mt-6 border rounded-md p-4 bg-zinc-50 dark:bg-zinc-800">
          <h3 className="text-xl font-semibold mb-3">{generated.title}</h3>
          <Textarea
            value={generated.body}
            onChange={(e) => handleEditContent(e.target.value)}
            rows={15}
            className="w-full font-mono text-sm"
            aria-label={t('edu.aiContentGen.generatedContent')}
          />
          <div className="mt-4 text-xs text-muted-foreground">
            {t('edu.aiContentGen.generatedAt', { date: new Date(generated.createdAt).toLocaleString() })}
          </div>
        </section>
      )}
    </section>
  );
};

export default React.memo(AIContentGenerationPanel);
