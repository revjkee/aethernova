import React, { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import ReactPlayer from 'react-player/lazy';
import { useQuery, useMutation } from '@tanstack/react-query';
import { fetchLessonContent, saveProgress } from '@/services/api/eduAPI';
import { Spinner } from '@/shared/components/Spinner';
import { Button } from '@/shared/components/Button';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { Tooltip } from '@/shared/components/Tooltip';
import { AiHintPanel } from '@/widgets/Edu/components/AiHintPanel';
import { cn } from '@/shared/utils/cn';

interface LessonViewerProps {
  lessonId: string;
  userId: string;
  onComplete?: () => void;
}

type ContentType = 'text' | 'video' | 'ai';

interface LessonContent {
  id: string;
  title: string;
  contentType: ContentType;
  textContent?: string;
  videoUrl?: string;
  aiContentId?: string;
  durationSeconds?: number;
}

const LessonViewer: React.FC<LessonViewerProps> = ({ lessonId, userId, onComplete }) => {
  const { t } = useTranslation();
  const [progress, setProgress] = useState(0);
  const [aiHintsVisible, setAiHintsVisible] = useState(false);
  const videoRef = useRef<ReactPlayer | null>(null);

  const { data: lesson, isLoading, error } = useQuery(['lessonContent', lessonId], () =>
    fetchLessonContent(lessonId)
  );

  const saveProgressMutation = useMutation(saveProgress);

  useEffect(() => {
    if (!lesson) return;
    setProgress(0);
    setAiHintsVisible(false);
  }, [lessonId, lesson]);

  const onVideoProgress = useCallback(
    (state: { playedSeconds: number }) => {
      if (!lesson?.durationSeconds) return;
      const newProgress = Math.min(100, (state.playedSeconds / lesson.durationSeconds) * 100);
      if (newProgress > progress) {
        setProgress(newProgress);
        saveProgressMutation.mutate({ userId, lessonId, progress: newProgress });
      }
      if (newProgress >= 100 && onComplete) {
        onComplete();
      }
    },
    [progress, lesson, userId, lessonId, onComplete, saveProgressMutation]
  );

  const toggleAiHints = () => setAiHintsVisible((v) => !v);

  const renderContent = useMemo(() => {
    if (!lesson) return null;

    switch (lesson.contentType) {
      case 'text':
        return (
          <div
            className={cn(
              'prose max-w-none dark:prose-invert',
              'overflow-y-auto max-h-[500px] px-2 py-3 rounded-md border border-gray-300 dark:border-zinc-700'
            )}
            dangerouslySetInnerHTML={{ __html: lesson.textContent || '' }}
          />
        );

      case 'video':
        return (
          <div className="relative w-full aspect-video rounded-md overflow-hidden shadow-lg">
            <ReactPlayer
              ref={(ref) => (videoRef.current = ref)}
              url={lesson.videoUrl}
              width="100%"
              height="100%"
              controls
              onProgress={onVideoProgress}
              onEnded={() => {
                setProgress(100);
                if (onComplete) onComplete();
              }}
              config={{
                file: {
                  attributes: {
                    preload: 'metadata',
                    controlsList: 'nodownload',
                  },
                },
              }}
            />
          </div>
        );

      case 'ai':
        return (
          <AiHintPanel
            contentId={lesson.aiContentId || ''}
            userId={userId}
            visible={aiHintsVisible}
            onToggle={toggleAiHints}
          />
        );

      default:
        return <p>{t('edu.lessonContentNotAvailable')}</p>;
    }
  }, [lesson, onVideoProgress, aiHintsVisible, toggleAiHints, t, userId, onComplete]);

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <Spinner size="lg" />
      </div>
    );
  }

  if (error || !lesson) {
    return (
      <div className="text-center text-red-600">{t('edu.lessonLoadError')}</div>
    );
  }

  return (
    <section
      aria-labelledby="lesson-title"
      className="max-w-4xl mx-auto p-4 bg-white dark:bg-zinc-900 rounded-lg shadow-md"
    >
      <h2
        id="lesson-title"
        className="text-2xl font-semibold mb-4 text-gray-900 dark:text-gray-100 truncate"
        title={lesson.title}
      >
        {lesson.title}
      </h2>

      <div>{renderContent}</div>

      <div className="mt-4 flex items-center gap-4">
        <ProgressBar value={progress} />
        <Tooltip content={aiHintsVisible ? t('edu.hideAiHints') : t('edu.showAiHints')}>
          <Button variant="outline" size="sm" onClick={toggleAiHints} aria-pressed={aiHintsVisible}>
            {aiHintsVisible ? t('edu.hideHints') : t('edu.showHints')}
          </Button>
        </Tooltip>
      </div>
    </section>
  );
};

export default React.memo(LessonViewer);
