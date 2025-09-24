import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchFeedbackTemplates, submitTeacherFeedback } from '@/services/api/teacherFeedbackAPI';
import { Button } from '@/shared/components/Button';
import { Textarea } from '@/shared/components/Textarea';
import { Select } from '@/shared/components/Select';
import { FileUploader } from '@/shared/components/FileUploader';
import { Spinner } from '@/shared/components/Spinner';
import { cn } from '@/shared/utils/cn';

interface FeedbackTemplate {
  id: string;
  label: string;
  text: string;
}

interface Props {
  teacherId: string;
  studentId: string;
  lessonId: string;
  className?: string;
}

const ratingOptions = [
  { label: 'Excellent', value: 5 },
  { label: 'Good', value: 4 },
  { label: 'Satisfactory', value: 3 },
  { label: 'Needs Improvement', value: 2 },
  { label: 'Poor', value: 1 },
];

const TeacherFeedbackPanel: React.FC<Props> = ({
  teacherId,
  studentId,
  lessonId,
  className,
}) => {
  const { t } = useTranslation();
  const [templates, setTemplates] = useState<FeedbackTemplate[]>([]);
  const [loadingTemplates, setLoadingTemplates] = useState(true);
  const [rating, setRating] = useState<number | null>(null);
  const [comment, setComment] = useState('');
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(null);
  const [attachedFiles, setAttachedFiles] = useState<File[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const commentRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    const loadTemplates = async () => {
      setLoadingTemplates(true);
      try {
        const loadedTemplates = await fetchFeedbackTemplates(teacherId);
        if (!cancelled) setTemplates(loadedTemplates);
      } catch {
        if (!cancelled) setTemplates([]);
      } finally {
        if (!cancelled) setLoadingTemplates(false);
      }
    };
    loadTemplates();
    return () => {
      cancelled = true;
    };
  }, [teacherId]);

  useEffect(() => {
    if (selectedTemplateId) {
      const template = templates.find((t) => t.id === selectedTemplateId);
      if (template) {
        setComment((prev) => (prev.trim() === '' ? template.text : prev));
        commentRef.current?.focus();
      }
    }
  }, [selectedTemplateId, templates]);

  const validate = useCallback(() => {
    if (rating === null) {
      setError(t('edu.teacherFeedback.errorRating'));
      return false;
    }
    if (comment.trim().length < 10) {
      setError(t('edu.teacherFeedback.errorCommentLength'));
      return false;
    }
    setError(null);
    return true;
  }, [rating, comment, t]);

  const handleSubmit = async () => {
    if (!validate()) return;
    setSubmitting(true);
    setError(null);
    try {
      await submitTeacherFeedback({
        teacherId,
        studentId,
        lessonId,
        rating: rating as number,
        comment,
        attachments: attachedFiles,
      });
      setRating(null);
      setComment('');
      setAttachedFiles([]);
      setSelectedTemplateId(null);
    } catch (e: any) {
      setError(e.message || t('edu.teacherFeedback.errorSubmit'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section
      aria-label={t('edu.teacherFeedback.ariaLabel')}
      className={cn('max-w-4xl mx-auto bg-white dark:bg-zinc-900 rounded-md shadow-md p-6 space-y-6', className)}
    >
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
        {t('edu.teacherFeedback.title')}
      </h2>

      {loadingTemplates ? (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      ) : (
        <>
          <div>
            <label htmlFor="rating-select" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
              {t('edu.teacherFeedback.ratingLabel')}
            </label>
            <Select
              id="rating-select"
              value={rating !== null ? rating.toString() : ''}
              onChange={(e) => setRating(Number(e.target.value))}
              options={ratingOptions.map(({ label, value }) => ({ label: t(`edu.teacherFeedback.ratings.${label.toLowerCase()}`), value: value.toString() }))}
              placeholder={t('edu.teacherFeedback.ratingPlaceholder')}
            />
          </div>

          <div>
            <label htmlFor="template-select" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
              {t('edu.teacherFeedback.templateLabel')}
            </label>
            <Select
              id="template-select"
              value={selectedTemplateId || ''}
              onChange={(e) => setSelectedTemplateId(e.target.value || null)}
              options={[{ label: t('edu.teacherFeedback.templateNone'), value: '' }].concat(
                templates.map(({ id, label }) => ({ label, value: id }))
              )}
            />
          </div>

          <div>
            <label htmlFor="comment-textarea" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
              {t('edu.teacherFeedback.commentLabel')}
            </label>
            <Textarea
              id="comment-textarea"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={6}
              minLength={10}
              maxLength={2000}
              ref={commentRef}
              placeholder={t('edu.teacherFeedback.commentPlaceholder')}
              required
              aria-required="true"
            />
          </div>

          <div>
            <label className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
              {t('edu.teacherFeedback.attachmentsLabel')}
            </label>
            <FileUploader
              multiple
              accept="image/*,application/pdf"
              files={attachedFiles}
              onFilesChange={setAttachedFiles}
              maxFiles={5}
              maxFileSizeMB={10}
              aria-label={t('edu.teacherFeedback.attachmentsAriaLabel')}
            />
          </div>

          {error && (
            <div role="alert" className="text-red-600 dark:text-red-400">
              {error}
            </div>
          )}

          <div className="flex justify-end">
            <Button
              variant="primary"
              onClick={handleSubmit}
              disabled={submitting}
              aria-disabled={submitting}
            >
              {submitting ? t('edu.teacherFeedback.saving') : t('edu.teacherFeedback.submit')}
            </Button>
          </div>
        </>
      )}
    </section>
  );
};

export default React.memo(TeacherFeedbackPanel);
