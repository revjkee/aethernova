import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchHomeworkSubmission, fetchReviewHistory, submitReview } from '@/services/api/eduAPI';
import { Spinner } from '@/shared/components/Spinner';
import { Button } from '@/shared/components/Button';
import { Textarea } from '@/shared/components/Textarea';
import { Select } from '@/shared/components/Select';
import { cn } from '@/shared/utils/cn';

interface Submission {
  id: string;
  studentId: string;
  studentName: string;
  files: string[]; // URL или идентификаторы файлов
  submittedAt: string;
}

interface Review {
  id: string;
  reviewerId: string;
  reviewerName: string;
  rating: number; // 1-5
  comment: string;
  reviewedAt: string;
}

interface Props {
  submissionId: string;
  reviewerId: string;
  onReviewSubmitted?: () => void;
}

const ratingOptions = [
  { label: '1 - Очень плохо', value: 1 },
  { label: '2 - Плохо', value: 2 },
  { label: '3 - Средне', value: 3 },
  { label: '4 - Хорошо', value: 4 },
  { label: '5 - Отлично', value: 5 },
];

const HomeworkReviewInterface: React.FC<Props> = ({
  submissionId,
  reviewerId,
  onReviewSubmitted,
}) => {
  const { t } = useTranslation();
  const [submission, setSubmission] = useState<Submission | null>(null);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loadingSubmission, setLoadingSubmission] = useState(true);
  const [loadingReviews, setLoadingReviews] = useState(true);
  const [rating, setRating] = useState<number | null>(null);
  const [comment, setComment] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadSubmission = useCallback(async () => {
    setLoadingSubmission(true);
    try {
      const data = await fetchHomeworkSubmission(submissionId);
      setSubmission(data);
    } catch {
      setSubmission(null);
    } finally {
      setLoadingSubmission(false);
    }
  }, [submissionId]);

  const loadReviews = useCallback(async () => {
    setLoadingReviews(true);
    try {
      const data = await fetchReviewHistory(submissionId);
      setReviews(data);
    } catch {
      setReviews([]);
    } finally {
      setLoadingReviews(false);
    }
  }, [submissionId]);

  useEffect(() => {
    loadSubmission();
    loadReviews();
  }, [loadSubmission, loadReviews]);

  const handleSubmitReview = async () => {
    if (rating === null || comment.trim().length === 0) {
      setError(t('edu.review.validationRequired'));
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      await submitReview({ submissionId, reviewerId, rating, comment });
      setRating(null);
      setComment('');
      onReviewSubmitted && onReviewSubmitted();
      await loadReviews();
    } catch (e: any) {
      setError(e.message || t('edu.review.submitError'));
    } finally {
      setSubmitting(false);
    }
  };

  if (loadingSubmission) {
    return (
      <div className="flex justify-center py-12">
        <Spinner size="lg" />
      </div>
    );
  }

  if (!submission) {
    return (
      <div className="text-center text-red-600">
        {t('edu.review.submissionNotFound')}
      </div>
    );
  }

  return (
    <section
      aria-label={t('edu.review.interfaceTitle')}
      className="max-w-5xl mx-auto bg-white dark:bg-zinc-900 p-6 rounded-md shadow-md space-y-6"
    >
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
        {t('edu.review.homeworkFrom', { student: submission.studentName })}
      </h2>

      <div className="space-y-4">
        <h3 className="text-lg font-medium">{t('edu.review.submittedFiles')}</h3>
        <ul className="list-disc list-inside max-h-48 overflow-y-auto text-sm text-blue-600 dark:text-blue-400">
          {submission.files.length === 0 && <li>{t('edu.review.noFiles')}</li>}
          {submission.files.map((file, idx) => (
            <li key={idx}>
              <a href={file} target="_blank" rel="noopener noreferrer" className="underline">
                {file.split('/').pop()}
              </a>
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h3 className="text-lg font-medium">{t('edu.review.reviewHistory')}</h3>
        {loadingReviews ? (
          <Spinner size="sm" />
        ) : reviews.length === 0 ? (
          <p className="text-muted-foreground">{t('edu.review.noReviews')}</p>
        ) : (
          <ul className="space-y-3 max-h-48 overflow-y-auto text-sm">
            {reviews.map((rev) => (
              <li key={rev.id} className="border-b border-gray-300 dark:border-zinc-700 pb-2">
                <div className="flex justify-between text-muted-foreground">
                  <span>{rev.reviewerName}</span>
                  <span>{new Date(rev.reviewedAt).toLocaleString()}</span>
                </div>
                <div className="font-semibold text-yellow-500">
                  {t('edu.review.rating', { rating: rev.rating })}
                </div>
                <p className="mt-1 text-gray-800 dark:text-gray-200 whitespace-pre-wrap">
                  {rev.comment}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!submitting) handleSubmitReview();
        }}
        className="space-y-4"
        aria-label={t('edu.review.submitForm')}
      >
        <label htmlFor="rating" className="block text-sm font-medium text-gray-900 dark:text-gray-100">
          {t('edu.review.yourRating')}
        </label>
        <Select
          id="rating"
          options={[
            { label: '1 - Очень плохо', value: 1 },
            { label: '2 - Плохо', value: 2 },
            { label: '3 - Средне', value: 3 },
            { label: '4 - Хорошо', value: 4 },
            { label: '5 - Отлично', value: 5 },
          ]}
          value={rating}
          onChange={(val) => setRating(val as number)}
          aria-required
          className="max-w-xs"
          placeholder={t('edu.review.selectRating')}
        />

        <label htmlFor="comment" className="block text-sm font-medium text-gray-900 dark:text-gray-100">
          {t('edu.review.yourComment')}
        </label>
        <Textarea
          id="comment"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          required
          rows={4}
          maxLength={1500}
          placeholder={t('edu.review.commentPlaceholder')}
          aria-required
        />

        {error && <p className="text-red-600 text-sm">{error}</p>}

        <Button type="submit" variant="primary" disabled={submitting}>
          {submitting ? t('edu.review.submitting') : t('edu.review.submit')}
        </Button>
      </form>
    </section>
  );
};

export default React.memo(HomeworkReviewInterface);
