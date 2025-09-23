import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchPeerReviews, submitPeerReview } from '@/services/api/peerReviewAPI';
import { Spinner } from '@/shared/components/Spinner';
import { Button } from '@/shared/components/Button';
import { Textarea } from '@/shared/components/Textarea';
import { Select } from '@/shared/components/Select';
import { cn } from '@/shared/utils/cn';

interface Review {
  id: string;
  reviewerId: string;
  reviewerAnonymous: boolean;
  score: number; // 1-5
  comment: string;
  timestamp: string;
}

interface Props {
  assignmentId: string;
  userId: string;
  onReviewSubmitted?: () => void;
}

const scoreOptions = [
  { label: '1 - Very Poor', value: 1 },
  { label: '2 - Poor', value: 2 },
  { label: '3 - Average', value: 3 },
  { label: '4 - Good', value: 4 },
  { label: '5 - Excellent', value: 5 },
];

const PeerReviewPanel: React.FC<Props> = ({ assignmentId, userId, onReviewSubmitted }) => {
  const { t } = useTranslation();
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [score, setScore] = useState<number | null>(null);
  const [comment, setComment] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadReviews = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchPeerReviews(assignmentId);
      setReviews(data);
    } catch {
      setReviews([]);
    } finally {
      setLoading(false);
    }
  }, [assignmentId]);

  useEffect(() => {
    loadReviews();
  }, [loadReviews]);

  const averageScore = useMemo(() => {
    if (reviews.length === 0) return 0;
    return reviews.reduce((acc, r) => acc + r.score, 0) / reviews.length;
  }, [reviews]);

  const handleSubmit = async () => {
    if (score === null || comment.trim().length === 0) {
      setError(t('peerReview.validation.required'));
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      await submitPeerReview({ assignmentId, userId, score, comment });
      setScore(null);
      setComment('');
      onReviewSubmitted && onReviewSubmitted();
      await loadReviews();
    } catch (e: any) {
      setError(e.message || t('peerReview.submitError'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section
      aria-label={t('peerReview.panelTitle')}
      className="max-w-4xl mx-auto bg-white dark:bg-zinc-900 p-6 rounded-md shadow-md space-y-6"
    >
      <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
        {t('peerReview.panelTitle')}
      </h2>

      <div className="text-sm text-muted-foreground">
        {t('peerReview.averageScore', { score: averageScore.toFixed(1), count: reviews.length })}
      </div>

      {loading ? (
        <div className="flex justify-center py-8">
          <Spinner size="lg" />
        </div>
      ) : (
        <ul className="space-y-4 max-h-64 overflow-y-auto border rounded-md p-4 bg-zinc-50 dark:bg-zinc-800">
          {reviews.length === 0 ? (
            <li className="text-muted-foreground text-center">
              {t('peerReview.noReviews')}
            </li>
          ) : (
            reviews.map(({ id, reviewerAnonymous, score, comment, timestamp }) => (
              <li
                key={id}
                className={cn(
                  'border-b border-gray-300 dark:border-zinc-700 pb-2 last:border-b-0'
                )}
              >
                <div className="flex justify-between items-center text-sm text-muted-foreground">
                  <span>
                    {reviewerAnonymous
                      ? t('peerReview.anonymous')
                      : t('peerReview.reviewer', { id: id.slice(0, 6) })}
                  </span>
                  <span>{new Date(timestamp).toLocaleDateString()}</span>
                </div>
                <div className="text-yellow-500 font-semibold">
                  {t('peerReview.score', { score })}
                </div>
                <p className="mt-1 text-gray-800 dark:text-gray-200 whitespace-pre-wrap">
                  {comment}
                </p>
              </li>
            ))
          )}
        </ul>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!submitting) handleSubmit();
        }}
        className="space-y-4"
        aria-label={t('peerReview.submitForm')}
      >
        <label htmlFor="score" className="block text-sm font-medium text-gray-900 dark:text-gray-100">
          {t('peerReview.yourScore')}
        </label>
        <Select
          id="score"
          options={scoreOptions}
          value={score}
          onChange={(val) => setScore(val as number)}
          aria-required
          className="max-w-xs"
          placeholder={t('peerReview.selectScore')}
        />

        <label htmlFor="comment" className="block text-sm font-medium text-gray-900 dark:text-gray-100">
          {t('peerReview.yourComment')}
        </label>
        <Textarea
          id="comment"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          required
          rows={4}
          maxLength={1000}
          placeholder={t('peerReview.commentPlaceholder')}
          aria-required
        />

        {error && <p className="text-red-600 text-sm">{error}</p>}

        <Button type="submit" variant="primary" disabled={submitting}>
          {submitting ? t('peerReview.submitting') : t('peerReview.submit')}
        </Button>
      </form>
    </section>
  );
};

export default React.memo(PeerReviewPanel);
