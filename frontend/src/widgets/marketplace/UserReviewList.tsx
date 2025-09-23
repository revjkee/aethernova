import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ScrollArea } from '@/components/ui/scroll-area';
import { RatingStars } from '@/components/shared/RatingStars';
import { AIReviewBadge } from '@/components/shared/AIReviewBadge';
import { Button } from '@/components/ui/button';
import { useUser } from '@/hooks/useUser';
import { formatDateTime } from '@/lib/date';
import { useInfiniteScroll } from '@/hooks/useInfiniteScroll';
import { cn } from '@/lib/utils';
import { Review } from '@/types/review';

type UserReviewListProps = {
  productId: string;
  maxVisible?: number;
  className?: string;
};

export const UserReviewList: React.FC<UserReviewListProps> = ({
  productId,
  maxVisible = 50,
  className,
}) => {
  const { user } = useUser();
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);

  const loadReviews = useCallback(async () => {
    try {
      const res = await fetch(`/api/reviews/${productId}?page=${page}`);
      const data = await res.json();
      if (data.reviews.length === 0) {
        setHasMore(false);
        return;
      }
      setReviews((prev) => [...prev, ...data.reviews]);
      setPage((p) => p + 1);
    } catch (e) {
      console.error('Ошибка загрузки отзывов', e);
      setHasMore(false);
    } finally {
      setLoading(false);
    }
  }, [productId, page]);

  useEffect(() => {
    loadReviews();
  }, []);

  const { loaderRef } = useInfiniteScroll({
    hasMore,
    onLoadMore: loadReviews,
  });

  const visibleReviews = useMemo(() => reviews.slice(0, maxVisible), [reviews, maxVisible]);

  return (
    <ScrollArea className={cn('h-full w-full', className)}>
      {loading && (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-[100px] w-full rounded-md" />
          ))}
        </div>
      )}

      {!loading && visibleReviews.length === 0 && (
        <div className="text-muted-foreground text-sm text-center mt-6">Пока нет отзывов</div>
      )}

      {visibleReviews.map((review) => (
        <Card key={review.id} className="mb-3">
          <CardHeader className="pb-1 flex flex-row items-center justify-between">
            <div className="font-medium text-sm truncate">{review.user?.name || 'Аноним'}</div>
            <div className="text-xs text-muted-foreground">{formatDateTime(review.created_at)}</div>
          </CardHeader>

          <CardContent className="text-sm text-foreground/90 space-y-1">
            <RatingStars rating={review.rating} />
            <p className="leading-relaxed">{review.comment}</p>
            {review.ai_insight && <AIReviewBadge insight={review.ai_insight} />}
          </CardContent>
        </Card>
      ))}

      {hasMore && (
        <div ref={loaderRef} className="text-center py-4">
          <Button variant="ghost" onClick={loadReviews} disabled={loading}>
            {loading ? 'Загрузка...' : 'Загрузить ещё'}
          </Button>
        </div>
      )}
    </ScrollArea>
  );
};
