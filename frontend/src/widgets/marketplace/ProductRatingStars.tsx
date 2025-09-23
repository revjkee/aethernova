// src/widgets/Marketplace/ProductRatingStars.tsx

import React, { FC, useState, useEffect, useMemo, useCallback } from 'react';
import { Star, StarHalf, StarOff } from 'lucide-react';
import { cn } from '@/shared/utils/classNames';
import { useTelemetry } from '@/shared/hooks/useTelemetry';
import { useAuth } from '@/shared/hooks/useAuth';
import { useToast } from '@/components/ui/toast';

export type RatingSize = 'sm' | 'md' | 'lg';

interface ProductRatingStarsProps {
  productId: string;
  rating: number; // 0 - 5
  votesCount: number;
  interactive?: boolean;
  onRate?: (newRating: number) => Promise<void>;
  size?: RatingSize;
  className?: string;
}

const sizeMap = {
  sm: 16,
  md: 20,
  lg: 28,
};

export const ProductRatingStars: FC<ProductRatingStarsProps> = ({
  productId,
  rating,
  votesCount,
  interactive = false,
  onRate,
  size = 'md',
  className,
}) => {
  const [hovered, setHovered] = useState<number | null>(null);
  const [currentRating, setCurrentRating] = useState(rating);
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  const telemetry = useTelemetry();
  const { isAuthenticated } = useAuth();
  const { toast } = useToast();

  const displayRating = useMemo(() => hovered ?? currentRating, [hovered, currentRating]);
  const iconSize = sizeMap[size];

  useEffect(() => {
    setCurrentRating(rating);
  }, [rating]);

  const handleClick = useCallback(
    async (index: number) => {
      if (!interactive || submitted || loading) return;

      const selectedRating = index + 1;

      if (!isAuthenticated) {
        toast({
          title: 'Авторизация',
          description: 'Пожалуйста, войдите, чтобы оставить отзыв.',
          variant: 'warning',
        });
        return;
      }

      try {
        setLoading(true);
        await onRate?.(selectedRating);
        setCurrentRating(selectedRating);
        setSubmitted(true);
        telemetry.send({
          type: 'rate_product',
          payload: {
            productId,
            rating: selectedRating,
          },
        });

        toast({
          title: 'Спасибо за оценку',
          description: `Вы поставили ${selectedRating} звезд.`,
        });
      } catch (e: any) {
        toast({
          title: 'Ошибка',
          description: e.message || 'Не удалось отправить вашу оценку.',
          variant: 'destructive',
        });
      } finally {
        setLoading(false);
      }
    },
    [interactive, submitted, loading, onRate, telemetry, toast, productId, isAuthenticated]
  );

  const renderStar = (index: number) => {
    const value = index + 1;
    const full = displayRating >= value;
    const half = displayRating >= value - 0.5 && displayRating < value;

    let Icon = StarOff;
    if (full) Icon = Star;
    else if (half) Icon = StarHalf;

    const color =
      full || half ? 'text-yellow-400' : 'text-muted-foreground opacity-40';

    return (
      <div
        key={index}
        onMouseEnter={() => interactive && setHovered(value)}
        onMouseLeave={() => interactive && setHovered(null)}
        onClick={() => handleClick(index)}
        className={cn(
          'transition-all cursor-pointer',
          interactive && !submitted && 'hover:scale-110 active:scale-95'
        )}
      >
        <Icon size={iconSize} className={color} />
      </div>
    );
  };

  return (
    <div
      className={cn(
        'inline-flex items-center gap-1',
        interactive && 'select-none',
        className
      )}
    >
      {[0, 1, 2, 3, 4].map(renderStar)}

      <span className="ml-2 text-sm text-muted-foreground">
        {displayRating.toFixed(1)} / 5
        {votesCount > 0 && <span className="ml-1">({votesCount})</span>}
      </span>
    </div>
  );
};
