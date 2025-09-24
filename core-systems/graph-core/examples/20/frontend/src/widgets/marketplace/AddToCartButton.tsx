// src/widgets/Marketplace/AddToCartButton.tsx

import React, { FC, useState, useCallback, useMemo, useEffect } from 'react';
import { ShoppingCart, Loader2, CheckCircle, LockKeyhole } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCart } from '@/shared/hooks/useCart';
import { useTelemetry } from '@/shared/hooks/useTelemetry';
import { useAuth } from '@/shared/hooks/useAuth';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/shared/utils/classNames';
import { ProductType } from '@/shared/types/product';
import { formatCurrency } from '@/shared/utils/formatters';

interface AddToCartButtonProps {
  productId: string;
  price: number;
  currency: string;
  type: ProductType;
  isAvailable: boolean;
  variant?: 'default' | 'full' | 'compact';
  className?: string;
}

export const AddToCartButton: FC<AddToCartButtonProps> = ({
  productId,
  price,
  currency,
  type,
  isAvailable,
  variant = 'default',
  className,
}) => {
  const [loading, setLoading] = useState(false);
  const [added, setAdded] = useState(false);
  const { addItem } = useCart();
  const telemetry = useTelemetry();
  const { isAuthenticated } = useAuth();
  const { toast } = useToast();

  const isRestricted = useMemo(() => !isAvailable || type === 'access', [isAvailable, type]);

  const handleAdd = useCallback(async () => {
    if (loading || added || isRestricted) return;

    if (!isAuthenticated) {
      toast({
        title: 'Вход не выполнен',
        description: 'Авторизуйтесь, чтобы добавлять товары в корзину.',
        variant: 'warning',
      });
      return;
    }

    try {
      setLoading(true);
      await addItem({
        id: productId,
        price,
        currency,
        type,
      });

      telemetry.send({
        type: 'add_to_cart',
        payload: {
          productId,
          price,
          currency,
          type,
        },
      });

      setAdded(true);
      toast({
        title: 'Добавлено в корзину',
        description: 'Товар успешно добавлен',
      });
    } catch (err: any) {
      toast({
        title: 'Ошибка добавления',
        description: err.message || 'Произошла ошибка при добавлении в корзину',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  }, [productId, price, currency, type, loading, added, isAuthenticated, isRestricted, addItem, telemetry, toast]);

  useEffect(() => {
    let timeout: NodeJS.Timeout;
    if (added) {
      timeout = setTimeout(() => setAdded(false), 3000);
    }
    return () => clearTimeout(timeout);
  }, [added]);

  const getButtonContent = () => {
    if (loading) {
      return <Loader2 className="animate-spin h-4 w-4" />;
    }
    if (added) {
      return <CheckCircle className="h-4 w-4 text-green-600" />;
    }
    if (isRestricted) {
      return <LockKeyhole className="h-4 w-4 text-muted" />;
    }
    return <ShoppingCart className="h-4 w-4" />;
  };

  const getLabel = () => {
    if (added) return 'Добавлено';
    if (isRestricted) return 'Недоступно';
    return `В корзину (${formatCurrency(price, currency)})`;
  };

  return (
    <Button
      onClick={handleAdd}
      disabled={loading || added || isRestricted}
      variant={variant === 'full' ? 'default' : 'secondary'}
      className={cn(
        'flex items-center gap-2 rounded-md font-medium transition-all',
        {
          'w-full justify-center': variant === 'full',
          'px-3 py-1.5 text-sm': variant === 'compact',
          'opacity-60 cursor-not-allowed': isRestricted,
        },
        className
      )}
    >
      {getButtonContent()}
      {variant !== 'compact' && <span>{getLabel()}</span>}
    </Button>
  );
};
