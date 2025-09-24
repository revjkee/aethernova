// src/widgets/Marketplace/ProductVisibilityToggle.tsx

import React, { FC, useState, useCallback, useEffect } from 'react';
import { Eye, EyeOff, Lock, Loader2, AlertTriangle } from 'lucide-react';
import { Switch } from '@/components/ui/switch';
import { useTelemetry } from '@/shared/hooks/useTelemetry';
import { useToast } from '@/components/ui/toast';
import { cn } from '@/shared/utils/classNames';
import { VisibilityStatus } from '@/shared/types/product';
import { updateProductVisibility } from '@/services/products';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

interface ProductVisibilityToggleProps {
  productId: string;
  initialStatus: VisibilityStatus; // 'visible' | 'hidden' | 'locked'
  className?: string;
}

export const ProductVisibilityToggle: FC<ProductVisibilityToggleProps> = ({
  productId,
  initialStatus,
  className,
}) => {
  const [status, setStatus] = useState<VisibilityStatus>(initialStatus);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);

  const telemetry = useTelemetry();
  const { toast } = useToast();

  const isVisible = status === 'visible';
  const isLocked = status === 'locked';

  const handleToggle = useCallback(async () => {
    if (loading || isLocked) return;

    const newStatus: VisibilityStatus = isVisible ? 'hidden' : 'visible';

    setLoading(true);
    setFailed(false);
    setStatus(newStatus); // оптимистичный UI

    try {
      await updateProductVisibility(productId, newStatus);

      telemetry.send({
        type: 'visibility_toggle',
        payload: {
          productId,
          newStatus,
        },
      });

      toast({
        title: `Статус обновлён`,
        description:
          newStatus === 'visible'
            ? 'Продукт опубликован'
            : 'Продукт скрыт из витрины',
      });
    } catch (error: any) {
      setFailed(true);
      setStatus(isVisible ? 'visible' : 'hidden'); // rollback
      toast({
        title: 'Ошибка',
        description:
          error?.message || 'Не удалось изменить видимость продукта.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  }, [productId, isVisible, loading, isLocked, telemetry, toast]);

  useEffect(() => {
    setStatus(initialStatus);
  }, [initialStatus]);

  const renderIcon = () => {
    if (loading) return <Loader2 size={16} className="animate-spin text-muted" />;
    if (failed) return <AlertTriangle size={16} className="text-destructive" />;
    if (isLocked) return <Lock size={16} className="text-muted" />;
    return isVisible ? (
      <Eye size={16} className="text-green-500" />
    ) : (
      <EyeOff size={16} className="text-yellow-500" />
    );
  };

  const tooltipLabel = () => {
    if (isLocked) return 'Продукт заблокирован';
    if (failed) return 'Ошибка при изменении статуса';
    return isVisible ? 'Скрыть с витрины' : 'Опубликовать';
  };

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="cursor-pointer" onClick={handleToggle}>
            {renderIcon()}
          </div>
        </TooltipTrigger>
        <TooltipContent>{tooltipLabel()}</TooltipContent>
      </Tooltip>

      <Switch
        checked={isVisible}
        disabled={loading || isLocked}
        onCheckedChange={handleToggle}
        className={cn({
          'opacity-50 cursor-not-allowed': isLocked,
        })}
      />
    </div>
  );
};
