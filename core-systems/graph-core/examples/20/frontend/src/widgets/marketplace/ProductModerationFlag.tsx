// src/widgets/Marketplace/ProductModerationFlag.tsx

import React, { FC, useMemo, useCallback, useState } from 'react';
import {
  Flag,
  CheckCircle,
  AlertTriangle,
  ShieldCheck,
  Hourglass,
  XCircle,
  Loader2,
} from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/shared/utils/classNames';
import { useModeration } from '@/shared/hooks/useModeration';
import { useTelemetry } from '@/shared/hooks/useTelemetry';
import { useToast } from '@/components/ui/toast';
import { updateModerationStatus } from '@/services/moderation';

type ModerationStatus = 'pending' | 'approved' | 'rejected' | 'flagged';

interface ProductModerationFlagProps {
  productId: string;
  status: ModerationStatus;
  editable?: boolean;
  className?: string;
}

export const ProductModerationFlag: FC<ProductModerationFlagProps> = ({
  productId,
  status,
  editable = false,
  className,
}) => {
  const { isModerator } = useModeration();
  const telemetry = useTelemetry();
  const { toast } = useToast();

  const [currentStatus, setCurrentStatus] = useState<ModerationStatus>(status);
  const [loading, setLoading] = useState(false);

  const colorClass = useMemo(() => {
    switch (currentStatus) {
      case 'approved':
        return 'text-green-500';
      case 'rejected':
        return 'text-destructive';
      case 'flagged':
        return 'text-yellow-500';
      case 'pending':
        return 'text-muted-foreground';
      default:
        return 'text-muted';
    }
  }, [currentStatus]);

  const icon = useMemo(() => {
    if (loading) return <Loader2 size={18} className="animate-spin" />;
    switch (currentStatus) {
      case 'approved':
        return <CheckCircle size={18} />;
      case 'rejected':
        return <XCircle size={18} />;
      case 'flagged':
        return <AlertTriangle size={18} />;
      case 'pending':
        return <Hourglass size={18} />;
      default:
        return <Flag size={18} />;
    }
  }, [currentStatus, loading]);

  const label = useMemo(() => {
    switch (currentStatus) {
      case 'approved':
        return 'Одобрено';
      case 'rejected':
        return 'Отклонено';
      case 'flagged':
        return 'Помечено';
      case 'pending':
        return 'На модерации';
      default:
        return 'Неизвестно';
    }
  }, [currentStatus]);

  const handleCycleStatus = useCallback(async () => {
    if (!editable || !isModerator || loading) return;

    const nextStatus: ModerationStatus =
      currentStatus === 'pending'
        ? 'flagged'
        : currentStatus === 'flagged'
        ? 'rejected'
        : currentStatus === 'rejected'
        ? 'approved'
        : 'pending';

    setLoading(true);

    try {
      await updateModerationStatus(productId, nextStatus);
      setCurrentStatus(nextStatus);

      telemetry.send({
        type: 'moderation_status_changed',
        payload: {
          productId,
          newStatus: nextStatus,
        },
      });

      toast({
        title: `Статус обновлён`,
        description: `Текущий статус: ${label}`,
      });
    } catch (e: any) {
      toast({
        title: 'Ошибка обновления статуса',
        description: e.message || 'Попробуйте позже.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  }, [currentStatus, editable, isModerator, loading, productId, label, telemetry, toast]);

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div
          className={cn(
            'flex items-center justify-center p-1 rounded-full border border-muted transition-all',
            editable && isModerator && 'hover:bg-accent cursor-pointer',
            colorClass,
            className
          )}
          onClick={handleCycleStatus}
        >
          {icon}
        </div>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
};
