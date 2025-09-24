import React, { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useWebSocketSubscription } from '@/hooks/useWebSocketSubscription';
import { ProductAvailability, ProductStatus } from '@/types/marketplace';
import { AlertTriangle, CheckCircle, Clock, XCircle, Loader } from 'lucide-react';
import { cn } from '@/lib/utils';

type ProductAvailabilityStatusProps = {
  productId: string;
  fallbackStatus?: ProductAvailability;
  compact?: boolean;
};

export const ProductAvailabilityStatus: React.FC<ProductAvailabilityStatusProps> = ({
  productId,
  fallbackStatus = 'unknown',
  compact = false,
}) => {
  const [status, setStatus] = useState<ProductAvailability>(fallbackStatus);
  const [loading, setLoading] = useState(true);

  const { connect, data, error } = useWebSocketSubscription<ProductStatus>({
    topic: `product/${productId}/availability`,
  });

  useEffect(() => {
    connect();
  }, [productId]);

  useEffect(() => {
    if (data?.status) {
      setStatus(data.status);
      setLoading(false);
    } else if (error) {
      setStatus('unknown');
      setLoading(false);
    }
  }, [data, error]);

  const getStatusConfig = (): { icon: JSX.Element; label: string; variant: 'default' | 'destructive' | 'warning' | 'success'; color?: string } => {
    switch (status) {
      case 'in_stock':
        return {
          icon: <CheckCircle className="w-4 h-4 text-green-600" />,
          label: 'В наличии',
          variant: 'success',
        };
      case 'out_of_stock':
        return {
          icon: <XCircle className="w-4 h-4 text-red-600" />,
          label: 'Нет в наличии',
          variant: 'destructive',
        };
      case 'preorder':
        return {
          icon: <Clock className="w-4 h-4 text-yellow-600" />,
          label: 'Предзаказ',
          variant: 'warning',
        };
      case 'limited':
        return {
          icon: <AlertTriangle className="w-4 h-4 text-orange-600" />,
          label: 'Ограничено',
          variant: 'warning',
        };
      case 'unknown':
      default:
        return {
          icon: <Loader className="w-4 h-4 animate-spin text-muted-foreground" />,
          label: 'Загрузка...',
          variant: 'default',
        };
    }
  };

  const { icon, label, variant } = getStatusConfig();

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant={variant}
          className={cn(
            'inline-flex items-center gap-1 px-2 py-1 text-xs rounded-md border',
            compact && 'text-[10px] px-1.5 py-0.5'
          )}
        >
          {icon}
          {!compact && <span>{label}</span>}
        </Badge>
      </TooltipTrigger>
      <TooltipContent side="top">
        <div className="text-sm font-medium text-muted-foreground">
          Статус обновляется в реальном времени
        </div>
      </TooltipContent>
    </Tooltip>
  );
};
