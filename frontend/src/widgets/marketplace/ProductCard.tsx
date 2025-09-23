import React, { memo, useMemo } from 'react';
import { Card, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { ProductType, ProductMeta, ProductCardProps } from '@/types/marketplace';
import { Skeleton } from '@/components/ui/skeleton';
import { formatPrice, formatSupply } from '@/utils/formatter';
import { useTokenIcon } from '@/hooks/useTokenIcon';
import { cn } from '@/lib/utils';
import { Icons } from '@/components/icons';
import { ProductMediaRenderer } from './ProductMediaRenderer';
import { ProductStatusChip } from './ProductStatusChip';
import { ProductTagDisplay } from './ProductTagDisplay';
import { motion } from 'framer-motion';

const ProductCard = memo(
  ({
    product,
    onBuy,
    onInspect,
    loading = false,
    disabled = false,
    showStatus = true,
  }: ProductCardProps) => {
    const {
      id,
      name,
      price,
      currency,
      type,
      imageUrl,
      availability,
      status,
      tags,
      supply,
      metadata,
    } = product;

    const formattedPrice = useMemo(() => formatPrice(price, currency), [price, currency]);
    const tokenIcon = useTokenIcon(currency);

    if (loading) {
      return (
        <Card className="w-full h-[320px] p-4 flex flex-col gap-4 animate-pulse">
          <Skeleton className="h-[160px] w-full rounded-xl" />
          <Skeleton className="h-6 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-8 w-1/3 mt-auto" />
        </Card>
      );
    }

    return (
      <motion.div
        layout
        initial={{ opacity: 0.8, scale: 0.98 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        transition={{ duration: 0.2 }}
      >
        <Card
          className={cn(
            'relative group hover:shadow-xl transition-shadow duration-300 flex flex-col justify-between p-4 h-[360px]',
            disabled && 'opacity-50 pointer-events-none'
          )}
        >
          <div>
            <ProductMediaRenderer url={imageUrl} type={type} name={name} />
            <div className="mt-3 flex items-center justify-between gap-2">
              <div className="text-lg font-semibold truncate">{name}</div>
              <div className="flex items-center gap-1">
                <img src={tokenIcon} alt={currency} className="w-4 h-4" />
                <span className="text-sm font-medium">{formattedPrice}</span>
              </div>
            </div>

            {supply !== undefined && (
              <div className="text-xs text-muted-foreground">
                {formatSupply(supply)}
              </div>
            )}

            {tags?.length > 0 && <ProductTagDisplay tags={tags} />}
          </div>

          <div className="mt-3 flex items-center justify-between">
            <Button size="sm" variant="outline" onClick={() => onInspect?.(product)}>
              <Icons.search className="w-4 h-4 mr-1" />
              Обзор
            </Button>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button size="sm" onClick={() => onBuy?.(product)} disabled={disabled}>
                  <Icons.shoppingCart className="w-4 h-4 mr-1" />
                  Купить
                </Button>
              </TooltipTrigger>
              <TooltipContent>Оплатить через AI/TON</TooltipContent>
            </Tooltip>
          </div>

          {showStatus && status && (
            <div className="absolute top-3 right-3">
              <ProductStatusChip status={status} />
            </div>
          )}
        </Card>
      </motion.div>
    );
  }
);

ProductCard.displayName = 'ProductCard';

export default ProductCard;
