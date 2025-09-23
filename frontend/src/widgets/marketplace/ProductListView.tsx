import React, { useCallback, useEffect, useMemo, useRef } from 'react';
import { VirtuosoGrid } from 'react-virtuoso';
import { ProductCard } from './ProductCard';
import { Product } from '@/types/marketplace';
import { useProductStore } from '@/store/productStore';
import { FilterPanel } from './FilterPanel';
import { LoadingSpinner } from '@/components/ui/loading-spinner';
import { cn } from '@/lib/utils';
import { EmptyState } from '@/components/ui/empty-state';
import { MarketplaceHeader } from './MarketplaceHeader';

type ProductListViewProps = {
  className?: string;
};

export const ProductListView: React.FC<ProductListViewProps> = ({ className }) => {
  const {
    products,
    loading,
    filters,
    applyFilters,
    loadMore,
    hasMore,
    fetchInitialProducts,
    error,
  } = useProductStore();

  const observerRef = useRef<IntersectionObserver | null>(null);
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  const handleBuy = useCallback((product: Product) => {
    console.log('Buy requested', product.id);
    // future: dispatch to checkout flow
  }, []);

  const handleInspect = useCallback((product: Product) => {
    console.log('Inspect requested', product.id);
    // future: open drawer/modal with product details
  }, []);

  useEffect(() => {
    fetchInitialProducts();
  }, [fetchInitialProducts]);

  useEffect(() => {
    if (!hasMore || !sentinelRef.current) return;

    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !loading) {
        loadMore();
      }
    });

    observer.observe(sentinelRef.current);
    observerRef.current = observer;

    return () => observer.disconnect();
  }, [loading, loadMore, hasMore]);

  const filteredProducts = useMemo(() => {
    if (!filters || Object.keys(filters).length === 0) return products;
    return applyFilters(products);
  }, [products, filters, applyFilters]);

  return (
    <section className={cn('w-full flex flex-col gap-4', className)}>
      <MarketplaceHeader />

      <FilterPanel />

      {loading && products.length === 0 ? (
        <div className="w-full flex justify-center py-20">
          <LoadingSpinner size="xl" />
        </div>
      ) : error ? (
        <EmptyState
          title="Ошибка загрузки"
          description="Не удалось загрузить список товаров. Повторите попытку позже."
        />
      ) : filteredProducts.length === 0 ? (
        <EmptyState
          title="Нет товаров"
          description="Измените фильтры или попробуйте позже."
        />
      ) : (
        <>
          <VirtuosoGrid
            data={filteredProducts}
            totalCount={filteredProducts.length}
            itemContent={(_, product) => (
              <ProductCard
                key={product.id}
                product={product}
                onBuy={handleBuy}
                onInspect={handleInspect}
              />
            )}
            listClassName="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6"
          />
          {hasMore && (
            <div ref={sentinelRef} className="h-20 flex justify-center items-center">
              <LoadingSpinner />
            </div>
          )}
        </>
      )}
    </section>
  );
};
