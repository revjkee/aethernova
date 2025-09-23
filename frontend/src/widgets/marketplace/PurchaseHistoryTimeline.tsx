import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FixedSizeList as VirtualList } from 'react-window';
import { format } from 'date-fns';
import { cn } from '@/shared/utils/classNames';
import { Spinner } from '@/shared/components/Spinner';
import { ErrorBoundary } from '@/shared/components/ErrorBoundary';
import { FilterPanel } from '@/widgets/Marketplace/components/FilterPanel';
import { TimelineItem } from '@/widgets/Marketplace/components/TimelineItem';
import { fetchPurchaseHistory } from '@/services/api/purchaseAPI';
import { PurchaseRecord, PurchaseStatus } from '@/shared/types/marketplace';
import { GroupedTimeline } from '@/shared/components/GroupedTimeline';
import { useTheme } from '@/shared/hooks/useTheme';
import { Button } from '@/shared/components/Button';

interface Props {
  userId: string;
  limit?: number;
  showControls?: boolean;
}

const PurchaseHistoryTimeline: React.FC<Props> = ({ userId, limit = 100, showControls = true }) => {
  const { theme } = useTheme();
  const [filters, setFilters] = useState<{ status?: PurchaseStatus; dateFrom?: Date; dateTo?: Date }>({});
  const [selectedYear, setSelectedYear] = useState<number | null>(null);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['purchaseHistory', userId, filters],
    queryFn: () => fetchPurchaseHistory(userId, filters),
    refetchOnWindowFocus: false,
    staleTime: 1000 * 60 * 5,
  });

  const groupedData = useMemo(() => {
    if (!data) return {};
    return data.reduce((acc, item) => {
      const year = new Date(item.date).getFullYear();
      if (!acc[year]) acc[year] = [];
      acc[year].push(item);
      return acc;
    }, {} as Record<number, PurchaseRecord[]>);
  }, [data]);

  const availableYears = useMemo(() => Object.keys(groupedData).map(Number).sort((a, b) => b - a), [groupedData]);

  const renderRow = useCallback(
    ({ index, style }) => {
      const year = selectedYear ?? availableYears[0];
      const record = groupedData[year]?.[index];
      if (!record) return null;
      return (
        <div style={style}>
          <TimelineItem record={record} />
        </div>
      );
    },
    [groupedData, selectedYear, availableYears]
  );

  useEffect(() => {
    if (availableYears.length > 0 && selectedYear === null) {
      setSelectedYear(availableYears[0]);
    }
  }, [availableYears, selectedYear]);

  return (
    <ErrorBoundary fallback="Ошибка загрузки истории покупок.">
      <div className={cn('flex flex-col gap-4 w-full', theme === 'dark' ? 'bg-gray-900 text-white' : 'bg-white text-black')}>
        {showControls && (
          <div className="flex justify-between items-center px-4 pt-2">
            <FilterPanel
              filters={filters}
              onChange={setFilters}
              statuses={['pending', 'completed', 'cancelled']}
            />
            <Button variant="ghost" onClick={() => refetch()}>
              Обновить
            </Button>
          </div>
        )}

        {isLoading ? (
          <div className="flex justify-center items-center h-64">
            <Spinner size="lg" />
          </div>
        ) : isError ? (
          <div className="text-center text-red-600">Не удалось загрузить данные</div>
        ) : (
          <div className="flex flex-col gap-2 px-4 pb-4">
            {availableYears.length > 1 && (
              <div className="flex flex-wrap gap-2">
                {availableYears.map((year) => (
                  <Button
                    key={year}
                    variant={year === selectedYear ? 'primary' : 'outline'}
                    size="sm"
                    onClick={() => setSelectedYear(year)}
                  >
                    {year}
                  </Button>
                ))}
              </div>
            )}

            <GroupedTimeline year={selectedYear ?? availableYears[0]}>
              <VirtualList
                height={500}
                itemCount={groupedData[selectedYear ?? availableYears[0]]?.length || 0}
                itemSize={72}
                width="100%"
              >
                {renderRow}
              </VirtualList>
            </GroupedTimeline>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
};

export default React.memo(PurchaseHistoryTimeline);
