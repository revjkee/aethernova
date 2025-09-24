import React, { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useMemoryMetrics } from '@/services/monitoring/metrics';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { MetricChart } from '@/shared/components/MetricChart';
import { AlertCircle } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { Tooltip } from '@/components/ui/tooltip';
import { MemoryHealthIndicator } from '@/widgets/Monitoring/indicators/MemoryHealthIndicator';

export const MemoryConsumptionChart: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const { data, loading, latestSnapshot, node } = useMemoryMetrics();

  const preparedData = useMemo(() => {
    if (!data.length) return [];
    return data.map(point => ({
      timestamp: point.timestamp,
      used: point.usedMB,
      cached: point.cachedMB,
      free: point.freeMB,
    }));
  }, [data]);

  const latest = useMemo(() => latestSnapshot, [latestSnapshot]);

  if (!hasPermission('monitoring.memory.view')) {
    return (
      <div className="p-4 text-sm text-red-500 border border-red-400 rounded-md bg-red-50 flex items-center gap-2">
        <AlertCircle size={16} />
        {t('monitoring.access_denied')}
      </div>
    );
  }

  return (
    <Card className="relative">
      <CardHeader className="flex justify-between items-center">
        <div>
          <h2 className="text-sm font-semibold">{t('monitoring.memory_usage', 'Memory Consumption')}</h2>
          <p className="text-xs text-muted-foreground">
            {node ? `${t('monitoring.node')}: ${node}` : t('monitoring.no_node_selected')}
          </p>
        </div>
        <MemoryHealthIndicator snapshot={latest} />
      </CardHeader>

      <CardContent className="pb-2">
        {loading || !preparedData.length ? (
          <Skeleton className="h-[200px] w-full rounded-md" />
        ) : (
          <MetricChart
            data={preparedData}
            title=""
            height={200}
            stacked
            keys={[
              { key: 'used', label: t('monitoring.used'), color: '#ef4444' },
              { key: 'cached', label: t('monitoring.cached'), color: '#f59e0b' },
              { key: 'free', label: t('monitoring.free'), color: '#10b981' },
            ]}
            unit="MB"
            enableZoom
            gradient
            legendPosition="bottom"
            tooltipFormatter={(value, key) =>
              `${t(`monitoring.${key}`)}: ${value.toFixed(1)} MB`
            }
          />
        )}
      </CardContent>
    </Card>
  );
};

export default MemoryConsumptionChart;
