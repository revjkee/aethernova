import React, { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { useCPULoadMetrics } from '@/services/monitoring/metrics';
import { MetricGridChart } from '@/shared/components/MetricGridChart';
import { Skeleton } from '@/components/ui/skeleton';
import { NodeHealthIndicator } from '@/widgets/Monitoring/indicators/NodeHealthIndicator';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { AlertCircle } from 'lucide-react';

export const CPULoadDistribution: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const { data, loading, metadata } = useCPULoadMetrics();

  const formattedData = useMemo(() => {
    return data.map(entry => ({
      node: entry.node,
      avgLoad: entry.avgLoad,
      coreDetails: entry.coreLoads, // { core0: %, core1: %, ... }
    }));
  }, [data]);

  if (!hasPermission('monitoring.cpu.view')) {
    return (
      <div className="p-4 text-sm text-red-500 border border-red-400 rounded-md bg-red-50 flex items-center gap-2">
        <AlertCircle size={16} />
        {t('monitoring.access_denied')}
      </div>
    );
  }

  return (
    <Card className="w-full">
      <CardHeader className="flex justify-between items-center">
        <div>
          <h2 className="text-sm font-semibold">{t('monitoring.cpu_distribution', 'CPU Load Distribution')}</h2>
          <p className="text-xs text-muted-foreground">
            {t('monitoring.node_count', { count: formattedData.length })}
          </p>
        </div>
      </CardHeader>

      <CardContent className="pb-2">
        {loading ? (
          <Skeleton className="h-[300px] w-full rounded-md" />
        ) : (
          <MetricGridChart
            data={formattedData}
            keys={['avgLoad']}
            labels={{ avgLoad: t('monitoring.avg_cpu_load', 'Avg Load') }}
            unit="%"
            valueFormatter={(val) => `${val.toFixed(1)}%`}
            thresholdColor={(val) =>
              val > 90 ? '#dc2626' : val > 70 ? '#f59e0b' : '#10b981'
            }
            tooltipFormatter={({ node, avgLoad }) =>
              `${t('monitoring.node')}: ${node}\n${t('monitoring.load')}: ${avgLoad.toFixed(2)}%`
            }
            legend={{
              critical: '> 90%',
              warning: '70–90%',
              normal: '< 70%',
            }}
            showHealthIcons
            nodeMetadata={metadata}
            maxColumns={4}
            minHeight={320}
          />
        )}
      </CardContent>
    </Card>
  );
};

export default CPULoadDistribution;
