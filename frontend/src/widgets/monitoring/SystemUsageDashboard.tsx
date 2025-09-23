import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { MetricChart } from '@/shared/components/MetricChart';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { SystemMetric, useLiveSystemMetrics } from '@/services/monitoring/metrics';
import { NodeSelector } from '@/widgets/Monitoring/NodeSelector';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/shared/utils/cn';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { AlertCircle } from 'lucide-react';

const THRESHOLDS = {
  cpu: [60, 85],
  ram: [70, 90],
  disk: [75, 95],
  gpu: [50, 90],
};

const getLevelColor = (type: keyof typeof THRESHOLDS, value: number): string => {
  const [warn, crit] = THRESHOLDS[type];
  if (value >= crit) return 'text-red-500';
  if (value >= warn) return 'text-yellow-400';
  return 'text-green-500';
};

export const SystemUsageDashboard: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const { metrics, loading, nodes } = useLiveSystemMetrics(selectedNode);

  const latest = useMemo(() => {
    if (!metrics.length) return null;
    return metrics[metrics.length - 1];
  }, [metrics]);

  if (!hasPermission('monitoring.system.view')) {
    return (
      <div className="p-4 text-sm text-red-500 border border-red-400 rounded-md bg-red-50 flex items-center gap-2">
        <AlertCircle size={16} /> {t('monitoring.access_denied')}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-base font-semibold">{t('system_usage.title', 'System Resource Dashboard')}</h2>
        <NodeSelector nodes={nodes} selected={selectedNode} onChange={setSelectedNode} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {loading || !latest ? (
          Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-[180px] rounded-lg" />
          ))
        ) : (
          <>
            <UsageCard title="CPU" value={latest.cpu} type="cpu" />
            <UsageCard title="RAM" value={latest.ram} type="ram" />
            <UsageCard title="Disk" value={latest.disk} type="disk" />
            <UsageCard title="GPU" value={latest.gpu} type="gpu" />
            <UsageCard title="IO Read" value={latest.ioRead} type="disk" unit="MB/s" />
            <UsageCard title="IO Write" value={latest.ioWrite} type="disk" unit="MB/s" />
          </>
        )}
      </div>

      <MetricChart
        data={metrics}
        keys={['cpu', 'ram', 'disk', 'gpu']}
        title={t('system_usage.chart_title', 'Usage Over Time')}
        height={260}
      />
    </div>
  );
};

type UsageCardProps = {
  title: string;
  value: number;
  type: keyof typeof THRESHOLDS;
  unit?: string;
};

const UsageCard: React.FC<UsageCardProps> = ({ title, value, type, unit = '%' }) => {
  const color = getLevelColor(type, value);
  return (
    <Card>
      <CardHeader className="text-sm font-semibold flex justify-between items-center">
        <span>{title}</span>
        <Badge variant="ghost" className={cn('text-[11px]', color)}>
          {value.toFixed(1)} {unit}
        </Badge>
      </CardHeader>
      <CardContent className="pt-1">
        <div className="h-[100px] relative">
          <div
            className={cn(
              'absolute bottom-0 left-0 w-full rounded-b-md transition-all duration-500',
              type === 'cpu' ? 'bg-blue-500' :
              type === 'ram' ? 'bg-emerald-500' :
              type === 'disk' ? 'bg-purple-500' :
              'bg-yellow-400'
            )}
            style={{ height: `${Math.min(value, 100)}%` }}
          />
          <div className="absolute bottom-0 left-0 w-full text-xs text-center text-white font-bold">
            {value.toFixed(1)}{unit}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default SystemUsageDashboard;
