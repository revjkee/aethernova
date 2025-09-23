import React, { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { ResponsiveLine } from '@nivo/line';
import { useNetworkIOMetrics } from '@/services/monitoring/network';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { Skeleton } from '@/components/ui/skeleton';
import { formatBytes } from '@/shared/utils/format';
import { AlertCircle } from 'lucide-react';

export const NetworkIOGraph: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const { data, loading } = useNetworkIOMetrics();

  const formattedData = useMemo(() => {
    const tx: any[] = [];
    const rx: any[] = [];

    data?.forEach(point => {
      tx.push({ x: point.timestamp, y: point.txBytes });
      rx.push({ x: point.timestamp, y: point.rxBytes });
    });

    return [
      { id: t('monitoring.network_tx', 'TX (Sent)'), color: '#3b82f6', data: tx },
      { id: t('monitoring.network_rx', 'RX (Received)'), color: '#10b981', data: rx }
    ];
  }, [data, t]);

  if (!hasPermission('monitoring.network.view')) {
    return (
      <div className="p-4 text-sm text-red-500 border border-red-400 rounded-md bg-red-50 flex items-center gap-2">
        <AlertCircle size={16} />
        {t('monitoring.access_denied', 'Access denied to network metrics')}
      </div>
    );
  }

  return (
    <Card className="w-full">
      <CardHeader className="flex justify-between items-center">
        <div>
          <h2 className="text-sm font-semibold">{t('monitoring.network_io_graph', 'Network I/O Graph')}</h2>
          <p className="text-xs text-muted-foreground">{t('monitoring.graph_live', 'Live updated, 1 min window')}</p>
        </div>
      </CardHeader>

      <CardContent className="h-[340px]">
        {loading ? (
          <Skeleton className="h-full w-full rounded-md" />
        ) : (
          <ResponsiveLine
            data={formattedData}
            margin={{ top: 20, right: 30, bottom: 50, left: 60 }}
            xScale={{ type: 'time', format: '%Y-%m-%dT%H:%M:%S', precision: 'second' }}
            xFormat="time:%H:%M:%S"
            yScale={{ type: 'linear', stacked: false, min: 'auto', max: 'auto' }}
            axisBottom={{
              format: '%H:%M:%S',
              tickValues: 'every 30 seconds',
              legend: t('monitoring.timestamp', 'Timestamp'),
              legendOffset: 36,
              legendPosition: 'middle',
            }}
            axisLeft={{
              format: value => formatBytes(value),
              legend: t('monitoring.network_traffic', 'Network Traffic'),
              legendOffset: -50,
              legendPosition: 'middle',
            }}
            colors={d => d.color}
            pointSize={4}
            pointBorderWidth={1}
            enableGridX={true}
            enableGridY={true}
            useMesh={true}
            legends={[
              {
                anchor: 'top-left',
                direction: 'column',
                justify: false,
                translateX: 0,
                translateY: -10,
                itemWidth: 120,
                itemHeight: 18,
                symbolSize: 10,
                symbolShape: 'circle',
              }
            ]}
            theme={{
              axis: {
                ticks: {
                  text: {
                    fontSize: 11,
                    fill: '#6b7280',
                  }
                }
              }
            }}
            animate={true}
            motionConfig="wobbly"
          />
        )}
      </CardContent>
    </Card>
  );
};

export default NetworkIOGraph;
