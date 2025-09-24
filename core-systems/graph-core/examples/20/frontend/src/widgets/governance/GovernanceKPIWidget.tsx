// src/widgets/Governance/GovernanceKPIWidget.tsx

import React, { useMemo } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { useGovernanceKPI } from '@/hooks/governance/useGovernanceKPI';
import { Skeleton } from '@/components/ui/skeleton';
import { KPIIndicator } from '@/components/ui/kpi/KPIIndicator';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { cn } from '@/lib/utils';
import { GovernanceKPI } from '@/types/governance';
import { TrendArrow } from '@/components/ui/indicators/TrendArrow';
import { ImpactBadge } from '@/components/ui/indicators/ImpactBadge';
import { TokenIcon } from '@/components/ui/icons/TokenIcon';
import { ShieldCheckIcon, PulseIcon, UserIcon, StarIcon } from 'lucide-react';

export const GovernanceKPIWidget: React.FC = () => {
  const { data, loading } = useGovernanceKPI();

  const metrics: GovernanceKPI[] = useMemo(() => data?.metrics || [], [data]);

  return (
    <Card className="w-full bg-background/90 border border-border/40 shadow-xl rounded-xl">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Метрики управления DAO</h3>
          <ImpactBadge level={data?.impactLevel ?? 'neutral'} />
        </div>
        <p className="text-muted-foreground text-sm mt-1">
          Показатели эффективности, доверия, безопасности и роста активности
        </p>
      </CardHeader>

      <CardContent className="grid grid-cols-2 xl:grid-cols-4 gap-4 pt-2">
        {loading || !metrics.length ? (
          <Skeleton className="h-[120px] col-span-4 rounded-lg" />
        ) : (
          <>
            <KPIIndicator
              title="Активность DAO"
              icon={<PulseIcon className="w-5 h-5 text-primary" />}
              value={metrics[0].value}
              unit="действий"
              trend={metrics[0].trend}
              hint="Общее число транзакций и изменений в DAO"
            />
            <KPIIndicator
              title="Влияние делегатов"
              icon={<UserIcon className="w-5 h-5 text-primary" />}
              value={metrics[1].value}
              unit="голосов"
              trend={metrics[1].trend}
              hint="Суммарный вес голосов делегатов"
            />
            <KPIIndicator
              title="Ценность предложений"
              icon={<TokenIcon className="w-5 h-5 text-primary" />}
              value={metrics[2].value}
              unit="$NEURO"
              trend={metrics[2].trend}
              hint="Финансовая значимость решений"
            />
            <KPIIndicator
              title="Этическое соответствие"
              icon={<ShieldCheckIcon className="w-5 h-5 text-primary" />}
              value={metrics[3].value}
              unit="%"
              trend={metrics[3].trend}
              hint="Доля предложений, прошедших аудит этики"
            />

            <div className="col-span-2 xl:col-span-4 bg-muted/30 rounded-lg p-3 shadow-inner">
              <ResponsiveContainer width="100%" height={160}>
                <AreaChart data={metrics[4]?.history ?? []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="label" />
                  <YAxis />
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke="#4ade80"
                    fill="rgba(74, 222, 128, 0.3)"
                  />
                </AreaChart>
              </ResponsiveContainer>
              <div className="text-xs text-muted-foreground text-center mt-1">
                Граф роста доверия и устойчивости к атакам
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};

export default GovernanceKPIWidget;
