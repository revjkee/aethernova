// src/widgets/Governance/TreasuryImpactGraph.tsx

import React, { useMemo } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { useTreasuryImpactData } from '@/hooks/governance/useTreasuryImpactData';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { TokenIcon } from '@/components/ui/icons/TokenIcon';
import { formatToken } from '@/lib/formatters';
import { cn } from '@/lib/utils';

const impactColors: Record<string, string> = {
  funding: '#4ade80',
  burn: '#f87171',
  staking: '#60a5fa',
  redistribution: '#fbbf24',
  inflation: '#a78bfa',
};

const impactLabels: Record<string, string> = {
  funding: 'Финансирование',
  burn: 'Сжигание',
  staking: 'Стейкинг',
  redistribution: 'Распределение',
  inflation: 'Инфляция',
};

const GraphLegend = ({ keys }: { keys: string[] }) => (
  <div className="flex flex-wrap gap-3 pt-2 px-1">
    {keys.map((key) => (
      <Badge key={key} style={{ backgroundColor: impactColors[key] }} className="text-xs">
        {impactLabels[key] || key}
      </Badge>
    ))}
  </div>
);

export const TreasuryImpactGraph: React.FC = () => {
  const { data, loading } = useTreasuryImpactData();

  const activeKeys = useMemo(() => {
    if (!data?.history?.length) return [];
    return Object.keys(data.history[0]).filter((k) => k !== 'timestamp');
  }, [data]);

  return (
    <Card className="w-full bg-background/90 border border-border/40 shadow-xl rounded-xl">
      <CardHeader className="pb-1">
        <div className="flex justify-between items-center">
          <div>
            <h3 className="text-lg font-semibold leading-snug">Влияние на казну и токеномику</h3>
            <p className="text-sm text-muted-foreground">
              Историческое влияние решений DAO на ключевые финансовые показатели
            </p>
          </div>
          <TokenIcon className="w-6 h-6 text-primary/80" />
        </div>
      </CardHeader>

      <CardContent className="pt-3">
        {loading || !data?.history?.length ? (
          <Skeleton className="h-[220px] w-full rounded-md" />
        ) : (
          <div className="w-full h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data.history}>
                <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.2} />
                <XAxis dataKey="timestamp" tick={{ fontSize: 12 }} />
                <YAxis tickFormatter={(val) => `${val} NEURO`} />
                <Tooltip
                  formatter={(value: any, name: string) => [`${formatToken(value)} $NEURO`, impactLabels[name] || name]}
                  labelFormatter={(label) => `Дата: ${label}`}
                />
                <Legend />
                {activeKeys.map((key) => (
                  <Line
                    key={key}
                    type="monotone"
                    dataKey={key}
                    stroke={impactColors[key] || '#8884d8'}
                    strokeWidth={2}
                    dot={false}
                    name={impactLabels[key] || key}
                  />
                ))}
                <ReferenceLine y={0} stroke="#ccc" strokeDasharray="3 3" />
              </LineChart>
            </ResponsiveContainer>
            <GraphLegend keys={activeKeys} />
            <div className="text-xs text-muted-foreground text-right mt-2">
              Источник данных: контракт казны DAO + AI-анализ
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default TreasuryImpactGraph;
