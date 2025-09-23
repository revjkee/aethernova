// src/widgets/Governance/DelegateActivityChart.tsx

import React, { useMemo, useState } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
  Brush,
  ReferenceLine,
  AreaChart,
  Area,
} from 'recharts';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Select, SelectItem } from '@/components/ui/select';
import { useDelegateActivity } from '@/hooks/governance/useDelegateActivity';
import { cn } from '@/lib/utils';

type ActivityPoint = {
  timestamp: number; // unix
  activeVotes: number;
  proposalsSubmitted: number;
  actionsExecuted: number;
  trustScoreAvg: number; // 0–100
};

const TIME_RANGES = [
  { label: '7 дней', value: '7d' },
  { label: '30 дней', value: '30d' },
  { label: '90 дней', value: '90d' },
];

export const DelegateActivityChart: React.FC = () => {
  const [range, setRange] = useState<'7d' | '30d' | '90d'>('30d');
  const { data, loading } = useDelegateActivity(range);

  const chartData: ActivityPoint[] = useMemo(() => {
    if (!data) return [];
    return data.map((point: any) => ({
      timestamp: point.timestamp,
      activeVotes: point.activeVotes,
      proposalsSubmitted: point.proposalsSubmitted,
      actionsExecuted: point.actionsExecuted,
      trustScoreAvg: point.trustScoreAvg,
    }));
  }, [data]);

  return (
    <Card className="bg-card/60 border border-border/30 shadow-sm backdrop-blur-sm">
      <CardHeader className="pb-2 flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
        <div>
          <h3 className="text-lg font-semibold">Активность делегатов</h3>
          <p className="text-muted-foreground text-sm">
            Динамика участия делегатов по времени
          </p>
        </div>
        <Select
          value={range}
          onValueChange={(value) => setRange(value as any)}
          className="w-40"
        >
          {TIME_RANGES.map((r) => (
            <SelectItem key={r.value} value={r.value}>
              {r.label}
            </SelectItem>
          ))}
        </Select>
      </CardHeader>

      <CardContent className="h-[400px] p-0">
        {loading || chartData.length === 0 ? (
          <div className="p-6 text-muted-foreground text-center">Загрузка данных…</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="trustGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#4ade80" stopOpacity={0.6} />
                  <stop offset="95%" stopColor="#4ade80" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />
              <XAxis
                dataKey="timestamp"
                tickFormatter={(ts) =>
                  new Date(ts * 1000).toLocaleDateString('ru-RU', {
                    day: 'numeric',
                    month: 'short',
                  })
                }
              />
              <YAxis
                yAxisId="left"
                label={{ value: 'Активность', angle: -90, position: 'insideLeft' }}
              />
              <YAxis
                yAxisId="right"
                orientation="right"
                domain={[0, 100]}
                label={{
                  value: 'Средний TrustScore',
                  angle: 90,
                  position: 'insideRight',
                }}
              />

              <Tooltip
                formatter={(value: any, name: string) => [
                  value,
                  {
                    activeVotes: 'Активных голосов',
                    proposalsSubmitted: 'Предложений',
                    actionsExecuted: 'Действий',
                    trustScoreAvg: 'TrustScore',
                  }[name] || name,
                ]}
                labelFormatter={(ts: number) =>
                  new Date(ts * 1000).toLocaleString('ru-RU')
                }
              />

              <Area
                type="monotone"
                yAxisId="left"
                dataKey="activeVotes"
                stroke="#6366f1"
                fillOpacity={0.2}
                fill="#6366f1"
                name="Активные голосования"
              />
              <Area
                type="monotone"
                yAxisId="left"
                dataKey="proposalsSubmitted"
                stroke="#f59e0b"
                fillOpacity={0.15}
                fill="#f59e0b"
                name="Предложения"
              />
              <Area
                type="monotone"
                yAxisId="left"
                dataKey="actionsExecuted"
                stroke="#10b981"
                fillOpacity={0.1}
                fill="#10b981"
                name="Исполненные действия"
              />
              <Line
                type="monotone"
                yAxisId="right"
                dataKey="trustScoreAvg"
                stroke="#4ade80"
                strokeWidth={2}
                dot={false}
                name="TrustScore"
              />
              <Legend verticalAlign="top" />
              <Brush dataKey="timestamp" height={20} stroke="#d4d4d8" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
};

export default DelegateActivityChart;
