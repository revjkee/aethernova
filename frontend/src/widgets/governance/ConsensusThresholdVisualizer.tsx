// src/widgets/Governance/ConsensusThresholdVisualizer.tsx

import React, { useMemo } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Bar,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
  CartesianGrid,
  Label,
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { useProposalMetrics } from '@/hooks/dao/useProposalMetrics';
import { useTheme } from '@/hooks/theme/useTheme';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { AiOutlineWarning } from 'react-icons/ai';

type ChartDataPoint = {
  name: string;
  votes: number;
  label?: string;
};

export const ConsensusThresholdVisualizer: React.FC = () => {
  const { data, thresholds, loading } = useProposalMetrics();
  const { theme } = useTheme();

  const chartData: ChartDataPoint[] = useMemo(() => {
    if (!data) return [];
    return [
      {
        name: 'За',
        votes: data.votesFor,
      },
      {
        name: 'Против',
        votes: data.votesAgainst,
      },
      {
        name: 'Воздержался',
        votes: data.votesAbstain,
      },
      {
        name: 'Неучаствующие',
        votes: data.votesUnvoted,
      },
    ];
  }, [data]);

  const referenceLines = useMemo(() => {
    if (!thresholds) return [];
    return [
      {
        label: 'Минимальный кворум',
        value: thresholds.minQuorum,
        color: '#c084fc',
      },
      {
        label: 'Порог принятия',
        value: thresholds.acceptanceThreshold,
        color: '#22c55e',
      },
      {
        label: 'Порог блокировки',
        value: thresholds.vetoThreshold,
        color: '#ef4444',
      },
    ];
  }, [thresholds]);

  return (
    <Card className="w-full h-[380px] shadow-md bg-background relative overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-semibold">
          Порог консенсуса и текущая активность
        </CardTitle>
        {loading && (
          <div className="absolute right-4 top-4 text-xs text-muted-foreground">
            Загрузка...
          </div>
        )}
      </CardHeader>
      <CardContent className="h-[320px]">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={chartData} margin={{ top: 20, right: 20, bottom: 20, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis>
              <Label
                value="Голоса"
                angle={-90}
                position="insideLeft"
                offset={0}
                style={{ fill: theme === 'dark' ? '#e4e4e7' : '#18181b' }}
              />
            </YAxis>
            <Tooltip
              contentStyle={{
                backgroundColor: theme === 'dark' ? '#18181b' : '#ffffff',
                borderColor: theme === 'dark' ? '#52525b' : '#d4d4d8',
                fontSize: '12px',
              }}
              cursor={{ fill: 'rgba(156,163,175,0.1)' }}
            />
            <Bar dataKey="votes" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            {referenceLines.map((line, idx) => (
              <ReferenceLine
                key={idx}
                y={line.value}
                label={{
                  value: line.label,
                  position: 'right',
                  fill: line.color,
                  fontSize: 10,
                  fontWeight: 600,
                }}
                stroke={line.color}
                strokeDasharray="4 2"
              />
            ))}
            <Line
              type="monotone"
              dataKey="votes"
              stroke="#6366f1"
              strokeWidth={2}
              dot={{ r: 3 }}
              activeDot={{ r: 6 }}
            />
          </ComposedChart>
        </ResponsiveContainer>
        {thresholds?.alert && (
          <div className="mt-2 text-sm text-warning flex items-center gap-1">
            <AiOutlineWarning className="text-yellow-500" />
            <span>{thresholds.alert}</span>
          </div>
        )}
        <div className="mt-3 flex flex-wrap gap-2 text-[10px]">
          <Badge variant="outline">
            Кворум: ≥ {thresholds?.minQuorum ?? '–'} голосов
          </Badge>
          <Badge variant="outline">
            Порог принятия: ≥ {thresholds?.acceptanceThreshold ?? '–'}
          </Badge>
          <Badge variant="destructive" className="bg-red-500/10 text-red-700 border-red-500/30">
            Блокировка: ≥ {thresholds?.vetoThreshold ?? '–'}
          </Badge>
        </div>
      </CardContent>
    </Card>
  );
};
