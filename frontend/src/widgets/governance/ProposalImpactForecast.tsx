// src/widgets/Governance/ProposalImpactForecast.tsx

import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { useProposalForecast } from '@/hooks/governance/useProposalForecast';
import { Skeleton } from '@/components/ui/skeleton';
import { ExplanationBubble } from '@/components/ui/ExplanationBubble';
import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, LabelList } from 'recharts';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { ScenarioCard } from '@/components/governance/ScenarioCard';
import { XAIReasoningBlock } from '@/components/governance/XAIReasoningBlock';

interface ForecastProps {
  proposalId: string;
}

export const ProposalImpactForecast: React.FC<ForecastProps> = ({ proposalId }) => {
  const { data, loading, error } = useProposalForecast(proposalId);
  const [activeHorizon, setActiveHorizon] = useState<'short' | 'mid' | 'long'>('mid');

  const horizonLabels = {
    short: '1 неделя',
    mid: '1 месяц',
    long: '3 месяца',
  };

  const horizonColors = {
    short: '#60a5fa',
    mid: '#4ade80',
    long: '#facc15',
  };

  if (loading) {
    return <Skeleton className="w-full h-[300px] rounded-xl" />;
  }

  if (error || !data) {
    return (
      <Card className="w-full">
        <CardContent className="text-sm text-destructive py-6 px-4">
          Не удалось загрузить прогноз последствий предложения.
        </CardContent>
      </Card>
    );
  }

  const currentData = data.forecasts[activeHorizon];

  return (
    <Card className="w-full border border-border bg-background/90 shadow-lg rounded-xl">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold">Прогноз воздействия предложения</h3>
            <p className="text-sm text-muted-foreground">
              AI-модель предсказывает, как предложение повлияет на DAO-экосистему.
            </p>
          </div>
          <div className="flex gap-2">
            {(['short', 'mid', 'long'] as const).map((h) => (
              <Badge
                key={h}
                onClick={() => setActiveHorizon(h)}
                variant={activeHorizon === h ? 'default' : 'outline'}
                className={cn('cursor-pointer text-xs capitalize', {
                  'border-primary': activeHorizon === h,
                })}
              >
                {horizonLabels[h]}
              </Badge>
            ))}
          </div>
        </div>
      </CardHeader>

      <CardContent>
        <div className="w-full h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={currentData.impactMetrics}>
              <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />
              <XAxis dataKey="label" />
              <YAxis />
              <Tooltip
                formatter={(val: number) => `${val > 0 ? '+' : ''}${val.toFixed(2)}%`}
                labelFormatter={(label) => `Метрика: ${label}`}
              />
              <Bar dataKey="value" fill={horizonColors[activeHorizon]}>
                <LabelList dataKey="value" position="top" formatter={(val) => `${val.toFixed(1)}%`} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="mt-4 space-y-3">
          <ScenarioCard
            title="Наиболее вероятный исход"
            description={data.scenario.summary}
            riskLevel={data.scenario.riskScore}
            impactValue={data.scenario.impactScore}
          />

          <XAIReasoningBlock
            label="Обоснование прогноза"
            xai={data.xai}
            className="mt-4"
          />
        </div>

        <div className="mt-6 text-xs text-muted-foreground text-right">
          Предсказание рассчитано AI-агентом NeuroForecast v3.2 с использованием RL-симуляции
        </div>
      </CardContent>
    </Card>
  );
};

export default ProposalImpactForecast;
