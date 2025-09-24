// src/widgets/Governance/DelegateTrustScore.tsx

import React, { useEffect, useMemo, useState } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { useDelegateTrustScore } from '@/hooks/governance/useDelegateTrustScore';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import {
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { Badge } from '@/components/ui/badge';

type Metric =
  | 'ethicsCompliance'
  | 'complaintsRatio'
  | 'zkProofScore'
  | 'voteParticipation'
  | 'decisionLatency'
  | 'codeAuditScore';

type MetricLabelMap = {
  [key in Metric]: string;
};

const METRIC_LABELS: MetricLabelMap = {
  ethicsCompliance: 'Этика',
  complaintsRatio: 'Жалобы',
  zkProofScore: 'ZK-доказательства',
  voteParticipation: 'Участие',
  decisionLatency: 'Реакция',
  codeAuditScore: 'Аудит решений',
};

const getTrustColor = (score: number): string => {
  if (score >= 90) return 'bg-green-500';
  if (score >= 70) return 'bg-yellow-400';
  if (score >= 50) return 'bg-orange-400';
  return 'bg-red-500';
};

interface Props {
  delegateId: string;
}

export const DelegateTrustScore: React.FC<Props> = ({ delegateId }) => {
  const { data, loading } = useDelegateTrustScore(delegateId);

  const radarData = useMemo(() => {
    if (!data) return [];
    return Object.entries(data.metrics || {}).map(([key, value]) => ({
      metric: METRIC_LABELS[key as Metric],
      score: Math.round((value as number) * 100),
    }));
  }, [data]);

  return (
    <Card className="w-full bg-card/70 border border-border/30 shadow-md rounded-xl backdrop-blur">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold">TrustScore Делегата</h3>
            <p className="text-muted-foreground text-sm">
              AI-аудит надёжности и поведения
            </p>
          </div>
          {data && (
            <Badge
              className={cn(
                'text-white font-bold px-3 py-1 text-sm rounded-full',
                getTrustColor(data.totalScore)
              )}
            >
              {data.totalScore} / 100
            </Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="h-[320px] px-2 py-4">
        {loading || !data ? (
          <Skeleton className="w-full h-full rounded-md" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart outerRadius="85%" data={radarData}>
              <PolarGrid strokeOpacity={0.1} />
              <PolarAngleAxis dataKey="metric" stroke="#9ca3af" fontSize={12} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} />
              <Tooltip
                formatter={(val: any) => `${val} / 100`}
                labelStyle={{ fontWeight: 600 }}
              />
              <Radar
                name="Trust"
                dataKey="score"
                stroke="#4ade80"
                fill="#4ade80"
                fillOpacity={0.25}
              />
            </RadarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
};

export default DelegateTrustScore;
