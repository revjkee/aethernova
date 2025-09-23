// src/widgets/Governance/EthicsApprovalMeter.tsx

import React, { useEffect, useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Gauge } from '@/components/ui/gauge';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip';
import { getEthicsApprovalRating } from '@/services/governance/ethicsService';
import { CheckCircle, AlertTriangle, ShieldX, Info } from 'lucide-react';
import { cn } from '@/lib/utils';

interface EthicsResponse {
  score: number; // 0–100
  riskLevel: 'approved' | 'caution' | 'violation';
  reasons: string[];
  ethicsModelVersion: string;
  lastReviewed: string;
  reviewAgent: string;
}

export default function EthicsApprovalMeter({ proposalId }: { proposalId: string }) {
  const [data, setData] = useState<EthicsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      const result = await getEthicsApprovalRating(proposalId);
      setData(result);
      setLoading(false);
    };
    fetchData();
  }, [proposalId]);

  if (loading || !data) {
    return (
      <Card className="p-6 rounded-2xl shadow-md w-full">
        <CardContent className="space-y-4">
          <Skeleton className="h-6 w-1/3" />
          <Skeleton className="h-36 w-full" />
        </CardContent>
      </Card>
    );
  }

  const { score, riskLevel, reasons, ethicsModelVersion, lastReviewed, reviewAgent } = data;

  const riskColorMap = {
    approved: 'text-green-600',
    caution: 'text-yellow-500',
    violation: 'text-red-600',
  };

  const iconMap = {
    approved: <CheckCircle className="w-5 h-5" />,
    caution: <AlertTriangle className="w-5 h-5" />,
    violation: <ShieldX className="w-5 h-5" />,
  };

  return (
    <Card className="p-6 rounded-2xl border bg-background/90 shadow-lg w-full">
      <CardContent className="space-y-6">
        <div className="flex justify-between items-center">
          <h2 className="text-lg font-semibold">Этический допуск предложения</h2>
          <Badge variant="outline" className={cn('flex items-center gap-1', riskColorMap[riskLevel])}>
            {iconMap[riskLevel]}
            {riskLevel === 'approved' && 'Допустимо'}
            {riskLevel === 'caution' && 'Внимание'}
            {riskLevel === 'violation' && 'Нарушение'}
          </Badge>
        </div>

        <div className="flex flex-col md:flex-row md:items-center md:gap-6">
          <div className="w-full md:w-1/3">
            <Gauge value={score} max={100} color={
              score >= 80 ? 'green' : score >= 50 ? 'yellow' : 'red'
            } label="Оценка доверия" />
          </div>
          <div className="flex-1 space-y-2">
            <ul className="text-sm text-muted-foreground list-disc pl-4">
              {reasons.map((reason, idx) => (
                <li key={idx}>{reason}</li>
              ))}
            </ul>
            <div className="text-xs text-muted-foreground flex items-center gap-2 pt-2">
              <Info className="w-4 h-4" />
              AI Model v{ethicsModelVersion} · Обновлено {lastReviewed} · Агент: {reviewAgent}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
