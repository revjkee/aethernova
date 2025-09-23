// src/widgets/Governance/VoterReputationIndicator.tsx

import React, { useEffect, useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip';
import { UserIcon, StarIcon, ShieldCheck, AlertTriangle, Info } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { getVoterReputation } from '@/services/governance/reputationService';
import { cn } from '@/lib/utils';

interface ReputationData {
  score: number; // 0–100
  level: 'trusted' | 'neutral' | 'risky';
  tags: string[];
  voteCount: number;
  proposalImpactScore: number;
  flagged: boolean;
  aiCommentary: string;
  lastActivity: string;
  voterId: string;
}

export default function VoterReputationIndicator({ voterId }: { voterId: string }) {
  const [data, setData] = useState<ReputationData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      setLoading(true);
      const result = await getVoterReputation(voterId);
      setData(result);
      setLoading(false);
    };
    fetch();
  }, [voterId]);

  if (loading || !data) {
    return (
      <Card className="p-4 rounded-xl w-full">
        <CardContent className="space-y-3">
          <Skeleton className="h-5 w-1/3" />
          <Skeleton className="h-8 w-full" />
        </CardContent>
      </Card>
    );
  }

  const { score, level, tags, voteCount, flagged, proposalImpactScore, aiCommentary, lastActivity } = data;

  const levelColors = {
    trusted: 'bg-green-500',
    neutral: 'bg-yellow-500',
    risky: 'bg-red-500',
  };

  const iconMap = {
    trusted: <ShieldCheck className="w-5 h-5 text-green-600" />,
    neutral: <AlertTriangle className="w-5 h-5 text-yellow-500" />,
    risky: <AlertTriangle className="w-5 h-5 text-red-600" />,
  };

  return (
    <Card className="p-6 rounded-2xl border bg-background/95 shadow-lg w-full">
      <CardContent className="space-y-5">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-2">
            <UserIcon className="h-5 w-5 text-muted-foreground" />
            <span className="font-medium text-sm text-muted-foreground">ID: {voterId.slice(0, 8)}...</span>
          </div>
          <Badge variant="outline" className="flex items-center gap-1 text-xs px-2 py-1">
            {iconMap[level]}
            {level === 'trusted' && 'Доверенный'}
            {level === 'neutral' && 'Нейтральный'}
            {level === 'risky' && 'Рискованный'}
          </Badge>
        </div>

        <div>
          <Progress value={score} className={cn('h-4 rounded-lg', levelColors[level])} />
          <div className="flex justify-between text-xs text-muted-foreground pt-1">
            <span>Репутация: {score} / 100</span>
            <span>Активность: {lastActivity}</span>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs text-muted-foreground">
          <div>
            <span className="font-semibold">Голосов:</span> {voteCount}
          </div>
          <div>
            <span className="font-semibold">Влияние:</span> {proposalImpactScore.toFixed(2)}
          </div>
          <div>
            <span className="font-semibold">Флагов:</span> {flagged ? 'Да' : 'Нет'}
          </div>
        </div>

        <div className="flex flex-wrap gap-2 pt-2">
          {tags.map((tag, idx) => (
            <Badge key={idx} variant="secondary" className="text-xs">{tag}</Badge>
          ))}
        </div>

        <div className="border-t pt-3 mt-3 text-sm text-muted-foreground flex items-start gap-2">
          <Info className="w-4 h-4 mt-0.5" />
          <p className="text-xs">{aiCommentary}</p>
        </div>
      </CardContent>
    </Card>
  );
}
