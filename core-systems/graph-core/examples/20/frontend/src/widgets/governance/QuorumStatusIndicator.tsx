// src/widgets/Governance/QuorumStatusIndicator.tsx

import React from 'react';
import { useQuorumStatus } from '@/hooks/governance/useQuorumStatus';
import { Progress } from '@/components/ui/progress';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Card, CardContent } from '@/components/ui/card';
import { AlertCircle, CheckCircle2, Hourglass, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';

interface QuorumStatusIndicatorProps {
  proposalId: string;
}

export const QuorumStatusIndicator: React.FC<QuorumStatusIndicatorProps> = ({ proposalId }) => {
  const { status, error, loading } = useQuorumStatus(proposalId);

  if (loading) {
    return (
      <Card className="p-4 rounded-lg shadow-sm bg-muted">
        <CardContent className="text-muted-foreground text-sm">
          Загрузка данных кворума...
        </CardContent>
      </Card>
    );
  }

  if (error || !status) {
    return (
      <Card className="p-4 rounded-lg border border-destructive/60 bg-destructive/10">
        <CardContent className="text-destructive text-sm flex items-center gap-2">
          <AlertCircle size={18} /> Не удалось получить статус кворума.
        </CardContent>
      </Card>
    );
  }

  const {
    requiredQuorumPercent,
    currentParticipationPercent,
    reached,
    estimatedTimeToQuorum,
    legitimacyThreshold,
    legitimacyReached,
    totalVoters,
    totalVotesCast,
    aiConfidenceScore,
  } = status;

  const quorumClass = reached ? 'text-green-600' : 'text-yellow-500';
  const legitimacyClass = legitimacyReached ? 'text-green-700' : 'text-red-500';

  return (
    <Card className="p-4 bg-background/80 border border-border rounded-xl shadow-md">
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-sm font-medium text-muted-foreground">Статус кворума</h4>
            <p className="text-xl font-semibold">
              {currentParticipationPercent.toFixed(1)}% / {requiredQuorumPercent}%
            </p>
          </div>

          <div className="flex items-center gap-2">
            {reached ? (
              <CheckCircle2 className="text-green-500" size={24} />
            ) : (
              <Hourglass className="text-yellow-500 animate-pulse" size={24} />
            )}
            <span className={cn('text-sm font-semibold', quorumClass)}>
              {reached ? 'Кворум достигнут' : 'Кворум не достигнут'}
            </span>
          </div>
        </div>

        <Progress value={currentParticipationPercent} max={100} className="h-2 rounded" />

        <div className="text-sm text-muted-foreground flex justify-between">
          <span>{totalVotesCast} из {totalVoters} участников проголосовали</span>
          <span>Прогноз AI: {aiConfidenceScore}% уверенности</span>
        </div>

        <div className="pt-2">
          <div className="flex justify-between items-center">
            <span className="text-sm font-medium">Легитимность</span>
            <div className="flex items-center gap-2">
              {legitimacyReached ? (
                <ShieldCheck className="text-green-600" size={18} />
              ) : (
                <AlertCircle className="text-red-500" size={18} />
              )}
              <span className={cn('text-sm font-semibold', legitimacyClass)}>
                {legitimacyReached ? 'Достигнута' : 'Не достигнута'}
              </span>
            </div>
          </div>
          <div className="text-xs text-muted-foreground">
            Порог: {legitimacyThreshold}%, Фактически: {(currentParticipationPercent).toFixed(1)}%
          </div>
        </div>

        {!reached && estimatedTimeToQuorum && (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="mt-2 text-xs text-muted-foreground underline cursor-help">
                  Ожидаемое время достижения кворума
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {estimatedTimeToQuorum}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
      </CardContent>
    </Card>
  );
};

export default QuorumStatusIndicator;
