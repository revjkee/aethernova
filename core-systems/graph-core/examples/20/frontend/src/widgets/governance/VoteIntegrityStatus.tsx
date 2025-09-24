// src/widgets/Governance/VoteIntegrityStatus.tsx

import React from 'react';
import { useVoteIntegrity } from '@/hooks/governance/useVoteIntegrity';
import { Card, CardContent } from '@/components/ui/card';
import { AlertTriangle, ShieldCheck, HelpCircle, ScanSearch } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '@/components/ui/tooltip';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';

interface VoteIntegrityStatusProps {
  proposalId: string;
}

const VoteIntegrityStatus: React.FC<VoteIntegrityStatusProps> = ({ proposalId }) => {
  const { integrityReport, isLoading, error } = useVoteIntegrity(proposalId);

  if (isLoading) {
    return (
      <Card className="p-4 shadow-sm bg-muted/30">
        <CardContent className="flex items-center gap-3">
          <ScanSearch className="animate-spin-slow text-muted-foreground" size={22} />
          <span className="text-sm text-muted-foreground">Анализ целостности голосования...</span>
        </CardContent>
      </Card>
    );
  }

  if (error || !integrityReport) {
    return (
      <Card className="p-4 border border-destructive/50 bg-destructive/10">
        <CardContent className="text-sm text-destructive flex items-center gap-2">
          <AlertTriangle size={18} /> Ошибка анализа целостности голосования.
        </CardContent>
      </Card>
    );
  }

  const {
    integrityScore,             // float [0-100]
    suspiciousWallets,          // array of strings
    sybilClusters,              // int
    zkFailureCount,             // int
    botVoteEstimate,            // %
    flaggedTxHashes,            // string[]
    comments,                   // string[]
    aiSummary,                  // string
  } = integrityReport;

  const scoreClass = integrityScore > 85
    ? 'text-green-600'
    : integrityScore > 60
    ? 'text-yellow-600'
    : 'text-red-600';

  return (
    <Card className="p-4 border border-border shadow-md bg-background/80 rounded-xl">
      <CardContent className="space-y-4">
        <div className="flex justify-between items-center">
          <div>
            <h4 className="text-sm font-semibold text-muted-foreground">Целостность голосования</h4>
            <p className={cn('text-xl font-bold', scoreClass)}>{integrityScore.toFixed(1)}%</p>
          </div>
          <div className="flex items-center gap-2">
            {integrityScore >= 85 ? (
              <ShieldCheck className="text-green-500" size={24} />
            ) : (
              <AlertTriangle className="text-yellow-500" size={24} />
            )}
            <span className={cn('text-sm font-semibold', scoreClass)}>
              {integrityScore >= 85 ? 'Высокая надёжность' : integrityScore >= 60 ? 'Внимание' : 'Низкая надёжность'}
            </span>
          </div>
        </div>

        <div className="text-sm text-muted-foreground leading-relaxed">
          {aiSummary}
        </div>

        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="flex items-center gap-2">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <HelpCircle className="text-muted-foreground cursor-help" size={16} />
                </TooltipTrigger>
                <TooltipContent>
                  Количество кошельков, не прошедших ZK-проверку.
                </TooltipContent>
              </Tooltip>
            </Tooltip>
            ZK-провалы: <span className="font-medium">{zkFailureCount}</span>
          </div>
          <div className="flex items-center gap-2">
            Sybil-кластеры: <span className="font-medium">{sybilClusters}</span>
          </div>
          <div className="flex items-center gap-2">
            Ботов голосовало (оценка AI): <span className="font-medium">{botVoteEstimate}%</span>
          </div>
          <div className="flex items-center gap-2">
            Флагнутые кошельки: <span className="font-medium">{suspiciousWallets.length}</span>
          </div>
        </div>

        {comments.length > 0 && (
          <div className="pt-3">
            <h5 className="text-sm font-medium text-foreground mb-1">AI-комментарии</h5>
            <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
              {comments.map((c, i) => (
                <li key={i}>{c}</li>
              ))}
            </ul>
          </div>
        )}

        {flaggedTxHashes.length > 0 && (
          <div className="pt-2">
            <h5 className="text-sm font-medium text-foreground">Флагнутые транзакции</h5>
            <div className="text-xs text-muted-foreground break-all space-y-1 max-h-32 overflow-y-auto">
              {flaggedTxHashes.map((tx, idx) => (
                <div key={idx}>{tx}</div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default VoteIntegrityStatus;
