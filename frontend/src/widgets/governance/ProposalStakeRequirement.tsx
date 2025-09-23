// src/widgets/Governance/ProposalStakeRequirement.tsx

import React from 'react';
import { Card, CardHeader, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { useUserStakeInfo } from '@/hooks/staking/useUserStakeInfo';
import { useProposalStakePolicy } from '@/hooks/dao/useProposalStakePolicy';
import { cn } from '@/lib/utils';
import { PiShieldCheckFill, PiWarningFill } from 'react-icons/pi';

export const ProposalStakeRequirement: React.FC = () => {
  const { requiredStake, currentStake, delegatedStake, eligible, riskAlert, loading } =
    useProposalStakePolicy();

  const isEligible = eligible && currentStake >= requiredStake;

  return (
    <Card className="w-full shadow-md relative">
      <CardHeader className="pb-1 flex items-center justify-between">
        <CardTitle className="text-base font-semibold">Требуемый Stake</CardTitle>
        {loading && (
          <span className="text-xs text-muted-foreground animate-pulse">загрузка...</span>
        )}
      </CardHeader>

      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between">
          <div className="flex items-center gap-2">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    className={cn(
                      'text-xs px-2 py-1 rounded-sm',
                      isEligible
                        ? 'bg-green-100 text-green-700 border border-green-500'
                        : 'bg-yellow-100 text-yellow-700 border border-yellow-500'
                    )}
                  >
                    {isEligible ? (
                      <div className="flex items-center gap-1">
                        <PiShieldCheckFill className="text-green-600" />
                        Достаточно для подачи
                      </div>
                    ) : (
                      <div className="flex items-center gap-1">
                        <PiWarningFill className="text-yellow-600" />
                        Недостаточно стейка
                      </div>
                    )}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  <p>
                    Минимальный стейк необходим для предотвращения спама. Учитывается собственный и
                    делегированный баланс.
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>

          <div className="text-right text-sm">
            <div className="text-muted-foreground">Требуется:</div>
            <div className="font-medium">{requiredStake?.toLocaleString() ?? '—'} $NEURO</div>
          </div>
        </div>

        <Progress
          value={Math.min((currentStake / requiredStake) * 100, 100)}
          className="h-3 rounded-lg bg-muted/40"
          indicatorClassName={cn(
            'rounded-lg transition-all duration-500',
            isEligible ? 'bg-green-500' : 'bg-yellow-500'
          )}
        />

        <div className="grid grid-cols-2 gap-4 text-xs mt-2 text-muted-foreground">
          <div>
            <div className="text-muted-foreground">Ваш stake</div>
            <div className="font-medium text-foreground">
              {currentStake?.toLocaleString() ?? '–'} $NEURO
            </div>
          </div>
          <div>
            <div className="text-muted-foreground">Делегировано вам</div>
            <div className="font-medium text-foreground">
              {delegatedStake?.toLocaleString() ?? '–'} $NEURO
            </div>
          </div>
        </div>

        {riskAlert && (
          <div className="mt-4 text-sm text-orange-600 bg-orange-100 px-3 py-2 rounded-md border border-orange-300 shadow-sm">
            <div className="flex items-center gap-2">
              <PiWarningFill className="text-orange-600" />
              <span>{riskAlert}</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
