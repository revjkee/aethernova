import React, { useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useAgentRuntimeStates } from '@/services/agents/runtime';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { AgentState } from '@/types/agents';
import { ChevronRightIcon, ClockIcon, PauseCircleIcon, ZapIcon } from 'lucide-react';

const STATE_ICONS = {
  idle: <PauseCircleIcon className="w-4 h-4 text-muted" />,
  running: <ZapIcon className="w-4 h-4 text-green-600 animate-pulse" />,
  waiting: <ClockIcon className="w-4 h-4 text-yellow-600 animate-pulse" />,
  blocked: <ChevronRightIcon className="w-4 h-4 text-red-500" />,
};

export const AgentRuntimeState: React.FC = () => {
  const { t } = useTranslation();
  const { data, isLoading, refetch } = useAgentRuntimeStates();

  useEffect(() => {
    const interval = setInterval(() => refetch(), 5000);
    return () => clearInterval(interval);
  }, [refetch]);

  const sorted = useMemo(() => {
    if (!data) return [];
    return [...data].sort((a, b) => {
      const weight = { running: 3, waiting: 2, blocked: 1, idle: 0 };
      return weight[b.state] - weight[a.state];
    });
  }, [data]);

  return (
    <Card className="w-full border shadow-sm">
      <CardHeader>
        <CardTitle className="text-lg font-semibold">
          {t('monitoring.agent_runtime_state', 'Agent Runtime State')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 max-h-[460px] overflow-y-auto">
        {isLoading && (
          <>
            {[...Array(6)].map((_, idx) => (
              <Skeleton key={idx} className="h-12 w-full rounded-md" />
            ))}
          </>
        )}
        {!isLoading && sorted.length === 0 && (
          <div className="text-sm text-muted-foreground">
            {t('monitoring.no_agents', 'No active agents detected')}
          </div>
        )}
        {sorted.map(agent => (
          <div
            key={agent.id}
            className={cn(
              'p-3 rounded-md border shadow-sm bg-background flex items-start justify-between gap-3',
              {
                'bg-red-50': agent.state === 'blocked',
                'bg-yellow-50': agent.state === 'waiting',
                'bg-green-50': agent.state === 'running',
              }
            )}
          >
            <div className="space-y-1 w-2/3">
              <div className="flex items-center gap-2 font-medium text-sm">
                {STATE_ICONS[agent.state]}
                {agent.name || agent.id}
                <Badge
                  variant="outline"
                  className={cn('text-xs', {
                    'border-green-600 text-green-700': agent.state === 'running',
                    'border-yellow-600 text-yellow-700': agent.state === 'waiting',
                    'border-red-600 text-red-700': agent.state === 'blocked',
                    'border-muted text-muted-foreground': agent.state === 'idle',
                  })}
                >
                  {t(`agent_state.${agent.state}`, agent.state)}
                </Badge>
              </div>
              <div className="text-xs text-muted-foreground">
                {t('monitoring.phase', 'Phase')}: {agent.currentPhase || '—'} <br />
                {t('monitoring.module', 'Module')}: {agent.module || '—'}
              </div>
            </div>
            <div className="w-1/3 flex flex-col justify-center">
              <Progress value={agent.cpuLoad} className="h-2" />
              <div className="text-[10px] text-muted-foreground text-right mt-1">
                CPU: {agent.cpuLoad?.toFixed(1)}%
              </div>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
};

export default AgentRuntimeState;
