// src/widgets/Governance/ProposalSimulationPreview.tsx

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { LoaderIcon, PlayIcon, RefreshCwIcon, EyeIcon, AlertCircleIcon } from '@/components/icons';
import { fetchSimulationResult, abortSimulation } from '@/services/dao/sandboxSimulator';
import { useToast } from '@/components/ui/use-toast';
import { Skeleton } from '@/components/ui/skeleton';
import dynamic from 'next/dynamic';

const SimulationGraph = dynamic(() => import('@/components/graphs/SimulationGraph'), { ssr: false });

interface SimulationData {
  impactVector: Record<string, number>;
  warnings: string[];
  isDeterministic: boolean;
  zkProofValid: boolean;
  affectedModules: string[];
  forecastSummary: string;
  estimatedGas: number;
  systemConfidence: number;
  aiCommentary: string;
}

export const ProposalSimulationPreview: React.FC<{ proposalId: string }> = ({ proposalId }) => {
  const [data, setData] = useState<SimulationData | null>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const { toast } = useToast();

  const simulate = async () => {
    setRunning(true);
    setLoading(true);
    setData(null);
    try {
      const result = await fetchSimulationResult(proposalId);
      if (!result.success || !result.data) {
        throw new Error(result.message || 'Ошибка при получении данных симуляции.');
      }
      setData(result.data);
    } catch (err: any) {
      toast({
        variant: 'destructive',
        title: 'Симуляция не выполнена',
        description: err.message || 'Ошибка выполнения sandbox-режима.'
      });
    } finally {
      setLoading(false);
      setRunning(false);
    }
  };

  const cancelSimulation = async () => {
    setRunning(false);
    await abortSimulation(proposalId);
    toast({
      title: 'Симуляция прервана',
      description: 'Вы отменили выполнение симуляции.',
    });
  };

  useEffect(() => {
    simulate();
  }, [proposalId]);

  return (
    <Card className="border-primary/20 shadow-md bg-muted/10">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-md font-semibold flex items-center gap-2">
          <EyeIcon className="w-4 h-4" />
          AI-предварительный просмотр предложения
        </CardTitle>
        <div className="flex gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="sm"
                variant="ghost"
                onClick={simulate}
                disabled={loading || running}
              >
                <RefreshCwIcon className="w-4 h-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Обновить симуляцию</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="sm"
                variant="destructive"
                onClick={cancelSimulation}
                disabled={!running}
              >
                <AlertCircleIcon className="w-4 h-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Прервать симуляцию</TooltipContent>
          </Tooltip>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {loading && <Skeleton className="h-[200px] w-full rounded-md" />}
        {!loading && data && (
          <>
            <div className="text-sm text-muted-foreground">{data.forecastSummary}</div>

            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="font-semibold text-foreground">Детерминизм:</span>{' '}
                {data.isDeterministic ? 'Да' : 'Нет'}
              </div>
              <div>
                <span className="font-semibold text-foreground">ZK-подтверждение:</span>{' '}
                {data.zkProofValid ? 'Проверено' : 'Ошибка'}
              </div>
              <div>
                <span className="font-semibold text-foreground">Модули:</span>{' '}
                {data.affectedModules.join(', ')}
              </div>
              <div>
                <span className="font-semibold text-foreground">Gas-предсказание:</span>{' '}
                {data.estimatedGas} Gwei
              </div>
              <div>
                <span className="font-semibold text-foreground">AI Confidence:</span>{' '}
                {(data.systemConfidence * 100).toFixed(1)}%
              </div>
            </div>

            {data.warnings.length > 0 && (
              <div className="text-sm text-yellow-700 dark:text-yellow-300 space-y-1 mt-2">
                <div className="font-semibold">Предупреждения:</div>
                <ul className="list-disc list-inside">
                  {data.warnings.map((warn, idx) => (
                    <li key={idx}>{warn}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="pt-4">
              <SimulationGraph data={data.impactVector} />
            </div>

            <div className="pt-2 text-xs italic text-blue-900 dark:text-blue-300 border-t border-border mt-4">
              AI-комментарий: {data.aiCommentary}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};
