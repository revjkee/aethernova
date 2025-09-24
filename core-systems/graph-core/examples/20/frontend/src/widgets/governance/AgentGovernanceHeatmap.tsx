// src/widgets/Governance/AgentGovernanceHeatmap.tsx

import React, { useEffect, useState, useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { HeatMapGrid } from 'react-grid-heatmap';
import { Skeleton } from '@/components/ui/skeleton';
import { TooltipProvider, Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { getAgentInfluenceData } from '@/services/governance/influenceService';
import { cn } from '@/lib/utils';
import { Flame, Zap, ShieldCheck } from 'lucide-react';

interface AgentInfluenceRecord {
  agentId: string;
  agentName: string;
  domain: string;
  influenceScore: number; // 0–1
  decisionCount: number;
  anomalyRatio: number;
  trustLevel: 'high' | 'medium' | 'low';
}

export default function AgentGovernanceHeatmap() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<AgentInfluenceRecord[]>([]);

  const fetchData = async () => {
    setLoading(true);
    const response = await getAgentInfluenceData();
    setData(response);
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 60000);
    return () => clearInterval(interval);
  }, []);

  const uniqueAgents = useMemo(() => [...new Set(data.map((item) => item.agentName))], [data]);
  const uniqueDomains = useMemo(() => [...new Set(data.map((item) => item.domain))], [data]);

  const heatmapData = useMemo(() => {
    return uniqueDomains.map((domain) =>
      uniqueAgents.map((agent) => {
        const found = data.find((d) => d.agentName === agent && d.domain === domain);
        return found ? Number((found.influenceScore * 100).toFixed(1)) : 0;
      }),
    );
  }, [data, uniqueAgents, uniqueDomains]);

  if (loading) {
    return (
      <Card className="p-6 rounded-xl shadow-md">
        <CardContent className="space-y-3">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-64 w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="p-6 rounded-2xl shadow border bg-background/80">
      <CardContent className="space-y-6">
        <div className="flex justify-between items-center">
          <h2 className="text-lg font-semibold">Тепловая карта влияния агентов</h2>
          <p className="text-sm text-muted-foreground">Источник: AI-оценка голосований и активности</p>
        </div>

        <HeatMapGrid
          data={heatmapData}
          xLabels={uniqueAgents}
          yLabels={uniqueDomains}
          xLabelsLocation="bottom"
          yLabelsLocation="left"
          cellRender={(value, x, y) => (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="text-xs font-medium text-white w-full h-full flex items-center justify-center">
                    {value > 0 ? `${value}%` : ''}
                  </div>
                </TooltipTrigger>
                <TooltipContent className="text-xs w-48">
                  <div className="font-semibold">{uniqueAgents[x]}</div>
                  <div>Сфера: {uniqueDomains[y]}</div>
                  <div>Влияние: {value}%</div>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          cellStyle={(value) => ({
            background: `rgba(255, 99, 71, ${value / 100})`,
            borderRadius: '8px',
          })}
          cellHeight="2.5rem"
          xLabelsStyle={() => ({
            fontSize: '0.75rem',
            transform: 'rotate(-45deg)',
            whiteSpace: 'nowrap',
          })}
          yLabelsStyle={() => ({
            fontSize: '0.75rem',
          })}
        />

        <div className="flex items-center gap-6 pt-4 border-t">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Flame size={14} /> Высокое влияние
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Zap size={14} /> Частые инициативы
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <ShieldCheck size={14} /> Этическое соответствие
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
