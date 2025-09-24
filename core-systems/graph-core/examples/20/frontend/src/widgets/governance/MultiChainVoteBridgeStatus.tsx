// src/widgets/Governance/MultiChainVoteBridgeStatus.tsx

import React, { useEffect, useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { AlertTriangle, CheckCircle, Link2, RefreshCw, ShieldOff, Timer } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { fetchBridgeStatus } from '@/services/governance/bridgeStatusService';
import { Skeleton } from '@/components/ui/skeleton';

type ChainBridgeStatus = {
  chainName: string;
  synced: boolean;
  lastSyncTime: string;
  lagSeconds: number;
  proofType: 'ZK' | 'Optimistic' | 'Manual' | 'None';
  isDegraded: boolean;
  voteTxHash?: string;
  blockHeight?: number;
};

export default function MultiChainVoteBridgeStatus() {
  const [statuses, setStatuses] = useState<ChainBridgeStatus[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    const data = await fetchBridgeStatus();
    setStatuses(data);
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Card className="p-6 rounded-2xl shadow border">
        <CardContent className="space-y-4">
          <Skeleton className="h-6 w-2/3" />
          <Skeleton className="h-12 w-full rounded-lg" />
          <Skeleton className="h-6 w-1/2" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="p-6 rounded-2xl shadow border bg-background/80">
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Мультичейн статус голосования</h2>
          <button onClick={fetchData} className="text-sm text-muted-foreground hover:underline flex items-center gap-1">
            <RefreshCw size={16} className="mr-1" /> Обновить
          </button>
        </div>

        <div className="space-y-4">
          {statuses.map((chain) => (
            <div
              key={chain.chainName}
              className={cn(
                'flex flex-col md:flex-row md:items-center justify-between p-4 border rounded-xl bg-muted/30',
                chain.isDegraded && 'border-red-500 bg-red-50'
              )}
            >
              <div className="flex items-center gap-4">
                {chain.synced ? (
                  <CheckCircle className="text-green-500" size={20} />
                ) : (
                  <AlertTriangle className="text-yellow-500" size={20} />
                )}
                <div>
                  <h3 className="text-base font-medium">{chain.chainName}</h3>
                  <p className="text-xs text-muted-foreground">
                    {chain.synced
                      ? `Синхронизировано: ${chain.lastSyncTime}`
                      : `Задержка: ${chain.lagSeconds} сек`}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3 mt-2 md:mt-0">
                <Badge variant="outline">{chain.proofType} Proof</Badge>
                {chain.voteTxHash && (
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger>
                        <Link2 className="text-blue-500 hover:underline cursor-pointer" size={18} />
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>Tx Hash: {chain.voteTxHash.slice(0, 8)}…</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                )}
                {chain.blockHeight !== undefined && (
                  <span className="text-xs text-muted-foreground">Блок #{chain.blockHeight}</span>
                )}
              </div>
            </div>
          ))}
        </div>

        <div className="pt-4 border-t">
          <p className="text-xs text-muted-foreground flex items-center gap-1">
            <Timer size={14} /> Обновление каждые 15 секунд | Proof-механизмы: ZK, Optimistic, Manual
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
