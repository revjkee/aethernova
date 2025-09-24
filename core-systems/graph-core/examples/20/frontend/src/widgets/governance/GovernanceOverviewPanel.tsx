// src/widgets/Governance/GovernanceOverviewPanel.tsx

import React, { useEffect, useState, useMemo, Suspense } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { GovernanceStatusAPI, type GovernanceMetrics } from '@/services/governanceService';
import { useInterval } from '@/shared/hooks/useInterval';
import { cn } from '@/shared/lib/utils';
import { ShieldCheck, Users, Gavel, AlertCircle, BarChart } from 'lucide-react';
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip';
import './GovernanceOverviewPanel.css';

const REFRESH_INTERVAL = 15000;

export default function GovernanceOverviewPanel(): JSX.Element {
  const [metrics, setMetrics] = useState<GovernanceMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMetrics = async () => {
    try {
      const data = await GovernanceStatusAPI.fetchOverview();
      setMetrics(data);
    } catch (error) {
      console.error('Ошибка получения данных управления:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  useInterval(() => {
    fetchMetrics();
  }, REFRESH_INTERVAL);

  const {
    activeAgents,
    pendingProposals,
    totalDAOVotes,
    governanceScore,
    zkVerifiedAgents,
    alerts,
  } = useMemo(() => metrics || {
    activeAgents: 0,
    pendingProposals: 0,
    totalDAOVotes: 0,
    governanceScore: 0,
    zkVerifiedAgents: 0,
    alerts: [],
  }, [metrics]);

  return (
    <Card className="governance-panel-container">
      <CardHeader>
        <div className="governance-title">Статус управления системой</div>
        <Separator className="my-2" />
      </CardHeader>
      <CardContent className="grid grid-cols-2 md:grid-cols-3 gap-4">

        <GovernanceMetric
          icon={<Users className="metric-icon" />}
          label="Активные агенты"
          value={activeAgents}
          loading={loading}
        />

        <GovernanceMetric
          icon={<Gavel className="metric-icon" />}
          label="Ожидающие предложения"
          value={pendingProposals}
          loading={loading}
        />

        <GovernanceMetric
          icon={<BarChart className="metric-icon" />}
          label="Всего голосов DAO"
          value={totalDAOVotes}
          loading={loading}
        />

        <GovernanceMetric
          icon={<ShieldCheck className="metric-icon" />}
          label="ZK-проверенные агенты"
          value={zkVerifiedAgents}
          loading={loading}
        />

        <GovernanceMetric
          icon={<AlertCircle className="metric-icon text-red-500" />}
          label="Аномалии / предупреждения"
          value={alerts.length}
          loading={loading}
          tooltip={alerts.length > 0 ? alerts.join(', ') : 'Система стабильна'}
        />

        <GovernanceMetric
          icon={<BarChart className="metric-icon" />}
          label="Индекс управления"
          value={`${governanceScore.toFixed(2)}%`}
          loading={loading}
        />

      </CardContent>
    </Card>
  );
}

type GovernanceMetricProps = {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  loading: boolean;
  tooltip?: string;
};

function GovernanceMetric({ icon, label, value, loading, tooltip }: GovernanceMetricProps): JSX.Element {
  const content = (
    <div className="gov-metric">
      <div className="gov-icon">{icon}</div>
      <div className="gov-info">
        <div className="gov-label">{label}</div>
        {loading ? (
          <Skeleton className="w-[60px] h-[16px] mt-1" />
        ) : (
          <div className="gov-value">{value}</div>
        )}
      </div>
    </div>
  );

  return tooltip ? (
    <Tooltip>
      <TooltipTrigger asChild>
        <div>{content}</div>
      </TooltipTrigger>
      <TooltipContent>{tooltip}</TooltipContent>
    </Tooltip>
  ) : <>{content}</>;
}
