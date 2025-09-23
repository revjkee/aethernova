import React, { useEffect, useState } from 'react';
import { useSocket } from '@/shared/hooks/useSocket';
import { Tooltip } from '@/shared/components/Tooltip';
import { Spinner } from '@/shared/components/Spinner';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { LoadBalancerIcon } from '@/shared/components/icons/LoadBalancerIcon';
import './styles/AgentLoadBalancerIndicator.css';

interface LoadStatus {
  agentId: string;
  loadPercent: number; // 0–100
  weight: number; // 0–1
  status: 'idle' | 'stable' | 'overloaded' | 'rebalancing';
  assignedBalancer: string;
  timestamp: number;
}

interface AgentLoadBalancerIndicatorProps {
  agentId: string;
}

export const AgentLoadBalancerIndicator: React.FC<AgentLoadBalancerIndicatorProps> = ({
  agentId,
}) => {
  const [status, setStatus] = useState<LoadStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const { connect, disconnect } = useSocket(`/agents/${agentId}/load_status`);

  useEffect(() => {
    const socket = connect((event) => {
      const data: LoadStatus = JSON.parse(event.data);
      setStatus(data);
      setLoading(false);
    });
    return () => disconnect(socket);
  }, [agentId]);

  const getColorByLoad = (percent: number): string => {
    if (percent < 40) return '#43a047';      // green
    if (percent < 70) return '#fbc02d';      // yellow
    if (percent < 90) return '#fb8c00';      // orange
    return '#e53935';                        // red
  };

  const renderContent = () => {
    if (!status) return null;

    const labelMap = {
      idle: 'Простой',
      stable: 'Стабильно',
      overloaded: 'Перегрузка',
      rebalancing: 'Балансировка…',
    };

    const tooltipContent = (
      <div className="load-tooltip">
        <div><strong>Нагрузка:</strong> {status.loadPercent}%</div>
        <div><strong>Вес агента:</strong> {Math.round(status.weight * 100)}%</div>
        <div><strong>Балансировщик:</strong> {status.assignedBalancer}</div>
        <div><strong>Статус:</strong> {labelMap[status.status]}</div>
        <div><strong>Обновлено:</strong> {new Date(status.timestamp).toLocaleTimeString('ru-RU')}</div>
      </div>
    );

    return (
      <Tooltip content={tooltipContent}>
        <div className="load-indicator">
          <LoadBalancerIcon color={getColorByLoad(status.loadPercent)} />
          <div className="load-status-text">
            {labelMap[status.status]} — {status.loadPercent}%
          </div>
          <ProgressBar
            value={status.loadPercent}
            color={getColorByLoad(status.loadPercent)}
            height={6}
            className="load-bar"
          />
        </div>
      </Tooltip>
    );
  };

  return (
    <div className="agent-load-balancer-indicator">
      {loading ? <Spinner size="small" /> : renderContent()}
    </div>
  );
};
