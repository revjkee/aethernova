import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { getAgentHeartbeatStatus } from '@/services/monitoring/agentService';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { Tooltip } from '@/shared/components/Tooltip';
import { PulseIcon, AlertCircleIcon, CheckCircleIcon } from 'lucide-react';
import clsx from 'clsx';

interface HeartbeatInfo {
  agentId: string;
  status: 'alive' | 'delayed' | 'missing' | 'unreachable';
  lastSeen: string;
  latencyMs: number;
  trustScore: number; // 0-100
  deviation: number;  // AI-calculated
  critical: boolean;
}

interface Props {
  agentId: string;
  compact?: boolean;
}

export const AgentHeartbeatIndicator: React.FC<Props> = ({ agentId, compact = false }) => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const [data, setData] = useState<HeartbeatInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canView = hasPermission('monitoring.agents.heartbeat');

  const fetchStatus = async () => {
    try {
      const result = await getAgentHeartbeatStatus(agentId);
      setData(result);
    } catch (err) {
      setError(t('monitoring.agent.error_loading'));
    }
  };

  useEffect(() => {
    if (!canView) return;
    fetchStatus();
    const interval = setInterval(fetchStatus, 10000);
    return () => clearInterval(interval);
  }, [agentId, canView]);

  if (!canView || !data) return null;

  const statusColor = {
    alive: 'text-green-500',
    delayed: 'text-yellow-400',
    missing: 'text-red-600',
    unreachable: 'text-gray-500',
  }[data.status];

  const statusIcon = {
    alive: <CheckCircleIcon size={16} />,
    delayed: <PulseIcon size={16} />,
    missing: <AlertCircleIcon size={16} />,
    unreachable: <AlertCircleIcon size={16} />,
  }[data.status];

  const label = t(`monitoring.agent.status.${data.status}`);

  return (
    <motion.div
      className={clsx(
        'flex items-center space-x-2',
        data.critical && 'animate-pulse'
      )}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <Tooltip
        content={
          <div className="text-sm space-y-1">
            <div>{t('monitoring.agent.last_seen')}: {new Date(data.lastSeen).toLocaleString()}</div>
            <div>{t('monitoring.agent.latency')}: {data.latencyMs}ms</div>
            <div>{t('monitoring.agent.trust')}: {data.trustScore}/100</div>
            <div>{t('monitoring.agent.deviation')}: {data.deviation.toFixed(2)}</div>
          </div>
        }
      >
        <div
          className={clsx(
            'flex items-center gap-1 px-2 py-1 rounded-md',
            'text-xs font-medium',
            statusColor,
            'bg-black/10 dark:bg-white/10'
          )}
        >
          {statusIcon}
          {!compact && <span>{label}</span>}
        </div>
      </Tooltip>
    </motion.div>
  );
};

export default AgentHeartbeatIndicator;
