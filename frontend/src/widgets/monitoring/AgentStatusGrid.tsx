import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { fetchAgentStatuses } from '@/services/monitoring/agentService';
import { Badge } from '@/shared/components/Badge';
import { Alert } from '@/shared/components/Alert';
import { Spinner } from '@/shared/components/Spinner';
import { FilterInput } from '@/shared/components/FilterInput';
import { AgentStatusCard } from '@/shared/components/AgentStatusCard';
import { RefreshCcw, Group, Zap } from 'lucide-react';
import clsx from 'clsx';

interface AgentStatus {
  id: string;
  name: string;
  status: 'online' | 'degraded' | 'offline' | 'booting' | 'suspended';
  role: string;
  namespace: string;
  cpuLoad: number;
  memoryUsage: number;
  heartbeatAt: string;
  lastError?: string;
  agentType?: 'worker' | 'coordinator' | 'sentinel';
}

export const AgentStatusGrid: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();

  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [groupBy, setGroupBy] = useState<'namespace' | 'role'>('namespace');

  const canView = hasPermission('monitoring.agents.view');

  const refreshAgents = async () => {
    setLoading(true);
    try {
      const result = await fetchAgentStatuses();
      setAgents(result);
    } catch {
      setError(t('monitoring.agents.error_loading'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (canView) refreshAgents();
    const interval = setInterval(refreshAgents, 15000); // 15s auto-refresh
    return () => clearInterval(interval);
  }, [canView]);

  const filtered = useMemo(() => {
    return agents.filter((a) =>
      a.name.toLowerCase().includes(filter.toLowerCase()) ||
      a.role.toLowerCase().includes(filter.toLowerCase()) ||
      a.namespace.toLowerCase().includes(filter.toLowerCase())
    );
  }, [agents, filter]);

  const grouped = useMemo(() => {
    return filtered.reduce<Record<string, AgentStatus[]>>((acc, agent) => {
      const key = groupBy === 'namespace' ? agent.namespace : agent.role;
      if (!acc[key]) acc[key] = [];
      acc[key].push(agent);
      return acc;
    }, {});
  }, [filtered, groupBy]);

  if (!canView) return null;

  return (
    <motion.div
      className="p-6 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg shadow-md"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div className="flex items-center gap-2">
          <Zap size={18} className="text-yellow-500" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">
            {t('monitoring.agents.title')}
          </h2>
        </div>
        <div className="flex gap-2 items-center">
          <FilterInput value={filter} onChange={setFilter} placeholder={t('monitoring.agents.search')} />
          <button
            onClick={() => setGroupBy(groupBy === 'namespace' ? 'role' : 'namespace')}
            className="text-sm text-blue-600 hover:underline flex items-center gap-1"
          >
            <Group size={14} /> {t('monitoring.agents.group_by')} {groupBy === 'namespace' ? 'Role' : 'Namespace'}
          </button>
          <button
            onClick={refreshAgents}
            className="text-sm text-green-600 hover:underline flex items-center gap-1"
          >
            <RefreshCcw size={14} /> {t('common.refresh')}
          </button>
        </div>
      </div>

      {error && <Alert type="error" message={error} />}
      {loading ? (
        <Spinner label={t('monitoring.agents.loading')} />
      ) : (
        <div className="space-y-6">
          {Object.entries(grouped).map(([group, agents]) => (
            <div key={group}>
              <div className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                {groupBy === 'namespace' ? t('monitoring.agents.namespace') : t('monitoring.agents.role')}: {group}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {agents.map((agent) => (
                  <AgentStatusCard key={agent.id} agent={agent} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </motion.div>
  );
};

export default AgentStatusGrid;
