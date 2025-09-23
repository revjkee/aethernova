import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { fetchSystemMetrics } from '@/services/monitoring/systemMetricsService';
import { formatBytes, formatUptime } from '@/shared/utils/formatters';
import { SparklineChart } from '@/shared/components/SparklineChart';
import { Badge } from '@/shared/components/Badge';
import { Alert } from '@/shared/components/Alert';
import { Spinner } from '@/shared/components/Spinner';
import { AIInsightCard } from '@/shared/components/AIInsightCard';
import { ShieldCheck, Cpu, Server, Activity, Clock, Cloud } from 'lucide-react';

interface Metric {
  label: string;
  value: number | string;
  unit?: string;
  icon: React.ReactNode;
  severity?: 'ok' | 'warn' | 'critical';
  trend?: number[];
}

export const SystemOverviewPanel: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();

  const [metrics, setMetrics] = useState<Metric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [aiInsights, setAiInsights] = useState<string[]>([]);

  const canView = hasPermission('monitoring.system.view');

  const fetchMetrics = async () => {
    setLoading(true);
    try {
      const result = await fetchSystemMetrics();
      setMetrics([
        {
          label: 'CPU',
          value: `${result.cpu.usage}%`,
          icon: <Cpu size={16} />,
          severity: result.cpu.usage > 90 ? 'critical' : result.cpu.usage > 75 ? 'warn' : 'ok',
          trend: result.cpu.history,
        },
        {
          label: 'RAM',
          value: `${result.ram.used}%`,
          icon: <Server size={16} />,
          severity: result.ram.used > 90 ? 'critical' : result.ram.used > 75 ? 'warn' : 'ok',
          trend: result.ram.history,
        },
        {
          label: 'Uptime',
          value: formatUptime(result.uptime),
          icon: <Clock size={16} />,
        },
        {
          label: 'Network',
          value: `${formatBytes(result.network.tx)}/${formatBytes(result.network.rx)}`,
          icon: <Activity size={16} />,
          trend: result.network.history,
        },
        {
          label: 'AI Agents',
          value: result.aiAgents.active,
          icon: <Cloud size={16} />,
        },
      ]);
      setAiInsights(result.aiInsights || []);
    } catch {
      setError(t('monitoring.system.error_loading'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (canView) fetchMetrics();
  }, [canView]);

  const getBadgeColor = (severity: Metric['severity']) => {
    switch (severity) {
      case 'critical': return 'red';
      case 'warn': return 'yellow';
      case 'ok': return 'green';
      default: return 'gray';
    }
  };

  if (!canView) return null;

  return (
    <motion.div
      className="w-full border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 p-6 rounded-md shadow-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center gap-2 mb-4">
        <ShieldCheck className="text-blue-500" size={18} />
        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-100">
          {t('monitoring.system.overview')}
        </h2>
      </div>

      {error && <Alert type="error" message={error} />}
      {loading ? (
        <Spinner label={t('monitoring.system.loading')} />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 mb-6">
          {metrics.map((metric, idx) => (
            <div
              key={idx}
              className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 p-4 rounded-md flex flex-col gap-2 shadow-sm"
            >
              <div className="flex items-center justify-between">
                <div className="flex gap-2 items-center text-sm text-gray-700 dark:text-gray-300">
                  {metric.icon}
                  {metric.label}
                </div>
                {metric.severity && (
                  <Badge color={getBadgeColor(metric.severity)} label={metric.severity.toUpperCase()} />
                )}
              </div>
              <div className="text-xl font-bold text-gray-900 dark:text-white">
                {metric.value}
              </div>
              {metric.trend && <SparklineChart data={metric.trend} />}
            </div>
          ))}
        </div>
      )}

      {aiInsights.length > 0 && (
        <div className="mt-4">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-2">
            {t('monitoring.system.ai_insights')}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {aiInsights.map((insight, idx) => (
              <AIInsightCard key={idx} message={insight} />
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
};

export default SystemOverviewPanel;
