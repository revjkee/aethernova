import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { getNodeHealthMetrics } from '@/services/monitoring/nodeService';
import { Alert } from '@/shared/components/Alert';
import { Spinner } from '@/shared/components/Spinner';
import { TrustMeter } from '@/shared/components/TrustMeter';
import { SparklineChart } from '@/shared/components/SparklineChart';
import { Badge } from '@/shared/components/Badge';
import { formatBytes, formatUptime } from '@/shared/utils/formatters';
import clsx from 'clsx';

interface NodeMetric {
  id: string;
  name: string;
  region: string;
  zone: string;
  uptime: number;
  cpu: number;
  memory: number;
  status: 'healthy' | 'warning' | 'critical' | 'offline';
  heartbeat: string;
  networkTx: number;
  networkRx: number;
  trustScore: number;
  cpuHistory: number[];
  memHistory: number[];
  aiDeviation?: string;
}

export const NodeHealthMeter: React.FC = () => {
  const { t } = useTranslation();
  const [nodes, setNodes] = useState<NodeMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadMetrics = async () => {
    try {
      setLoading(true);
      const result = await getNodeHealthMetrics();
      setNodes(result);
    } catch (err) {
      setError(t('monitoring.nodes.load_error'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMetrics();
    const interval = setInterval(loadMetrics, 20000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: NodeMetric['status']) => {
    switch (status) {
      case 'healthy': return 'green';
      case 'warning': return 'yellow';
      case 'critical': return 'red';
      case 'offline': return 'gray';
    }
  };

  return (
    <motion.div
      className="w-full p-6 bg-white dark:bg-gray-900 rounded-lg border border-gray-300 dark:border-gray-700 shadow-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <div className="flex items-center gap-2 mb-6">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-white">
          {t('monitoring.nodes.title')}
        </h2>
      </div>

      {error && <Alert type="error" message={error} />}
      {loading ? (
        <Spinner label={t('monitoring.nodes.loading')} />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {nodes.map((node) => (
            <div
              key={node.id}
              className={clsx(
                'p-4 rounded-md border shadow-md flex flex-col gap-2 bg-gray-50 dark:bg-gray-800',
                `border-${getStatusColor(node.status)}-500`
              )}
            >
              <div className="flex justify-between items-center">
                <div className="text-sm font-medium text-gray-700 dark:text-gray-200">
                  {node.name}
                </div>
                <Badge color={getStatusColor(node.status)} label={node.status.toUpperCase()} />
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">
                {t('monitoring.nodes.zone')}: {node.region}/{node.zone}
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">
                {t('monitoring.nodes.uptime')}: {formatUptime(node.uptime)}
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">
                {t('monitoring.nodes.heartbeat')}: {new Date(node.heartbeat).toLocaleTimeString()}
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-sm text-gray-700 dark:text-gray-200">
                  CPU: {node.cpu.toFixed(1)}%
                </span>
                <SparklineChart data={node.cpuHistory} color={getStatusColor(node.status)} />
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-sm text-gray-700 dark:text-gray-200">
                  RAM: {node.memory.toFixed(1)}%
                </span>
                <SparklineChart data={node.memHistory} color={getStatusColor(node.status)} />
              </div>
              <div className="text-xs text-gray-600 dark:text-gray-300">
                TX: {formatBytes(node.networkTx)} / RX: {formatBytes(node.networkRx)}
              </div>
              <div className="pt-2">
                <TrustMeter score={node.trustScore} />
              </div>
              {node.aiDeviation && (
                <div className="text-xs mt-2 text-red-500 font-medium">
                  AI: {node.aiDeviation}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </motion.div>
  );
};

export default NodeHealt
