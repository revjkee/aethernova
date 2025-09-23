import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { getLatencyMatrix } from '@/services/monitoring/latencyService';
import { Spinner } from '@/shared/components/Spinner';
import { Alert } from '@/shared/components/Alert';
import { LatencyCell } from '@/shared/components/LatencyCell';
import { useRBAC } from '@/shared/hooks/useRBAC';
import clsx from 'clsx';

interface LatencyEntry {
  source: string;
  target: string;
  latencyMs: number;
  deviation: number; // AI-deviation score
  trustLevel: number; // 0-100
  status: 'normal' | 'warning' | 'critical' | 'offline';
}

export const LatencyMap: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const [matrix, setMatrix] = useState<LatencyEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const canView = hasPermission('monitoring.latency.view');

  const loadMatrix = async () => {
    try {
      setLoading(true);
      const result = await getLatencyMatrix();
      setMatrix(result);
    } catch (err) {
      setError(t('monitoring.latency.load_error'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (canView) {
      loadMatrix();
      const interval = setInterval(loadMatrix, 10000);
      return () => clearInterval(interval);
    }
  }, [canView]);

  const allNodes = Array.from(
    new Set(matrix.flatMap(entry => [entry.source, entry.target]))
  ).sort();

  const buildCell = (src: string, tgt: string) => {
    const entry = matrix.find(e => e.source === src && e.target === tgt);
    if (!entry) return <td key={`${src}-${tgt}`} className="bg-gray-100 dark:bg-gray-800" />;
    return (
      <LatencyCell
        key={`${src}-${tgt}`}
        latency={entry.latencyMs}
        status={entry.status}
        trust={entry.trustLevel}
        deviation={entry.deviation}
      />
    );
  };

  if (!canView) return null;

  return (
    <motion.div
      ref={containerRef}
      className="w-full overflow-auto p-4 border rounded-lg bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-700"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <div className="text-lg font-semibold mb-4 text-gray-800 dark:text-white">
        {t('monitoring.latency.title')}
      </div>

      {error && <Alert type="error" message={error} />}
      {loading ? (
        <Spinner label={t('monitoring.latency.loading')} />
      ) : (
        <table className="table-auto border-collapse">
          <thead>
            <tr>
              <th className="sticky left-0 bg-gray-50 dark:bg-gray-800 z-10 p-2 text-sm text-left text-gray-600 dark:text-gray-300">
                /
              </th>
              {allNodes.map((node) => (
                <th key={node} className="p-2 text-xs text-gray-600 dark:text-gray-300 whitespace-nowrap">
                  {node}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {allNodes.map((rowNode) => (
              <tr key={rowNode}>
                <td className="sticky left-0 z-10 bg-gray-50 dark:bg-gray-800 p-2 text-xs text-gray-700 dark:text-gray-300 font-medium whitespace-nowrap">
                  {rowNode}
                </td>
                {allNodes.map((colNode) => buildCell(rowNode, colNode))}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </motion.div>
  );
};

export default LatencyMap;
