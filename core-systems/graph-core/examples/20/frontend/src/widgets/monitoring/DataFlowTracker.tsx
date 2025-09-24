import React, { useEffect, useState, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { Alert } from '@/shared/components/Alert';
import { Spinner } from '@/shared/components/Spinner';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { fetchDataFlows } from '@/services/monitoring/dataFlowService';
import { FlowNode } from '@/shared/components/FlowNode';
import { FlowLink } from '@/shared/components/FlowLink';
import { AutoLayoutEngine } from '@/shared/utils/layoutEngine';
import { AiDeviationBadge } from '@/shared/components/AiDeviationBadge';
import { DataTypeIcon } from '@/shared/components/DataTypeIcon';
import clsx from 'clsx';

interface DataFlow {
  id: string;
  source: string;
  target: string;
  inputRate: number; // bytes/sec
  outputRate: number; // bytes/sec
  dataType: 'json' | 'stream' | 'binary' | 'log' | 'video';
  latency: number; // ms
  aiDeviation?: string;
  confidence?: number; // 0..1
}

interface Position {
  x: number;
  y: number;
}

export const DataFlowTracker: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const [flows, setFlows] = useState<DataFlow[]>([]);
  const [positions, setPositions] = useState<Record<string, Position>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const canvasRef = useRef<HTMLDivElement>(null);

  const canView = hasPermission('monitoring.dataflow.view');

  const loadFlows = async () => {
    try {
      setLoading(true);
      const result = await fetchDataFlows();
      setFlows(result);
    } catch {
      setError(t('monitoring.dataflow.error_loading'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (canView) loadFlows();
    const interval = setInterval(loadFlows, 10000);
    return () => clearInterval(interval);
  }, [canView]);

  useEffect(() => {
    const nodes = new Set<string>();
    flows.forEach(f => {
      nodes.add(f.source);
      nodes.add(f.target);
    });
    const layout = AutoLayoutEngine([...nodes]);
    setPositions(layout);
  }, [flows]);

  if (!canView) return null;

  return (
    <motion.div
      className="relative h-[800px] w-full bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <div className="absolute top-4 left-4 z-10 text-lg font-semibold text-gray-800 dark:text-white">
        {t('monitoring.dataflow.title')}
      </div>

      {error && <Alert type="error" message={error} />}
      {loading ? (
        <Spinner label={t('monitoring.dataflow.loading')} />
      ) : (
        <div ref={canvasRef} className="absolute inset-0">
          {flows.map((flow, idx) => (
            <FlowLink
              key={flow.id}
              from={positions[flow.source]}
              to={positions[flow.target]}
              rateIn={flow.inputRate}
              rateOut={flow.outputRate}
              latency={flow.latency}
              critical={flow.latency > 250}
              type={flow.dataType}
            />
          ))}

          {Object.entries(positions).map(([nodeId, pos]) => (
            <FlowNode key={nodeId} id={nodeId} position={pos}>
              <div className="flex items-center gap-1">
                <DataTypeIcon type="stream" />
                <span className="text-sm font-medium">{nodeId}</span>
              </div>
              {flows.some(f => (f.source === nodeId || f.target === nodeId) && f.aiDeviation) && (
                <AiDeviationBadge label="AI anomaly" />
              )}
            </FlowNode>
          ))}
        </div>
      )}
    </motion.div>
  );
};

export default DataFlowTracker;
