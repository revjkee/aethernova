import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { useAuditLog } from '@/services/logging/auditLogger';
import { useTheme } from '@/shared/hooks/useTheme';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { getVaultAnomalies } from '@/services/ai/anomalyDetectionService';
import { Alert } from '@/shared/components/Alert';
import { Badge } from '@/shared/components/Badge';
import { DataTable } from '@/shared/components/DataTable';
import { formatDateTime } from '@/shared/utils/formatDate';
import { ShieldX, ShieldAlert, Eye, ArrowRight } from 'lucide-react';
import { Tooltip } from '@/shared/components/Tooltip';
import { Spinner } from '@/shared/components/Spinner';

type AnomalySeverity = 'low' | 'medium' | 'high';
type AnomalyStatus = 'unreviewed' | 'escalated' | 'ignored';

interface VaultAnomaly {
  id: string;
  timestamp: string;
  user: {
    id: string;
    name: string;
    role: string;
  };
  keyId: string;
  description: string;
  severity: AnomalySeverity;
  modelReasoning: string;
  status: AnomalyStatus;
}

interface VaultAnomalyDetectorProps {
  objectId: string;
  userId?: string;
}

export const VaultAnomalyDetector: React.FC<VaultAnomalyDetectorProps> = ({
  objectId,
  userId = 'unknown',
}) => {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { hasPermission } = useRBAC();
  const { logAction } = useAuditLog();

  const [anomalies, setAnomalies] = useState<VaultAnomaly[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const canView = hasPermission('vault.anomaly.view');

  useEffect(() => {
    const fetch = async () => {
      try {
        const result = await getVaultAnomalies(objectId);
        setAnomalies(result);
        logAction('vault_anomalies_viewed', {
          objectId,
          userId,
          anomalyCount: result.length,
          theme,
        });
      } catch {
        setError(t('vault.anomalies.error_fetching'));
      } finally {
        setLoading(false);
      }
    };

    if (canView) fetch();
    else setLoading(false);
  }, [canView, objectId, userId, logAction, theme, t]);

  const columns = useMemo(() => [
    {
      key: 'timestamp',
      label: t('vault.anomalies.time'),
      render: (a: VaultAnomaly) => (
        <span className="text-xs text-gray-500 dark:text-gray-400">{formatDateTime(a.timestamp)}</span>
      ),
    },
    {
      key: 'user',
      label: t('vault.anomalies.user'),
      render: (a: VaultAnomaly) => (
        <div className="flex flex-col">
          <span className="text-sm font-medium">{a.user.name}</span>
          <span className="text-xs text-gray-500">{a.user.role}</span>
        </div>
      ),
    },
    {
      key: 'keyId',
      label: t('vault.anomalies.key'),
      render: (a: VaultAnomaly) => (
        <Badge label={a.keyId} color="blue" />
      ),
    },
    {
      key: 'severity',
      label: t('vault.anomalies.severity'),
      render: (a: VaultAnomaly) => {
        const colorMap = {
          low: 'green',
          medium: 'yellow',
          high: 'red',
        };
        return <Badge label={t(`vault.anomalies.level.${a.severity}`)} color={colorMap[a.severity]} />;
      },
    },
    {
      key: 'status',
      label: t('vault.anomalies.status'),
      render: (a: VaultAnomaly) => {
        const colorMap = {
          unreviewed: 'gray',
          escalated: 'red',
          ignored: 'blue',
        };
        return <Badge label={t(`vault.anomalies.status.${a.status}`)} color={colorMap[a.status]} />;
      },
    },
    {
      key: 'modelReasoning',
      label: t('vault.anomalies.reason'),
      render: (a: VaultAnomaly) => (
        <Tooltip content={a.modelReasoning}>
          <div className="text-xs text-gray-600 dark:text-gray-300 line-clamp-2 max-w-sm">
            {a.modelReasoning}
          </div>
        </Tooltip>
      ),
    },
  ], [t]);

  return (
    <motion.div
      className="p-4 border border-gray-300 dark:border-gray-700 rounded-md bg-white dark:bg-gray-900 shadow-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center gap-2 mb-3">
        <ShieldAlert size={18} className="text-orange-500" />
        <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
          {t('vault.anomalies.title')}
        </h3>
      </div>

      {error && <Alert type="error" message={error} />}
      {loading ? (
        <Spinner label={t('vault.anomalies.loading')} />
      ) : anomalies.length === 0 ? (
        <Alert type="info" message={t('vault.anomalies.none_found')} />
      ) : (
        <DataTable
          data={anomalies}
          columns={columns}
          rowKey="id"
          className="text-sm"
        />
      )}
    </motion.div>
  );
};

export default VaultAnomalyDetector;
