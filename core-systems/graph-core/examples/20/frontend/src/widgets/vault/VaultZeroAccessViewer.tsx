import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { getZeroAccessLogs } from '@/services/security/zeroAccessService';
import { useAuditLog } from '@/services/logging/auditLogger';
import { DataTable } from '@/shared/components/DataTable';
import { Badge } from '@/shared/components/Badge';
import { Spinner } from '@/shared/components/Spinner';
import { Alert } from '@/shared/components/Alert';
import { formatDateTime } from '@/shared/utils/formatDate';
import { ShieldX, EyeOff } from 'lucide-react';
import { motion } from 'framer-motion';
import { useTheme } from '@/shared/hooks/useTheme';
import { useRBAC } from '@/shared/hooks/useRBAC';

interface VaultZeroAccessViewerProps {
  objectId: string;
  userId: string;
}

interface ZeroAccessLogEntry {
  id: string;
  timestamp: string;
  user: {
    id: string;
    name: string;
    role: string;
  };
  attemptedAction: string;
  policyEnforced: string;
  status: 'blocked' | 'alerted' | 'review';
  context: string;
}

export const VaultZeroAccessViewer: React.FC<VaultZeroAccessViewerProps> = ({
  objectId,
  userId,
}) => {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { hasPermission } = useRBAC();
  const { logAction } = useAuditLog();

  const [logs, setLogs] = useState<ZeroAccessLogEntry[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const canViewLogs = hasPermission('vault.logs.view_zero_access');

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await getZeroAccessLogs(objectId);
        setLogs(response);
        logAction('view_zero_access_logs', {
          objectId,
          userId,
          logsCount: response.length,
          theme,
        });
      } catch (err) {
        setError(t('vault.zero_access.fetch_error'));
      } finally {
        setIsLoading(false);
      }
    };

    if (canViewLogs) {
      fetchLogs();
    } else {
      setIsLoading(false);
    }
  }, [objectId, userId, logAction, t, canViewLogs, theme]);

  const columns = useMemo(() => [
    {
      key: 'timestamp',
      label: t('vault.zero_access.time'),
      render: (row: ZeroAccessLogEntry) => (
        <span className="text-xs text-gray-500 dark:text-gray-400">{formatDateTime(row.timestamp)}</span>
      ),
    },
    {
      key: 'user',
      label: t('vault.zero_access.user'),
      render: (row: ZeroAccessLogEntry) => (
        <div>
          <div className="text-sm font-medium">{row.user.name}</div>
          <div className="text-xs text-gray-500">{row.user.role}</div>
        </div>
      ),
    },
    {
      key: 'attemptedAction',
      label: t('vault.zero_access.action'),
      render: (row: ZeroAccessLogEntry) => (
        <span className="text-sm">{row.attemptedAction}</span>
      ),
    },
    {
      key: 'policyEnforced',
      label: t('vault.zero_access.policy'),
      render: (row: ZeroAccessLogEntry) => (
        <Badge color="gray" label={row.policyEnforced} />
      ),
    },
    {
      key: 'status',
      label: t('vault.zero_access.status'),
      render: (row: ZeroAccessLogEntry) => {
        const statusColor = {
          blocked: 'red',
          alerted: 'yellow',
          review: 'blue',
        }[row.status];

        return (
          <Badge color={statusColor} label={t(`vault.zero_access.status.${row.status}`)} />
        );
      },
    },
    {
      key: 'context',
      label: t('vault.zero_access.context'),
      render: (row: ZeroAccessLogEntry) => (
        <span className="text-xs break-words text-gray-600 dark:text-gray-300">{row.context}</span>
      ),
    },
  ], [t]);

  return (
    <motion.div
      className="p-4 rounded-md shadow border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.25 }}
    >
      <div className="flex items-center gap-3 mb-4">
        <ShieldX size={20} className="text-red-500" />
        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">
          {t('vault.zero_access.title')}
        </h2>
      </div>

      {!canViewLogs ? (
        <Alert type="error" message={t('vault.zero_access.no_permission')} />
      ) : isLoading ? (
        <Spinner label={t('vault.zero_access.loading')} />
      ) : error ? (
        <Alert type="error" message={error} />
      ) : logs.length === 0 ? (
        <Alert type="info" message={t('vault.zero_access.no_logs')} />
      ) : (
        <DataTable
          data={logs}
          columns={columns}
          rowKey="id"
          className="text-sm"
        />
      )}
    </motion.div>
  );
};

export default VaultZeroAccessViewer;
