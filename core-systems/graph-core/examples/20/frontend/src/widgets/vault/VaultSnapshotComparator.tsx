import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { useAuditLog } from '@/services/logging/auditLogger';
import { compareSnapshots } from '@/services/vault/snapshotService';
import { Spinner } from '@/shared/components/Spinner';
import { Alert } from '@/shared/components/Alert';
import { DataTable } from '@/shared/components/DataTable';
import { Badge } from '@/shared/components/Badge';
import { Tooltip } from '@/shared/components/Tooltip';
import { Filter, Eye, ShieldAlert } from 'lucide-react';

interface SnapshotDiff {
  field: string;
  oldValue: string | null;
  newValue: string | null;
  changeType: 'added' | 'removed' | 'modified';
  section: 'keys' | 'policies' | 'metadata' | 'system';
  severity: 'low' | 'medium' | 'high';
  explanation?: string;
}

interface VaultSnapshotComparatorProps {
  fromSnapshotId: string;
  toSnapshotId: string;
  objectId: string;
  userId?: string;
}

export const VaultSnapshotComparator: React.FC<VaultSnapshotComparatorProps> = ({
  fromSnapshotId,
  toSnapshotId,
  objectId,
  userId = 'unknown',
}) => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const { logAction } = useAuditLog();

  const [diffs, setDiffs] = useState<SnapshotDiff[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const canCompare = hasPermission('vault.snapshot.compare');

  const fetchDiffs = useCallback(async () => {
    setLoading(true);
    try {
      const result = await compareSnapshots(objectId, fromSnapshotId, toSnapshotId);
      setDiffs(result);
      logAction('vault_snapshots_compared', {
        fromSnapshotId,
        toSnapshotId,
        objectId,
        userId,
        diffCount: result.length,
      });
    } catch {
      setError(t('vault.snapshot.diff_error'));
    } finally {
      setLoading(false);
    }
  }, [objectId, fromSnapshotId, toSnapshotId, userId, logAction, t]);

  useEffect(() => {
    if (canCompare) fetchDiffs();
    else setLoading(false);
  }, [canCompare, fetchDiffs]);

  const columns = useMemo(() => [
    {
      key: 'field',
      label: t('vault.snapshot.field'),
      render: (d: SnapshotDiff) => (
        <span className="font-mono text-xs text-blue-700 dark:text-blue-300">{d.field}</span>
      ),
    },
    {
      key: 'changeType',
      label: t('vault.snapshot.change'),
      render: (d: SnapshotDiff) => {
        const colorMap = {
          added: 'green',
          removed: 'red',
          modified: 'yellow',
        };
        return (
          <Badge
            label={t(`vault.snapshot.${d.changeType}`)}
            color={colorMap[d.changeType]}
          />
        );
      },
    },
    {
      key: 'section',
      label: t('vault.snapshot.section'),
      render: (d: SnapshotDiff) => (
        <Badge label={d.section} color="gray" />
      ),
    },
    {
      key: 'oldValue',
      label: t('vault.snapshot.old'),
      render: (d: SnapshotDiff) =>
        d.oldValue ? <span className="text-red-600 dark:text-red-400">{d.oldValue}</span> : '-',
    },
    {
      key: 'newValue',
      label: t('vault.snapshot.new'),
      render: (d: SnapshotDiff) =>
        d.newValue ? <span className="text-green-600 dark:text-green-400">{d.newValue}</span> : '-',
    },
    {
      key: 'severity',
      label: t('vault.snapshot.severity'),
      render: (d: SnapshotDiff) => {
        const colors = {
          low: 'green',
          medium: 'orange',
          high: 'red',
        };
        return <Badge label={d.severity} color={colors[d.severity]} />;
      },
    },
    {
      key: 'explanation',
      label: t('vault.snapshot.reason'),
      render: (d: SnapshotDiff) => (
        <Tooltip content={d.explanation || t('vault.snapshot.no_reason')}>
          <Eye size={14} className="text-gray-500 dark:text-gray-300 cursor-pointer" />
        </Tooltip>
      ),
    },
  ], [t]);

  if (!canCompare) return null;

  return (
    <motion.div
      className="p-4 border rounded-md bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-700 shadow-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center gap-2 mb-4">
        <ShieldAlert className="text-yellow-600" size={18} />
        <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100">
          {t('vault.snapshot.compare_title')}
        </h3>
      </div>

      {error && <Alert type="error" message={error} />}
      {loading ? (
        <Spinner label={t('vault.snapshot.loading')} />
      ) : (
        <DataTable data={diffs} columns={columns} rowKey="field" />
      )}
    </motion.div>
  );
};

export default VaultSnapshotComparator;
