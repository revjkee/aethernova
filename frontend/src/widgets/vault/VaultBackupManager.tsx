import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { useTheme } from '@/shared/hooks/useTheme';
import { useAuditLog } from '@/services/logging/auditLogger';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { getBackups, createBackup, restoreBackup, deleteBackup } from '@/services/vault/backupService';
import { formatDateTime } from '@/shared/utils/formatDate';
import { Button } from '@/shared/components/Button';
import { Badge } from '@/shared/components/Badge';
import { Alert } from '@/shared/components/Alert';
import { Spinner } from '@/shared/components/Spinner';
import { DataTable } from '@/shared/components/DataTable';
import { ShieldCheck, RotateCcw, Trash2, PlusCircle } from 'lucide-react';
import { Tooltip } from '@/shared/components/Tooltip';

interface BackupItem {
  id: string;
  createdAt: string;
  createdBy: string;
  version: string;
  status: 'valid' | 'corrupted' | 'restored';
  notes?: string;
}

interface VaultBackupManagerProps {
  objectId: string;
  userId: string;
}

export const VaultBackupManager: React.FC<VaultBackupManagerProps> = ({ objectId, userId }) => {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { hasPermission } = useRBAC();
  const { logAction } = useAuditLog();

  const [backups, setBackups] = useState<BackupItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canManageBackups = hasPermission('vault.backup.manage');

  const loadBackups = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getBackups(objectId);
      setBackups(result);
    } catch {
      setError(t('vault.backup.load_error'));
    } finally {
      setLoading(false);
    }
  }, [objectId, t]);

  const handleCreateBackup = async () => {
    setCreating(true);
    try {
      const result = await createBackup(objectId, userId);
      logAction('vault_backup_created', {
        objectId,
        userId,
        version: result.version,
        theme,
      });
      await loadBackups();
    } catch {
      setError(t('vault.backup.create_error'));
    } finally {
      setCreating(false);
    }
  };

  const handleRestore = async (id: string) => {
    try {
      await restoreBackup(objectId, id);
      logAction('vault_backup_restored', { objectId, userId, backupId: id, theme });
      await loadBackups();
    } catch {
      setError(t('vault.backup.restore_error'));
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteBackup(objectId, id);
      logAction('vault_backup_deleted', { objectId, userId, backupId: id, theme });
      await loadBackups();
    } catch {
      setError(t('vault.backup.delete_error'));
    }
  };

  const columns = useMemo(() => [
    {
      key: 'createdAt',
      label: t('vault.backup.created_at'),
      render: (item: BackupItem) => (
        <span className="text-xs text-gray-500">{formatDateTime(item.createdAt)}</span>
      ),
    },
    {
      key: 'version',
      label: t('vault.backup.version'),
      render: (item: BackupItem) => <Badge label={`v${item.version}`} color="blue" />,
    },
    {
      key: 'createdBy',
      label: t('vault.backup.user'),
      render: (item: BackupItem) => (
        <span className="text-sm text-gray-700 dark:text-gray-300">{item.createdBy}</span>
      ),
    },
    {
      key: 'status',
      label: t('vault.backup.status'),
      render: (item: BackupItem) => {
        const colorMap = {
          valid: 'green',
          corrupted: 'red',
          restored: 'yellow',
        };
        return (
          <Badge
            label={t(`vault.backup.status.${item.status}`)}
            color={colorMap[item.status]}
          />
        );
      },
    },
    {
      key: 'actions',
      label: t('vault.backup.actions'),
      render: (item: BackupItem) => (
        <div className="flex gap-2">
          <Tooltip content={t('vault.backup.restore')}>
            <Button
              size="xs"
              variant="ghost"
              icon={<RotateCcw size={16} />}
              onClick={() => handleRestore(item.id)}
              disabled={!canManageBackups}
            />
          </Tooltip>
          <Tooltip content={t('vault.backup.delete')}>
            <Button
              size="xs"
              variant="ghost"
              icon={<Trash2 size={16} />}
              onClick={() => handleDelete(item.id)}
              disabled={!canManageBackups}
            />
          </Tooltip>
        </div>
      ),
    },
  ], [t, canManageBackups]);

  return (
    <motion.div
      className="w-full p-4 border rounded-md bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-700 shadow-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="text-green-600" size={20} />
          <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
            {t('vault.backup.title')}
          </h2>
        </div>
        {canManageBackups && (
          <Button
            size="sm"
            icon={<PlusCircle size={16} />}
            onClick={handleCreateBackup}
            loading={creating}
          >
            {t('vault.backup.create')}
          </Button>
        )}
      </div>

      {error && <Alert type="error" message={error} />}
      {loading ? (
        <Spinner label={t('vault.backup.loading')} />
      ) : (
        <DataTable data={backups} columns={columns} rowKey="id" />
      )}
    </motion.div>
  );
};

export default VaultBackupManager;
