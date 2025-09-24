import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, ShieldX, Loader, LockKeyhole } from 'lucide-react';
import { Tooltip } from '@/shared/components/Tooltip';
import { classNames } from '@/shared/utils/classNames';
import { checkHSMStatus } from '@/services/security/hsmService';
import { useTheme } from '@/shared/hooks/useTheme';
import { useAuditLog } from '@/services/logging/auditLogger';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { motion } from 'framer-motion';

export type HSMStatus = 'connected' | 'disconnected' | 'error' | 'verifying' | 'unsupported';

interface HSMIntegrationBadgeProps {
  objectId?: string;
  compact?: boolean;
  showLabel?: boolean;
  roleContext?: string;
}

export const HSMIntegrationBadge: React.FC<HSMIntegrationBadgeProps> = ({
  objectId,
  compact = false,
  showLabel = true,
  roleContext = 'viewer',
}) => {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { logAction } = useAuditLog();
  const { hasPermission } = useRBAC();

  const [status, setStatus] = useState<HSMStatus>('verifying');
  const [hasAccess, setHasAccess] = useState(false);

  const statusMeta = useMemo(() => ({
    connected: {
      label: t('vault.hsm.connected'),
      icon: <ShieldCheck className="text-green-600" size={compact ? 14 : 18} />,
      color: 'text-green-700 dark:text-green-400',
      bg: 'bg-green-50 dark:bg-green-900',
      border: 'border-green-200 dark:border-green-700',
    },
    disconnected: {
      label: t('vault.hsm.disconnected'),
      icon: <ShieldX className="text-gray-500" size={compact ? 14 : 18} />,
      color: 'text-gray-600 dark:text-gray-400',
      bg: 'bg-gray-100 dark:bg-gray-800',
      border: 'border-gray-300 dark:border-gray-700',
    },
    error: {
      label: t('vault.hsm.error'),
      icon: <ShieldX className="text-red-600" size={compact ? 14 : 18} />,
      color: 'text-red-700 dark:text-red-400',
      bg: 'bg-red-100 dark:bg-red-900',
      border: 'border-red-300 dark:border-red-700',
    },
    verifying: {
      label: t('vault.hsm.verifying'),
      icon: <Loader className="animate-spin text-blue-500" size={compact ? 14 : 18} />,
      color: 'text-blue-600 dark:text-blue-300',
      bg: 'bg-blue-50 dark:bg-blue-900',
      border: 'border-blue-200 dark:border-blue-700',
    },
    unsupported: {
      label: t('vault.hsm.unsupported'),
      icon: <LockKeyhole className="text-yellow-500" size={compact ? 14 : 18} />,
      color: 'text-yellow-700 dark:text-yellow-300',
      bg: 'bg-yellow-50 dark:bg-yellow-900',
      border: 'border-yellow-300 dark:border-yellow-700',
    },
  }[status]), [status, t, compact]);

  useEffect(() => {
    const verify = async () => {
      try {
        const result = await checkHSMStatus(objectId);
        setStatus(result.status as HSMStatus);
        setHasAccess(result.accessGranted || false);

        logAction('vault_hsm_status_check', {
          objectId: objectId ?? 'unknown',
          status: result.status,
          context: roleContext,
          theme,
          quantumSafe: result.quantumSafe ?? false,
        });
      } catch {
        setStatus('error');
      }
    };

    verify();
  }, [objectId, logAction, theme, roleContext]);

  if (!hasPermission('vault.view.hsm') && !hasAccess) return null;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.2 }}
      className={classNames(
        'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border',
        statusMeta.bg,
        statusMeta.color,
        statusMeta.border
      )}
      role="status"
      aria-label={`HSM Status: ${status}`}
    >
      <Tooltip content={statusMeta.label}>
        <div className="flex items-center gap-1">
          {statusMeta.icon}
          {showLabel && <span>{statusMeta.label}</span>}
        </div>
      </Tooltip>
    </motion.div>
  );
};

export default HSMIntegrationBadge;
