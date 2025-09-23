import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, AlertCircle, ShieldX, Lock, Loader } from 'lucide-react';
import { Tooltip } from '@/shared/components/Tooltip';
import { Badge } from '@/shared/components/Badge';
import { classNames } from '@/shared/utils/classNames';
import { useAuditLog } from '@/services/logging/auditLogger';
import { getComplianceStatus } from '@/services/compliance/complianceService';
import { motion } from 'framer-motion';
import { useTheme } from '@/shared/hooks/useTheme';
import { useRBAC } from '@/shared/hooks/useRBAC';

export type ComplianceStatus = 'compliant' | 'partial' | 'non_compliant' | 'checking' | 'unknown';

interface ComplianceFlag {
  code: string;
  label: string;
  status: ComplianceStatus;
  description: string;
}

interface VaultComplianceIndicatorProps {
  objectId: string;
  userId?: string;
  compact?: boolean;
  context?: string;
}

export const VaultComplianceIndicator: React.FC<VaultComplianceIndicatorProps> = ({
  objectId,
  userId = 'unknown',
  compact = false,
  context = 'vault',
}) => {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { hasPermission } = useRBAC();
  const { logAction } = useAuditLog();

  const [flags, setFlags] = useState<ComplianceFlag[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const canView = hasPermission('vault.view.compliance');

  const icons: Record<ComplianceStatus, JSX.Element> = {
    compliant: <ShieldCheck className="text-green-600" size={16} />,
    partial: <AlertCircle className="text-yellow-600" size={16} />,
    non_compliant: <ShieldX className="text-red-600" size={16} />,
    checking: <Loader className="animate-spin text-blue-500" size={16} />,
    unknown: <Lock className="text-gray-500" size={16} />,
  };

  useEffect(() => {
    const fetchCompliance = async () => {
      try {
        const result = await getComplianceStatus(objectId);
        setFlags(result);
        logAction('vault_compliance_checked', {
          objectId,
          userId,
          flagsCount: result.length,
          context,
          theme,
        });
      } catch (e) {
        setError(t('vault.compliance.fetch_error'));
      } finally {
        setLoading(false);
      }
    };

    if (canView) {
      fetchCompliance();
    } else {
      setLoading(false);
    }
  }, [objectId, userId, context, theme, logAction, t, canView]);

  const statusColors: Record<ComplianceStatus, string> = {
    compliant: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    partial: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
    non_compliant: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
    checking: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
    unknown: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
  };

  if (!canView) return null;

  return (
    <motion.div
      className={classNames(
        'w-full border rounded-md p-4 shadow-sm bg-white dark:bg-gray-900',
        loading ? 'opacity-50' : 'opacity-100'
      )}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.25 }}
    >
      <div className="mb-3">
        <h4 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
          {t('vault.compliance.title')}
        </h4>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          {t('vault.compliance.description')}
        </p>
      </div>

      {error ? (
        <div className="text-red-500 text-sm">{error}</div>
      ) : loading ? (
        <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
          <Loader className="animate-spin" size={16} />
          {t('vault.compliance.checking')}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
          {flags.map((flag) => (
            <Tooltip key={flag.code} content={flag.description}>
              <div
                className={classNames(
                  'flex items-center gap-2 text-xs px-3 py-2 rounded-md border',
                  statusColors[flag.status],
                  'border-transparent'
                )}
                role="status"
                aria-label={`Compliance ${flag.code} - ${flag.status}`}
              >
                {icons[flag.status]}
                {!compact && (
                  <span className="font-medium uppercase">{flag.code}</span>
                )}
              </div>
            </Tooltip>
          ))}
        </div>
      )}
    </motion.div>
  );
};

export default VaultComplianceIndicator;
