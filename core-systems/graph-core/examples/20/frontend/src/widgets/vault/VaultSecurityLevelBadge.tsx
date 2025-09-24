import React, { useMemo } from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, Shield } from 'lucide-react';
import { Tooltip } from '@/shared/components/Tooltip';
import { classNames } from '@/shared/utils/classNames';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { auditLogAction } from '@/services/logging/auditLogger';
import { useTheme } from '@/shared/hooks/useTheme';

export type SecurityLevel = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

interface VaultSecurityLevelBadgeProps {
  level: SecurityLevel;
  objectId: string;
  displayLabel?: boolean;
  auditContext?: string;
}

const levelConfig: Record<
  SecurityLevel,
  {
    label: string;
    icon: React.ReactNode;
    color: string;
    bgColor: string;
    border: string;
  }
> = {
  low: {
    label: 'Low',
    icon: <Shield className="text-gray-600" size={16} />,
    color: 'text-gray-700 dark:text-gray-300',
    bgColor: 'bg-gray-100 dark:bg-gray-800',
    border: 'border border-gray-300 dark:border-gray-700',
  },
  medium: {
    label: 'Medium',
    icon: <ShieldCheck className="text-blue-600" size={16} />,
    color: 'text-blue-700 dark:text-blue-300',
    bgColor: 'bg-blue-100 dark:bg-blue-900',
    border: 'border border-blue-300 dark:border-blue-700',
  },
  high: {
    label: 'High',
    icon: <ShieldAlert className="text-orange-600" size={16} />,
    color: 'text-orange-800 dark:text-orange-300',
    bgColor: 'bg-orange-100 dark:bg-orange-900',
    border: 'border border-orange-300 dark:border-orange-700',
  },
  critical: {
    label: 'Critical',
    icon: <ShieldX className="text-red-600" size={16} />,
    color: 'text-red-800 dark:text-red-300',
    bgColor: 'bg-red-100 dark:bg-red-900',
    border: 'border border-red-300 dark:border-red-700',
  },
  unknown: {
    label: 'Unknown',
    icon: <Shield className="text-neutral-400" size={16} />,
    color: 'text-neutral-600 dark:text-neutral-300',
    bgColor: 'bg-neutral-100 dark:bg-neutral-800',
    border: 'border border-neutral-300 dark:border-neutral-700',
  },
};

export const VaultSecurityLevelBadge: React.FC<VaultSecurityLevelBadgeProps> = ({
  level,
  objectId,
  displayLabel = false,
  auditContext = 'vault_ui',
}) => {
  const { t } = useTranslation();
  const { theme } = useTheme();

  const levelMeta = useMemo(() => levelConfig[level] ?? levelConfig['unknown'], [level]);

  const handleAudit = () => {
    auditLogAction('security_badge_viewed', {
      objectId,
      level,
      theme,
      context: auditContext,
      timestamp: new Date().toISOString(),
    });
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.9 }}
      transition={{ duration: 0.15 }}
      className={classNames(
        'inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold shadow-sm',
        levelMeta.bgColor,
        levelMeta.color,
        levelMeta.border
      )}
      onClick={handleAudit}
      role="status"
      aria-label={`Security level ${level}`}
    >
      <Tooltip content={t(`security.level.${level}`)}>
        <span className="flex items-center gap-1">
          {levelMeta.icon}
          {displayLabel && <span>{t(`security.level.${level}`)}</span>}
        </span>
      </Tooltip>
    </motion.div>
  );
};

export default VaultSecurityLevelBadge;
