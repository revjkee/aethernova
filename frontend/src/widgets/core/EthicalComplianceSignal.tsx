import React, { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { getEthicalComplianceStatus } from '@/services/api/ethicsAPI';
import { Badge } from '@/shared/components/Badge';
import { Tooltip } from '@/shared/components/Tooltip';
import { Spinner } from '@/shared/components/Spinner';
import { ShieldCheckIcon, ShieldXIcon, AlertTriangleIcon, InfoIcon } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { AuditLogPanel } from '@/shared/components/AuditLogPanel';
import { cn } from '@/shared/utils/cn';

type ComplianceLevel = 'compliant' | 'warning' | 'non_compliant' | 'pending';

interface ComplianceStatus {
  level: ComplianceLevel;
  score: number; // 0-100
  lastChecked: string;
  reviewer: string;
  detailMessage?: string;
  decisionId: string;
}

const iconsMap: Record<ComplianceLevel, JSX.Element> = {
  compliant: <ShieldCheckIcon size={18} className="text-green-600" />,
  warning: <AlertTriangleIcon size={18} className="text-yellow-500" />,
  non_compliant: <ShieldXIcon size={18} className="text-red-600" />,
  pending: <InfoIcon size={18} className="text-gray-500" />,
};

const EthicalComplianceSignal: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<ComplianceStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getEthicalComplianceStatus()
      .then((data) => setStatus(data))
      .catch(() => setStatus(null))
      .finally(() => setLoading(false));
  }, []);

  const badgeColor = useMemo(() => {
    switch (status?.level) {
      case 'compliant':
        return 'success';
      case 'warning':
        return 'warning';
      case 'non_compliant':
        return 'destructive';
      default:
        return 'default';
    }
  }, [status]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-muted-foreground px-4 py-3">
        <Spinner size="sm" />
        {t('ethics.loading')}
      </div>
    );
  }

  if (!status) {
    return (
      <div className="px-4 py-3 text-red-600 font-semibold">
        {t('ethics.loadFailed')}
      </div>
    );
  }

  return (
    <div className={cn(
      'w-full rounded-md p-4 border shadow-sm flex flex-col gap-2',
      badgeColor === 'success' ? 'border-green-600 bg-green-50 dark:bg-green-900' :
      badgeColor === 'warning' ? 'border-yellow-500 bg-yellow-50 dark:bg-yellow-900' :
      badgeColor === 'destructive' ? 'border-red-600 bg-red-50 dark:bg-red-900' :
      'border-gray-300 bg-gray-50 dark:bg-gray-800'
    )}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 text-lg font-semibold text-gray-900 dark:text-white">
          {iconsMap[status.level]}
          <span>{t(`ethics.status.${status.level}`)}</span>
        </div>
        <Badge variant={badgeColor}>
          {t('ethics.score', { score: status.score })}
        </Badge>
      </div>

      <div className="text-sm text-muted-foreground">
        {status.detailMessage || t('ethics.noDetail')}
      </div>

      <div className="flex justify-between text-xs text-muted-foreground">
        <span>
          {t('ethics.reviewedBy')}: <strong>{status.reviewer}</strong>
        </span>
        <span>
          {t('ethics.lastChecked')}: {formatDistanceToNow(new Date(status.lastChecked), { addSuffix: true })}
        </span>
      </div>

      <div className="mt-2">
        <AuditLogPanel resource={`ethics:compliance:${status.decisionId}`} maxEntries={5} />
      </div>
    </div>
  );
};

export default React.memo(EthicalComplianceSignal);
