import React, { useEffect, useState } from 'react';
import { Alert, AlertTitle, AlertDescription } from '@/shared/components/Alert';
import { ShieldAlertIcon, BellIcon, InfoIcon, TimerResetIcon, CircleHelpIcon } from 'lucide-react';
import { Button } from '@/shared/components/Button';
import { getLatestPrivacyIncident } from '@/services/api/incidentAPI';
import { useTranslation } from 'react-i18next';
import { IncidentLevel, IncidentType, PrivacyIncident } from '@/shared/types/incidents';
import { cn } from '@/shared/utils/cn';
import { formatRelative } from 'date-fns';
import { Tooltip } from '@/shared/components/Tooltip';
import { usePermission } from '@/shared/hooks/usePermission';
import { IncidentImpactBadge } from '@/widgets/Privacy/components/IncidentImpactBadge';
import { CopyButton } from '@/shared/components/CopyButton';

interface Props {
  userId: string;
  dismissible?: boolean;
  compact?: boolean;
}

const iconMap: Record<IncidentLevel, React.ReactNode> = {
  low: <InfoIcon className="text-blue-600" size={18} />,
  medium: <BellIcon className="text-yellow-600" size={18} />,
  high: <ShieldAlertIcon className="text-red-600" size={18} />,
  critical: <TimerResetIcon className="text-pink-600" size={18} />,
};

export const PrivacyIncidentAlert: React.FC<Props> = ({
  userId,
  dismissible = true,
  compact = false,
}) => {
  const { t } = useTranslation();
  const [incident, setIncident] = useState<PrivacyIncident | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const allowView = usePermission('privacy:incident:view');

  useEffect(() => {
    if (!allowView) return;

    getLatestPrivacyIncident(userId)
      .then(setIncident)
      .catch(() => setIncident(null));
  }, [userId, allowView]);

  if (!incident || dismissed || !allowView) return null;

  const severityClass = {
    low: 'border-blue-500 bg-blue-50 dark:bg-zinc-900',
    medium: 'border-yellow-500 bg-yellow-50 dark:bg-zinc-900',
    high: 'border-red-500 bg-red-50 dark:bg-zinc-900',
    critical: 'border-pink-600 bg-pink-50 dark:bg-zinc-900',
  };

  return (
    <Alert
      className={cn(
        'w-full border-l-4 px-4 py-3 rounded-md shadow-sm flex flex-col gap-2',
        severityClass[incident.level],
        compact ? 'text-xs' : 'text-sm'
      )}
    >
      <div className="flex items-center gap-2">
        {iconMap[incident.level]}
        <AlertTitle className="font-semibold text-base">
          {t(`privacy.incident.level.${incident.level}`)} — {t(`privacy.incident.type.${incident.type}`)}
        </AlertTitle>
      </div>

      <AlertDescription className="leading-relaxed mt-1 text-muted-foreground">
        {incident.description || t('privacy.incident.noDescription')}
      </AlertDescription>

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground mt-2">
        <div className="flex items-center gap-2">
          <Tooltip content={incident.source}>
            <span>{t('privacy.incident.source')}:</span>
          </Tooltip>
          <span className="font-medium">{incident.source}</span>
        </div>
        <div className="flex items-center gap-2">
          <Tooltip content={incident.timestamp}>
            <span>{formatRelative(new Date(incident.timestamp), new Date())}</span>
          </Tooltip>
          <IncidentImpactBadge impact={incident.impact} />
        </div>
      </div>

      <div className="flex items-center justify-between mt-3">
        <CopyButton text={incident.incidentId} label={t('privacy.incident.copyId')} />
        {dismissible && (
          <Button
            size="xs"
            variant="ghost"
            onClick={() => setDismissed(true)}
            icon={<CircleHelpIcon size={14} />}
          >
            {t('privacy.incident.dismiss')}
          </Button>
        )}
      </div>
    </Alert>
  );
};

export default React.memo(PrivacyIncidentAlert);
