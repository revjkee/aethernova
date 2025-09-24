import React, { useEffect, useMemo, useState } from 'react';
import { cn } from '@/shared/utils/cn';
import { Badge } from '@/shared/components/Badge';
import { Tooltip } from '@/shared/components/Tooltip';
import { getGlobalStatus } from '@/services/api/systemAPI';
import { Spinner } from '@/shared/components/Spinner';
import { BellDotIcon, WifiIcon, ShieldCheckIcon, BotIcon, ClockIcon, CoinsIcon, RefreshCwIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { format } from 'date-fns';
import { useInterval } from '@/shared/hooks/useInterval';

interface StatusItem {
  label: string;
  value: string | React.ReactNode;
  icon: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'destructive';
  tooltip?: string;
}

const GlobalStatusBar: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [timestamp, setTimestamp] = useState<Date>(new Date());

  const fetchStatus = async () => {
    try {
      setLoading(true);
      const data = await getGlobalStatus();
      setStatus(data);
    } catch (e) {
      setStatus(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  useInterval(() => {
    setTimestamp(new Date());
  }, 1000);

  const items: StatusItem[] = useMemo(() => {
    if (!status) return [];

    return [
      {
        label: t('statusBar.aiStatus'),
        value: status.aiStatus,
        icon: <BotIcon size={16} />,
        variant: status.aiStatus === 'Active' ? 'success' : 'warning',
        tooltip: t('statusBar.aiStatusTip'),
      },
      {
        label: t('statusBar.network'),
        value: status.network === 'connected' ? t('statusBar.connected') : t('statusBar.disconnected'),
        icon: <WifiIcon size={16} />,
        variant: status.network === 'connected' ? 'success' : 'destructive',
      },
      {
        label: t('statusBar.privacy'),
        value: status.privacyShieldEnabled ? t('statusBar.protected') : t('statusBar.unprotected'),
        icon: <ShieldCheckIcon size={16} />,
        variant: status.privacyShieldEnabled ? 'success' : 'warning',
        tooltip: t('statusBar.privacyTip'),
      },
      {
        label: t('statusBar.token'),
        value: `${status.tokenBalance} $NEURO`,
        icon: <CoinsIcon size={16} />,
        variant: 'default',
      },
      {
        label: t('statusBar.incidents'),
        value: status.activeIncidents,
        icon: <BellDotIcon size={16} />,
        variant: status.activeIncidents > 0 ? 'warning' : 'default',
        tooltip: t('statusBar.incidentsTip'),
      },
      {
        label: t('statusBar.updated'),
        value: format(new Date(status.lastUpdate), 'HH:mm:ss'),
        icon: <RefreshCwIcon size={16} />,
        variant: 'default',
      },
      {
        label: t('statusBar.time'),
        value: format(timestamp, 'HH:mm:ss'),
        icon: <ClockIcon size={16} />,
        variant: 'default',
      },
    ];
  }, [status, t, timestamp]);

  return (
    <div className="w-full bg-zinc-100 dark:bg-zinc-900 border-t border-zinc-300 dark:border-zinc-800 px-4 py-2 flex flex-wrap items-center justify-start gap-3 text-sm">
      {loading ? (
        <div className="flex items-center gap-2 text-muted-foreground">
          <Spinner size="sm" />
          {t('statusBar.loading')}
        </div>
      ) : (
        items.map((item, idx) => (
          <Tooltip key={idx} content={item.tooltip || item.label}>
            <div className="flex items-center gap-1.5">
              {item.icon}
              <Badge variant={item.variant || 'default'}>{item.value}</Badge>
            </div>
          </Tooltip>
        ))
      )}
    </div>
  );
};

export default React.memo(GlobalStatusBar);
