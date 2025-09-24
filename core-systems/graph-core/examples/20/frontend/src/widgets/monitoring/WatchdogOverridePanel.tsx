import React, { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/components/ui/use-toast';
import { useTranslation } from 'react-i18next';
import { getWatchdogStatus, overrideWatchdog, resetWatchdog } from '@/services/monitoring/watchdog';
import { ShieldAlert, Activity, Lock, Unlock, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';

type WatchdogState = {
  isActive: boolean;
  isOverridden: boolean;
  triggerSource: string | null;
  overrideReason: string | null;
  lastHeartbeat: string;
};

export const WatchdogOverridePanel: React.FC = () => {
  const { t } = useTranslation();
  const { toast } = useToast();

  const [status, setStatus] = useState<WatchdogState | null>(null);
  const [loading, setLoading] = useState(false);
  const [overrideMode, setOverrideMode] = useState(false);
  const [reason, setReason] = useState('');

  const fetchStatus = useCallback(async () => {
    setLoading(true);
    const data = await getWatchdogStatus();
    setStatus(data);
    setOverrideMode(data.isOverridden);
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 15000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const handleOverride = async () => {
    if (!overrideMode && reason.trim() === '') {
      toast({ variant: 'destructive', title: t('watchdog.override_required_reason') });
      return;
    }

    const result = overrideMode
      ? await resetWatchdog()
      : await overrideWatchdog({ reason });

    if (result.success) {
      toast({ title: t('watchdog.status_updated') });
      fetchStatus();
    } else {
      toast({ variant: 'destructive', title: t('watchdog.update_failed') });
    }
  };

  return (
    <Card className="w-full border border-red-800 shadow-lg rounded-xl bg-white/95 backdrop-blur-sm">
      <CardHeader className="flex flex-row justify-between items-center">
        <CardTitle className="text-red-800 font-bold flex items-center gap-2">
          <ShieldAlert className="w-5 h-5" />
          {t('watchdog.panel_title', 'Watchdog Override Panel')}
        </CardTitle>
        <Button
          variant="ghost"
          onClick={fetchStatus}
          disabled={loading}
          className="text-red-600 hover:bg-red-50"
        >
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
        </Button>
      </CardHeader>
      <CardContent className="grid gap-5 text-sm text-gray-700">
        {status && (
          <>
            <div>
              <span className="font-semibold">{t('watchdog.current_state')}:</span>
              {status.isActive ? (
                <span className="ml-2 text-green-600 font-medium">
                  <Activity className="inline w-4 h-4 mr-1" /> Active
                </span>
              ) : (
                <span className="ml-2 text-gray-500 font-medium">Inactive</span>
              )}
            </div>
            <div>
              <span className="font-semibold">{t('watchdog.last_heartbeat')}:</span>
              <span className="ml-2">{status.lastHeartbeat}</span>
            </div>
            <div>
              <span className="font-semibold">{t('watchdog.override_status')}:</span>
              {status.isOverridden ? (
                <span className="ml-2 text-yellow-700 font-medium">
                  <Unlock className="inline w-4 h-4 mr-1" /> Overridden
                </span>
              ) : (
                <span className="ml-2 text-green-700 font-medium">
                  <Lock className="inline w-4 h-4 mr-1" /> Locked
                </span>
              )}
            </div>
            {status.overrideReason && (
              <div>
                <span className="font-semibold">{t('watchdog.override_reason')}:</span>
                <span className="ml-2">{status.overrideReason}</span>
              </div>
            )}
            {status.triggerSource && (
              <div>
                <span className="font-semibold">{t('watchdog.trigger_source')}:</span>
                <span className="ml-2">{status.triggerSource}</span>
              </div>
            )}
            <div className="flex items-center gap-3 mt-4">
              <Switch
                checked={overrideMode}
                onCheckedChange={(val) => setOverrideMode(val)}
                id="override-toggle"
              />
              <label htmlFor="override-toggle" className="text-sm">
                {overrideMode
                  ? t('watchdog.force_restore')
                  : t('watchdog.enable_override')}
              </label>
            </div>
            {!overrideMode && (
              <input
                className="w-full mt-2 px-3 py-2 border border-gray-300 rounded-md"
                type="text"
                placeholder={t('watchdog.enter_reason')}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            )}
            <Button
              onClick={handleOverride}
              variant="destructive"
              className="w-full mt-4"
              disabled={loading}
            >
              {overrideMode ? t('watchdog.reset_watchdog') : t('watchdog.confirm_override')}
            </Button>
          </>
        )}
        {!status && !loading && (
          <div className="text-center text-red-600">
            {t('watchdog.unavailable')}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default WatchdogOverridePanel;
