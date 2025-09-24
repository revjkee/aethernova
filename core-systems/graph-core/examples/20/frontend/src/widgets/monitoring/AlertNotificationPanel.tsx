import React, { useEffect, useState, useCallback } from 'react';
import { AlertCircleIcon, CheckIcon, ShieldAlertIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { NotificationFeedItem, subscribeToAlertFeed } from '@/services/monitoring/alertService';
import { Tooltip } from '@/shared/components/Tooltip';
import { Badge } from '@/shared/components/Badge';
import clsx from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';

type AlertLevel = 'info' | 'warning' | 'critical' | 'breach';

const ICON_MAP = {
  info: <CheckIcon size={16} className="text-blue-400" />,
  warning: <AlertCircleIcon size={16} className="text-yellow-400" />,
  critical: <ShieldAlertIcon size={16} className="text-red-600" />,
  breach: <ShieldAlertIcon size={16} className="text-pink-700 animate-pulse" />,
};

interface Props {
  maxItems?: number;
  autoHideMs?: number;
}

export const AlertNotificationPanel: React.FC<Props> = ({ maxItems = 6, autoHideMs = 15000 }) => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const [alerts, setAlerts] = useState<NotificationFeedItem[]>([]);

  const canView = hasPermission('monitoring.alerts.view');

  const handleNewAlert = useCallback((alert: NotificationFeedItem) => {
    setAlerts((prev) => {
      const updated = [alert, ...prev].slice(0, maxItems);
      return updated;
    });
    if (autoHideMs > 0) {
      setTimeout(() => {
        setAlerts((prev) => prev.filter((a) => a.id !== alert.id));
      }, autoHideMs);
    }
  }, [maxItems, autoHideMs]);

  useEffect(() => {
    if (!canView) return;
    const unsubscribe = subscribeToAlertFeed(handleNewAlert);
    return () => unsubscribe();
  }, [canView, handleNewAlert]);

  if (!canView || alerts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 w-full max-w-sm space-y-2">
      <AnimatePresence>
        {alerts.map((alert) => (
          <motion.div
            key={alert.id}
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, x: 50 }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className={clsx(
              'bg-white dark:bg-black border border-gray-200 dark:border-gray-800 shadow-xl rounded-lg p-3 flex items-start space-x-3',
              alert.level === 'critical' && 'border-red-500',
              alert.level === 'breach' && 'border-pink-600'
            )}
          >
            <div className="pt-1">{ICON_MAP[alert.level]}</div>
            <div className="flex flex-col flex-1">
              <div className="text-sm font-semibold">{t(alert.title)}</div>
              <div className="text-xs text-gray-600 dark:text-gray-400">{t(alert.message)}</div>
              <div className="text-[10px] text-muted mt-1">
                {new Date(alert.timestamp).toLocaleTimeString()}
              </div>
              {alert.tags && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {alert.tags.map((tag) => (
                    <Badge key={tag} size="xs" variant="outline" className="text-[10px]">{tag}</Badge>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};

export default AlertNotificationPanel;
