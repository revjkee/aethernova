// src/widgets/Governance/GovernanceNotificationBadge.tsx

import React, { useEffect, useState, useMemo } from 'react';
import { BellIcon, AlertTriangleIcon } from '@/components/icons';
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip';
import { Badge } from '@/components/ui/badge';
import { getGovernanceNotifications } from '@/services/dao/notifications';
import { cn } from '@/lib/utils';
import { useInterval } from '@/hooks/use-interval';
import { useUserPreferences } from '@/context/userPreferences';
import { AnimatePresence, motion } from 'framer-motion';

type Notification = {
  id: string;
  type: 'alert' | 'info' | 'vote' | 'critical';
  message: string;
  timestamp: number;
  acknowledged: boolean;
  actor?: string;
  importance: number; // 1-10
  module?: string;
};

export const GovernanceNotificationBadge: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const { preferences } = useUserPreferences();

  const fetchNotifications = async () => {
    try {
      const result = await getGovernanceNotifications();
      if (result?.data) {
        setNotifications(result.data);
      }
    } catch (e) {
      console.error('Ошибка при загрузке уведомлений:', e);
    } finally {
      setLoading(false);
    }
  };

  // Auto-refresh every 60 seconds
  useInterval(() => {
    fetchNotifications();
  }, 60000);

  useEffect(() => {
    fetchNotifications();
  }, []);

  const activeNotifications = useMemo(() => {
    return notifications.filter(n => !n.acknowledged);
  }, [notifications]);

  const mostImportant = useMemo(() => {
    return activeNotifications
      .sort((a, b) => b.importance - a.importance)
      .slice(0, 1)[0];
  }, [activeNotifications]);

  const badgeColor = useMemo(() => {
    if (!mostImportant) return 'muted';
    if (mostImportant.importance >= 9) return 'destructive';
    if (mostImportant.importance >= 6) return 'warning';
    return 'primary';
  }, [mostImportant]);

  const badgeText = useMemo(() => {
    if (!mostImportant) return '';
    const prefix =
      mostImportant.type === 'critical'
        ? 'Критично'
        : mostImportant.type === 'alert'
        ? 'Тревога'
        : mostImportant.type === 'vote'
        ? 'Голосование'
        : 'Обновление';
    return `${prefix}: ${mostImportant.message}`;
  }, [mostImportant]);

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="relative cursor-pointer select-none">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.3 }}
            className="flex items-center"
          >
            <BellIcon className="w-5 h-5 text-foreground" />
            {activeNotifications.length > 0 && (
              <Badge
                variant={badgeColor}
                className={cn(
                  'absolute -top-1 -right-2 text-[10px] px-1.5 py-0.5',
                  badgeColor === 'destructive' && 'animate-pulse',
                  badgeColor === 'warning' && 'animate-bounce'
                )}
              >
                {activeNotifications.length}
              </Badge>
            )}
          </motion.div>
        </div>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm text-xs text-left space-y-1 p-2">
        <div className="font-semibold text-foreground">
          Уведомления управления ({activeNotifications.length})
        </div>
        {mostImportant ? (
          <div className="text-foreground/80">
            {badgeText}
            <div className="mt-1 text-muted-foreground text-[10px] italic">
              {new Date(mostImportant.timestamp).toLocaleString()}
            </div>
          </div>
        ) : (
          <div className="text-muted-foreground">Нет новых уведомлений.</div>
        )}
      </TooltipContent>
    </Tooltip>
  );
};
