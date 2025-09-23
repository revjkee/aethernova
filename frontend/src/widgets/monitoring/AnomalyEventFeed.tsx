import React, { useEffect, useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import clsx from 'clsx';
import { useTranslation } from 'react-i18next';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { subscribeToAnomalyFeed, AnomalyEvent } from '@/services/monitoring/anomalyService';
import { ShieldAlertIcon, ActivitySquareIcon, BrainCircuitIcon } from 'lucide-react';
import { Tooltip } from '@/shared/components/Tooltip';
import { Badge } from '@/shared/components/Badge';

const ICONS: Record<AnomalyEvent['severity'], JSX.Element> = {
  low: <ActivitySquareIcon size={16} className="text-blue-400" />,
  medium: <ActivitySquareIcon size={16} className="text-yellow-500" />,
  high: <ShieldAlertIcon size={16} className="text-red-600" />,
  critical: <ShieldAlertIcon size={16} className="text-pink-700 animate-pulse" />,
};

const ANOMALY_TAG_COLORS: Record<string, string> = {
  'ai': 'text-indigo-500',
  'network': 'text-emerald-600',
  'zero-trust': 'text-orange-600',
  'root-access': 'text-rose-700',
  'sandbox-escape': 'text-fuchsia-500',
};

const MAX_EVENTS = 20;

export const AnomalyEventFeed: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const [events, setEvents] = useState<AnomalyEvent[]>([]);
  const feedRef = useRef<HTMLDivElement>(null);

  const canView = hasPermission('monitoring.anomalies.view');

  const addAnomaly = useCallback((event: AnomalyEvent) => {
    setEvents((prev) => {
      const next = [event, ...prev];
      return next.slice(0, MAX_EVENTS);
    });
  }, []);

  useEffect(() => {
    if (!canView) return;
    const unsubscribe = subscribeToAnomalyFeed(addAnomaly);
    return () => unsubscribe();
  }, [canView, addAnomaly]);

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [events]);

  if (!canView || events.length === 0) return null;

  return (
    <div className="bg-neutral-900 border border-neutral-700 rounded-xl p-4 shadow-xl max-h-[400px] overflow-auto" ref={feedRef}>
      <h3 className="text-sm font-semibold text-neutral-200 mb-2">
        {t('anomaly_feed.title', 'Live Anomaly Feed')}
      </h3>
      <ul className="space-y-2">
        <AnimatePresence initial={false}>
          {events.map((event) => (
            <motion.li
              key={event.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
              className={clsx(
                'bg-neutral-800 border border-neutral-700 rounded-lg p-3 text-xs text-neutral-100 flex flex-col gap-1',
                event.severity === 'critical' && 'border-pink-600'
              )}
            >
              <div className="flex items-center gap-2 font-medium">
                {ICONS[event.severity]}
                <span>{event.title}</span>
                <span className="ml-auto text-[10px] text-neutral-400">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <div className="text-neutral-400">{event.description}</div>
              {event.tags?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {event.tags.map((tag) => (
                    <Badge key={tag} size="xs" variant="outline" className={clsx('text-[10px]', ANOMALY_TAG_COLORS[tag] || 'text-neutral-400')}>
                      {tag}
                    </Badge>
                  ))}
                </div>
              )}
              {event.agent && (
                <div className="text-[10px] mt-1 text-neutral-500">
                  {t('anomaly_feed.detected_by', { agent: event.agent })}
                </div>
              )}
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </div>
  );
};

export default AnomalyEventFeed;
