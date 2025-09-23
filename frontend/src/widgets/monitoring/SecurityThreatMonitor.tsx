import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import clsx from 'clsx';
import { ThreatEvent, useThreatFeed } from '@/services/monitoring/threatService';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { AnimatePresence, motion } from 'framer-motion';
import { FlagIcon, RadarIcon, AlertTriangleIcon } from 'lucide-react';
import { Badge } from '@/shared/components/Badge';
import { Tooltip } from '@/shared/components/Tooltip';
import { ThreatLevel, ThreatType, ThreatMap, getThreatIcon } from '@/shared/constants/threatTypes';
import { SystemClock } from '@/shared/components/SystemClock';

const MAX_ENTRIES = 30;

const colorMap: Record<ThreatLevel, string> = {
  low: 'text-blue-400',
  medium: 'text-yellow-500',
  high: 'text-orange-500',
  critical: 'text-rose-600',
};

const iconMap: Record<ThreatType, JSX.Element> = {
  dos: <RadarIcon size={16} className="text-cyan-400" />,
  malware: <AlertTriangleIcon size={16} className="text-red-600" />,
  rootkit: <FlagIcon size={16} className="text-fuchsia-500" />,
};

export const SecurityThreatMonitor: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);
  const canView = hasPermission('monitoring.security.view');

  const onNewThreat = useCallback((event: ThreatEvent) => {
    setEvents((prev) => [event, ...prev.slice(0, MAX_ENTRIES - 1)]);
  }, []);

  useEffect(() => {
    if (!canView) return;
    const unsubscribe = useThreatFeed(onNewThreat);
    return () => unsubscribe();
  }, [canView, onNewThreat]);

  useEffect(() => {
    if (containerRef.current) containerRef.current.scrollTop = 0;
  }, [events]);

  if (!canView || events.length === 0) return null;

  return (
    <section
      className="bg-neutral-950 border border-neutral-700 p-4 rounded-xl shadow-md h-[420px] overflow-y-auto"
      ref={containerRef}
    >
      <div className="flex justify-between items-center mb-3">
        <h3 className="text-sm font-semibold text-neutral-200">
          {t('threat_monitor.title', 'Active Security Threats')}
        </h3>
        <SystemClock />
      </div>

      <ul className="space-y-3">
        <AnimatePresence initial={false}>
          {events.map((event) => (
            <motion.li
              key={event.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ type: 'spring', stiffness: 260, damping: 20 }}
              className={clsx(
                'rounded-md p-3 border shadow-sm bg-gradient-to-br from-neutral-900 to-neutral-800',
                'border-neutral-700 text-xs text-neutral-100'
              )}
            >
              <div className="flex items-center gap-2 mb-1">
                {iconMap[event.type] || <RadarIcon size={16} />}
                <span className="font-medium">{event.title}</span>
                <span className="ml-auto text-[10px] text-neutral-400">
                  {new Date(event.detectedAt).toLocaleTimeString()}
                </span>
              </div>

              <p className="text-neutral-400 mb-1">{event.description}</p>

              <div className="flex flex-wrap items-center gap-1">
                <Badge size="xs" className={clsx(colorMap[event.level], 'text-[10px]')}>
                  {t(`threat.level.${event.level}`)}
                </Badge>
                <Badge size="xs" variant="outline" className="text-[10px] border-fuchsia-500">
                  {event.source}
                </Badge>
                {event.tags?.map((tag) => (
                  <Badge key={tag} size="xs" variant="ghost" className="text-[10px] text-emerald-400">
                    {tag}
                  </Badge>
                ))}
              </div>

              <div className="mt-1 text-[10px] text-neutral-500">
                {t('threat_monitor.agent_id', { id: event.agentId })}
              </div>
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </section>
  );
};

export default SecurityThreatMonitor;
