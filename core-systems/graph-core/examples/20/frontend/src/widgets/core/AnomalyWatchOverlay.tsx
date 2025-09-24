import React, { useEffect, useState } from 'react';
import { getAnomalyEvents } from '@/services/api/anomalyAPI';
import { Tooltip } from '@/shared/components/Tooltip';
import { cn } from '@/shared/utils/cn';
import { AlertCircleIcon, FlameIcon, WifiOffIcon, ShieldOffIcon, BotOffIcon, ClockIcon, ZapIcon } from 'lucide-react';
import { useInterval } from '@/shared/hooks/useInterval';
import { formatDistanceToNow } from 'date-fns';
import { Badge } from '@/shared/components/Badge';
import { useTranslation } from 'react-i18next';

type AnomalyLevel = 'info' | 'warning' | 'critical';

interface AnomalyEvent {
  id: string;
  type: string;
  message: string;
  timestamp: string;
  level: AnomalyLevel;
  origin: string;
}

const iconByType: Record<string, JSX.Element> = {
  intrusion: <ShieldOffIcon size={16} className="text-red-600" />,
  agent_fault: <BotOffIcon size={16} className="text-yellow-500" />,
  data_leak: <WifiOffIcon size={16} className="text-red-500" />,
  overload: <FlameIcon size={16} className="text-orange-500" />,
  heartbeat: <ZapIcon size={16} className="text-blue-500" />,
  default: <AlertCircleIcon size={16} className="text-gray-500" />,
};

const AnomalyWatchOverlay: React.FC = () => {
  const { t } = useTranslation();
  const [events, setEvents] = useState<AnomalyEvent[]>([]);
  const [visible, setVisible] = useState(true);

  const fetchEvents = async () => {
    try {
      const data = await getAnomalyEvents({ recentOnly: true });
      setEvents(data || []);
    } catch {
      setEvents([]);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, []);

  useInterval(fetchEvents, 15000); // обновление каждые 15 секунд

  if (!visible || events.length === 0) return null;

  return (
    <div
      className={cn(
        'fixed top-0 left-0 right-0 z-50 bg-zinc-950/95 border-b border-red-900 shadow-lg',
        'text-sm text-white px-6 py-2 flex items-center gap-6 overflow-x-auto backdrop-blur-md'
      )}
    >
      {events.map((event) => (
        <div key={event.id} className="flex items-center gap-3 min-w-[280px]">
          <div className="flex items-center gap-1.5">
            {iconByType[event.type] || iconByType.default}
            <Badge
              variant={
                event.level === 'critical'
                  ? 'destructive'
                  : event.level === 'warning'
                  ? 'warning'
                  : 'default'
              }
            >
              {t(`anomalies.level.${event.level}`)}
            </Badge>
          </div>

          <div className="flex flex-col">
            <Tooltip content={event.origin}>
              <span className="text-xs text-muted-foreground">{event.origin}</span>
            </Tooltip>
            <span className="font-medium leading-tight">{event.message}</span>
          </div>

          <div className="flex items-center gap-1 text-muted-foreground text-xs min-w-[100px]">
            <ClockIcon size={12} />
            <span>{formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}</span>
          </div>
        </div>
      ))}
    </div>
  );
};

export default React.memo(AnomalyWatchOverlay);
