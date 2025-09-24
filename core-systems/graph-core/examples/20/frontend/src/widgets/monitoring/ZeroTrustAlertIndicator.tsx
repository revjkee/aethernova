import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { AlertTriangle, ShieldX, ShieldCheck, Activity } from 'lucide-react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { ZeroTrustEvent, fetchZeroTrustEvents } from '@/services/zero-trust/events';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { formatDistanceToNowStrict, parseISO } from 'date-fns';
import clsx from 'clsx';
import { useTranslation } from 'react-i18next';

const getAlertColor = (severity: ZeroTrustEvent['severity']) => {
  switch (severity) {
    case 'critical': return 'bg-red-500';
    case 'high': return 'bg-orange-500';
    case 'medium': return 'bg-yellow-500';
    case 'low': return 'bg-green-500';
    default: return 'bg-gray-500';
  }
};

const getIconByType = (type: ZeroTrustEvent['type']) => {
  switch (type) {
    case 'policy_breach': return <ShieldX className="w-4 h-4 text-red-600" />;
    case 'unauthorized_access': return <AlertTriangle className="w-4 h-4 text-orange-600" />;
    case 'compliance_check': return <ShieldCheck className="w-4 h-4 text-green-600" />;
    default: return <Activity className="w-4 h-4 text-muted-foreground" />;
  }
};

const truncate = (str: string, length = 96) => str.length > length ? str.slice(0, length) + '…' : str;

export const ZeroTrustAlertIndicator: React.FC = () => {
  const { t } = useTranslation();
  const [events, setEvents] = useState<ZeroTrustEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    const data = await fetchZeroTrustEvents();
    setEvents(data);
    setLoading(false);
  }, []);

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 15000);
    return () => clearInterval(interval);
  }, [loadEvents]);

  const sortedEvents = useMemo(() => {
    return [...events].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [events]);

  return (
    <Card className="w-full h-full flex flex-col border border-red-600 shadow-lg rounded-xl">
      <CardHeader className="pb-3">
        <CardTitle className="text-base font-bold tracking-tight flex items-center gap-2">
          <ShieldX className="w-5 h-5 text-red-600" />
          {t('zero_trust.alerts', 'Zero Trust Alerts')}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex-1 overflow-hidden">
        {loading ? (
          <div className="text-sm text-muted-foreground">Loading threats…</div>
        ) : (
          <ScrollArea className="h-full pr-2">
            {sortedEvents.length === 0 && (
              <div className="text-sm text-muted-foreground">{t('zero_trust.no_alerts', 'No current threats')}</div>
            )}
            <ul className="space-y-3">
              {sortedEvents.map(event => (
                <li key={event.id} className={clsx('p-3 rounded-md border shadow-sm flex items-start gap-3', getAlertColor(event.severity))}>
                  <div className="shrink-0 mt-0.5">{getIconByType(event.type)}</div>
                  <div className="flex flex-col">
                    <div className="text-sm font-semibold text-white">{event.title}</div>
                    <div className="text-xs text-white/80">{truncate(event.message)}</div>
                    <div className="text-[10px] text-white/60 mt-1">
                      {t('zero_trust.detected_by', 'Detected by')}: <span className="font-mono">{event.agentId}</span> · {formatDistanceToNowStrict(parseISO(event.timestamp))} ago
                    </div>
                  </div>
                  <Tooltip>
                    <TooltipTrigger className="ml-auto">
                      <Badge variant="outline" className="text-xs uppercase bg-black/30 border-white/30 text-white">
                        {event.severity}
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent side="left">
                      {t(`zero_trust.severity_${event.severity}`, `Severity: ${event.severity}`)}
                    </TooltipContent>
                  </Tooltip>
                </li>
              ))}
            </ul>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
};

export default ZeroTrustAlertIndicator;
