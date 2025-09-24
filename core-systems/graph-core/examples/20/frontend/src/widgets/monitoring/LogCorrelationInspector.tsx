import React, { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useLogCorrelations } from '@/services/logs/correlation';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { LogGraph } from '@/components/graph/LogGraph';
import { LogItemCorrelation } from '@/types/logs';
import { Badge } from '@/components/ui/badge';
import { debounce } from 'lodash';

export const LogCorrelationInspector: React.FC = () => {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState('');
  const { data, isLoading, refetch } = useLogCorrelations(search);

  const handleInput = debounce((value: string) => setSearch(value), 400);

  useEffect(() => {
    const interval = setInterval(() => refetch(), 10000);
    return () => clearInterval(interval);
  }, [refetch]);

  const grouped = useMemo(() => {
    if (!data) return {};
    return data.reduce((acc: Record<string, LogItemCorrelation[]>, item) => {
      const key = item.pattern || 'unclassified';
      acc[key] = acc[key] || [];
      acc[key].push(item);
      return acc;
    }, {});
  }, [data]);

  return (
    <Card className="w-full h-full flex flex-col border shadow-md">
      <CardHeader>
        <CardTitle className="text-lg font-semibold">
          {t('logs.correlation_inspector', 'Log Correlation Inspector')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 flex-1 flex flex-col overflow-hidden">
        <Input
          placeholder={t('logs.search_placeholder', 'Enter keyword or event ID...')}
          onChange={e => {
            setQuery(e.target.value);
            handleInput(e.target.value);
          }}
          value={query}
          className="w-full"
        />
        {isLoading && (
          <div className="space-y-2">
            {[...Array(5)].map((_, idx) => (
              <Skeleton key={idx} className="h-10 w-full rounded-md" />
            ))}
          </div>
        )}
        {!isLoading && data && data.length === 0 && (
          <div className="text-sm text-muted-foreground">
            {t('logs.no_correlations_found', 'No correlations found for query')}
          </div>
        )}
        <ScrollArea className="flex-1 overflow-y-auto pr-2">
          {Object.entries(grouped).map(([pattern, items]) => (
            <div key={pattern} className="mb-4">
              <div className="font-semibold text-sm mb-1 flex items-center gap-2">
                <Badge variant="outline" className="text-muted-foreground">
                  {pattern}
                </Badge>
                <span className="text-xs text-muted-foreground">({items.length} logs)</span>
              </div>
              <ul className="text-xs pl-3 list-disc space-y-1">
                {items.map(item => (
                  <li key={item.id} className="text-muted-foreground">
                    {item.timestamp} – <strong>{item.agent}</strong>: {item.message}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </ScrollArea>
        {data && data.length > 0 && (
          <div className="h-[300px] mt-4 border-t pt-2">
            <LogGraph events={data} />
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default LogCorrelationInspector;
