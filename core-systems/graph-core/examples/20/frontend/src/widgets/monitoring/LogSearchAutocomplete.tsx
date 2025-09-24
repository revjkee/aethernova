import React, { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Command, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { useDebounce } from '@/shared/hooks/useDebounce';
import { useLogSearch } from '@/services/monitoring/logs';
import { LogSearchResult } from '@/types/monitoring';
import { SparkleIcon, TerminalIcon, XCircleIcon } from 'lucide-react';
import clsx from 'clsx';

interface LogSearchAutocompleteProps {
  onSelect: (log: LogSearchResult) => void;
  agentId?: string;
  className?: string;
  placeholder?: string;
  autoFocus?: boolean;
}

export const LogSearchAutocomplete: React.FC<LogSearchAutocompleteProps> = ({
  onSelect,
  agentId,
  className,
  placeholder,
  autoFocus = false
}) => {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebounce(query, 250);
  const { data, isLoading, refetch } = useLogSearch(debouncedQuery, agentId);

  const filteredResults = useMemo(() => {
    if (!data || data.length === 0) return [];
    return data
      .sort((a, b) => {
        const severityWeight = { critical: 3, error: 2, warn: 1, info: 0 };
        const delayDiff = (b.latency || 0) - (a.latency || 0);
        return (
          (severityWeight[b.severity] - severityWeight[a.severity]) * 100 +
          delayDiff
        );
      })
      .slice(0, 20);
  }, [data]);

  useEffect(() => {
    if (debouncedQuery.length >= 3) {
      refetch();
    }
  }, [debouncedQuery, refetch]);

  return (
    <div className={clsx('relative w-full', className)}>
      <Command className="bg-background border border-muted rounded-md shadow-md overflow-hidden">
        <CommandInput
          autoFocus={autoFocus}
          value={query}
          onValueChange={setQuery}
          placeholder={placeholder || t('monitoring.search_logs', 'Search logs...')}
          className="h-10 px-3 text-sm"
        />
        <CommandList className="max-h-[300px] overflow-y-auto">
          {isLoading ? (
            <CommandItem disabled className="text-muted-foreground text-xs">
              {t('loading', 'Loading...')}
            </CommandItem>
          ) : filteredResults.length === 0 ? (
            <CommandItem disabled className="text-muted-foreground text-xs">
              <XCircleIcon className="w-4 h-4 mr-2 text-muted" />
              {t('monitoring.no_results', 'No matching logs found')}
            </CommandItem>
          ) : (
            <CommandGroup heading={t('monitoring.results', 'Results')}>
              {filteredResults.map((log, idx) => (
                <CommandItem
                  key={`${log.id}-${idx}`}
                  onSelect={() => onSelect(log)}
                  className={clsx(
                    'cursor-pointer items-start px-3 py-2 flex flex-col gap-1 transition-all',
                    {
                      'bg-red-50 text-red-800': log.severity === 'critical',
                      'bg-yellow-50 text-yellow-900': log.severity === 'warn',
                      'bg-green-50 text-green-900': log.severity === 'info',
                      'hover:bg-accent': true
                    }
                  )}
                >
                  <div className="flex items-center gap-2 w-full text-sm font-medium truncate">
                    <TerminalIcon className="w-4 h-4" />
                    {log.message}
                  </div>
                  <div className="text-xs text-muted-foreground truncate">
                    {t('monitoring.agent_id', 'Agent')}: {log.agentId} | {log.timestamp}
                  </div>
                  {log.latency !== undefined && (
                    <div className="text-[10px] text-muted-foreground">
                      {t('monitoring.latency', 'Latency')}: {log.latency}ms
                    </div>
                  )}
                </CommandItem>
              ))}
            </CommandGroup>
          )}
        </CommandList>
      </Command>
      {debouncedQuery.length > 0 && (
        <div className="absolute top-2.5 right-3 text-muted-foreground">
          <SparkleIcon className="w-4 h-4 animate-pulse" />
        </div>
      )}
    </div>
  );
};

export default LogSearchAutocomplete;
