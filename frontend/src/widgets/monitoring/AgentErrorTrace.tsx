import React, { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { useAgentErrors } from '@/services/monitoring/errors';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { AlertTriangle, Code, Terminal, Search } from 'lucide-react';
import clsx from 'clsx';

export const AgentErrorTrace: React.FC = () => {
  const { t } = useTranslation();
  const { hasPermission } = useRBAC();
  const { errorLogs, isLoading } = useAgentErrors();
  const [searchQuery, setSearchQuery] = useState('');

  const filteredErrors = useMemo(() => {
    if (!searchQuery) return errorLogs;
    return errorLogs.filter(e =>
      e.agentId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.stack.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [errorLogs, searchQuery]);

  if (!hasPermission('monitoring.agents.errors.view')) {
    return (
      <div className="p-4 text-sm text-red-600 border border-red-400 rounded bg-red-50">
        {t('monitoring.access_denied', 'Access to error traces is denied.')}
      </div>
    );
  }

  return (
    <Card className="w-full">
      <CardHeader className="flex justify-between items-center">
        <div>
          <h2 className="text-sm font-bold">{t('monitoring.agent_error_trace', 'Agent Error Trace')}</h2>
          <p className="text-xs text-muted-foreground">
            {t('monitoring.agent_error_trace_desc', 'Live error logs and stack traces of AI agents')}
          </p>
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-gray-400" />
          <Input
            className="pl-8 text-sm h-8"
            placeholder={t('monitoring.search_errors', 'Search...')}
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
        </div>
      </CardHeader>

      <CardContent className="h-[480px]">
        <ScrollArea className="h-full pr-2">
          {isLoading ? (
            <div className="text-center text-muted-foreground text-sm">{t('loading', 'Loading...')}</div>
          ) : filteredErrors.length === 0 ? (
            <div className="text-center text-muted-foreground text-sm">
              {t('monitoring.no_errors_found', 'No agent errors found')}
            </div>
          ) : (
            filteredErrors.map((error, idx) => (
              <div
                key={`${error.agentId}-${idx}`}
                className="mb-4 p-3 border border-muted rounded-md bg-muted/30 shadow-sm transition hover:bg-muted/50"
              >
                <div className="flex items-center gap-2 mb-2">
                  <Terminal className="text-yellow-600" size={16} />
                  <span className="font-medium text-sm">{error.agentId}</span>
                  <Badge variant="destructive" className="ml-auto text-xs">
                    {error.severity.toUpperCase()}
                  </Badge>
                </div>
                <div className="text-sm font-semibold text-foreground flex items-start gap-2">
                  <AlertTriangle size={14} className="mt-0.5 text-red-500" />
                  <span>{error.message}</span>
                </div>
                <div className="mt-2 bg-black/90 text-green-400 font-mono text-xs rounded p-3 overflow-x-auto max-h-[180px]">
                  <pre className="whitespace-pre-wrap break-words">{error.stack}</pre>
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {new Date(error.timestamp).toLocaleString()}
                </div>
              </div>
            ))
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default AgentErrorTrace;
