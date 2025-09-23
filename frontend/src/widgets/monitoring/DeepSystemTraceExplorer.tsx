import React, { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tree } from '@/components/ui/tree';
import { Badge } from '@/components/ui/badge';
import { useTranslation } from 'react-i18next';
import { fetchDeepTraces } from '@/services/monitoring/tracing';
import { cn } from '@/lib/utils';
import { Code, Terminal, Activity, Cpu, Zap } from 'lucide-react';

type TraceEntry = {
  agentId: string;
  traceId: string;
  timestamp: string;
  level: 'AGENT' | 'PROCESS' | 'SYSCALL' | 'KERNEL';
  component: string;
  message: string;
  durationMs?: number;
  parentTraceId?: string;
};

export const DeepSystemTraceExplorer: React.FC = () => {
  const { t } = useTranslation();
  const [traces, setTraces] = useState<TraceEntry[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const loadTraces = useCallback(async () => {
    setLoading(true);
    const result = await fetchDeepTraces();
    setTraces(result);
    setLoading(false);
  }, []);

  useEffect(() => {
    loadTraces();
    const interval = setInterval(loadTraces, 30000); // refresh every 30s
    return () => clearInterval(interval);
  }, [loadTraces]);

  const groupByAgent = useCallback(() => {
    const map = new Map<string, TraceEntry[]>();
    traces.forEach((entry) => {
      if (!map.has(entry.agentId)) map.set(entry.agentId, []);
      map.get(entry.agentId)?.push(entry);
    });
    return Array.from(map.entries());
  }, [traces]);

  const renderIcon = (level: string) => {
    switch (level) {
      case 'AGENT': return <Activity className="w-4 h-4 text-blue-600" />;
      case 'PROCESS': return <Cpu className="w-4 h-4 text-purple-700" />;
      case 'SYSCALL': return <Terminal className="w-4 h-4 text-amber-600" />;
      case 'KERNEL': return <Zap className="w-4 h-4 text-red-700" />;
      default: return <Code className="w-4 h-4" />;
    }
  };

  const renderTraceTree = (entries: TraceEntry[]) => {
    const rootEntries = entries.filter(e => !e.parentTraceId);
    const buildTree = (parentId: string | undefined): JSX.Element[] => {
      return entries
        .filter(e => e.parentTraceId === parentId)
        .map(entry => (
          <Tree.Item
            key={entry.traceId}
            icon={renderIcon(entry.level)}
            label={`${entry.component} – ${entry.message}`}
            description={entry.timestamp}
            metadata={<Badge variant="outline">{entry.durationMs ?? 0}ms</Badge>}
          >
            {buildTree(entry.traceId)}
          </Tree.Item>
        ));
    };
    return (
      <Tree.Root>
        {rootEntries.map(root => (
          <Tree.Item
            key={root.traceId}
            icon={renderIcon(root.level)}
            label={`${root.component} – ${root.message}`}
            description={root.timestamp}
            metadata={<Badge variant="outline">{root.durationMs ?? 0}ms</Badge>}
          >
            {buildTree(root.traceId)}
          </Tree.Item>
        ))}
      </Tree.Root>
    );
  };

  return (
    <Card className="w-full shadow-xl border border-gray-300 rounded-xl bg-white/90 backdrop-blur-md">
      <CardHeader>
        <CardTitle className="text-xl font-semibold text-gray-800">
          {t('monitoring.deep_trace_explorer', 'Deep System Trace Explorer')}
        </CardTitle>
      </CardHeader>
      <CardContent className="mt-2">
        <Tabs value={selectedAgent ?? ''} onValueChange={setSelectedAgent}>
          <TabsList className="overflow-x-auto max-w-full scrollbar-hide flex space-x-2">
            {groupByAgent().map(([agentId]) => (
              <TabsTrigger key={agentId} value={agentId} className="whitespace-nowrap">
                {agentId}
              </TabsTrigger>
            ))}
          </TabsList>
          {groupByAgent().map(([agentId, entries]) => (
            <TabsContent key={agentId} value={agentId}>
              <ScrollArea className="h-[600px] pr-2">
                {renderTraceTree(entries)}
              </ScrollArea>
            </TabsContent>
          ))}
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default DeepSystemTraceExplorer;
