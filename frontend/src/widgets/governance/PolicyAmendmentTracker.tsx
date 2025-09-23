// src/widgets/Governance/PolicyAmendmentTracker.tsx

import React, { useEffect, useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { DiffViewer } from '@/components/ui/diff-viewer';
import { getPolicyAmendments } from '@/services/governance/policyService';
import { History, BookOpen, GitCommitHorizontal, SearchCheck, Loader2 } from 'lucide-react';

interface PolicyChange {
  id: string;
  title: string;
  version: string;
  timestamp: string;
  author: string;
  hash: string;
  diff: {
    old: string;
    new: string;
  };
  approvedBy: string[];
  status: 'active' | 'proposed' | 'rejected';
  aiSummary: string;
}

export default function PolicyAmendmentTracker() {
  const [changes, setChanges] = useState<PolicyChange[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      const data = await getPolicyAmendments();
      setChanges(data);
      setSelectedId(data?.[0]?.id ?? null);
      setLoading(false);
    };
    load();
  }, []);

  if (loading) {
    return (
      <Card className="p-6 rounded-2xl border w-full">
        <CardContent className="space-y-4">
          <Skeleton className="h-5 w-1/3" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </CardContent>
      </Card>
    );
  }

  const selected = changes.find(c => c.id === selectedId);

  return (
    <Card className="p-6 rounded-2xl border shadow-lg w-full">
      <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <ScrollArea className="max-h-[500px] pr-2">
          <div className="space-y-3">
            {changes.map(change => (
              <div
                key={change.id}
                className={`cursor-pointer p-3 rounded-xl border ${
                  selectedId === change.id ? 'border-primary bg-muted' : 'border-border'
                } transition`}
                onClick={() => setSelectedId(change.id)}
              >
                <div className="flex justify-between items-center">
                  <h4 className="text-sm font-semibold">{change.title}</h4>
                  <Badge variant="outline" className="text-xs">{change.version}</Badge>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {new Date(change.timestamp).toLocaleString()}
                </p>
                <p className="text-xs text-muted-foreground italic mt-1">Автор: {change.author}</p>
              </div>
            ))}
          </div>
        </ScrollArea>

        <div className="col-span-2">
          {selected ? (
            <>
              <div className="flex items-center gap-2 mb-2">
                <BookOpen className="w-5 h-5 text-primary" />
                <h3 className="font-semibold text-lg">{selected.title}</h3>
                <Badge variant="outline">{selected.status}</Badge>
              </div>

              <Tabs defaultValue="diff" className="w-full">
                <TabsList className="mb-3">
                  <TabsTrigger value="diff">
                    <GitCommitHorizontal className="w-4 h-4 mr-1" />
                    Изменения
                  </TabsTrigger>
                  <TabsTrigger value="summary">
                    <SearchCheck className="w-4 h-4 mr-1" />
                    AI-анализ
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="diff">
                  <DiffViewer oldText={selected.diff.old} newText={selected.diff.new} />
                </TabsContent>

                <TabsContent value="summary">
                  <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                    {selected.aiSummary}
                  </p>
                </TabsContent>
              </Tabs>

              <div className="mt-4 text-xs text-muted-foreground">
                <p>
                  <span className="font-semibold">Подписали:</span>{' '}
                  {selected.approvedBy.length > 0 ? selected.approvedBy.join(', ') : '—'}
                </p>
                <p className="mt-1">
                  <span className="font-semibold">Хэш:</span> {selected.hash}
                </p>
              </div>
            </>
          ) : (
            <div className="flex justify-center items-center h-64 text-muted-foreground">
              <Loader2 className="animate-spin mr-2 h-5 w-5" />
              Загрузка изменений...
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
