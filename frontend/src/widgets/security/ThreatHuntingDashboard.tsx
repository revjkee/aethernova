// src/widgets/Security/ThreatHuntingDashboard.tsx
import React, { useState, useMemo, useCallback } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useThreatLogs } from "@/hooks/security/useThreatLogs";
import { ThreatLogTable } from "@/widgets/Security/ThreatLogTable";
import { ThreatInsightPanel } from "@/widgets/Security/ThreatInsightPanel";
import { AIHuntingAssistant } from "@/widgets/Security/AIHuntingAssistant";
import { ExportToPDFButton } from "@/components/ui/export";
import { TimelineVisualizer } from "@/widgets/Security/TimelineVisualizer";
import { ThreatTagCloud } from "@/widgets/Security/ThreatTagCloud";
import { cn } from "@/lib/utils";

export const ThreatHuntingDashboard: React.FC = () => {
  const [query, setQuery] = useState<string>("");
  const [selectedLogId, setSelectedLogId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"logs" | "timeline" | "tags">("logs");

  const {
    logs,
    isLoading,
    error,
    refresh,
    filteredLogs,
    uniqueTags,
    timelineData,
  } = useThreatLogs({ query });

  const onSelectLog = useCallback((id: string) => {
    setSelectedLogId(id);
  }, []);

  const selectedLog = useMemo(() => {
    return logs.find((log) => log.id === selectedLogId) || null;
  }, [selectedLogId, logs]);

  return (
    <Card className="w-full min-h-[600px] shadow-lg bg-background">
      <CardHeader className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="flex flex-col">
          <h2 className="text-lg font-bold text-foreground">Панель анализа угроз</h2>
          <p className="text-muted-foreground text-sm">Полуавтоматическая охота за угрозами, анализ логов и инцидентов</p>
        </div>
        <div className="flex gap-2 items-center w-full md:w-auto">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Поиск по IP, тегу или событию..."
            className="max-w-sm"
          />
          <ExportToPDFButton data={filteredLogs} filename="threat-report" />
        </div>
      </CardHeader>

      <Tabs value={activeTab} onValueChange={(val) => setActiveTab(val as any)} className="px-6">
        <TabsList className="w-full justify-start">
          <TabsTrigger value="logs">Логи</TabsTrigger>
          <TabsTrigger value="timeline">Хронология</TabsTrigger>
          <TabsTrigger value="tags">Метки</TabsTrigger>
        </TabsList>

        <TabsContent value="logs">
          <CardContent className="pt-4 pb-2">
            <ThreatLogTable
              logs={filteredLogs}
              isLoading={isLoading}
              error={error}
              onSelect={onSelectLog}
              selectedLogId={selectedLogId}
            />
            {selectedLog && (
              <ThreatInsightPanel log={selectedLog} />
            )}
          </CardContent>
        </TabsContent>

        <TabsContent value="timeline">
          <CardContent className="pt-4">
            <TimelineVisualizer data={timelineData} />
          </CardContent>
        </TabsContent>

        <TabsContent value="tags">
          <CardContent className="pt-4">
            <ThreatTagCloud tags={uniqueTags} onTagClick={(tag) => setQuery(tag)} />
          </CardContent>
        </TabsContent>
      </Tabs>

      <div className="border-t mt-4">
        <AIHuntingAssistant logs={filteredLogs} />
      </div>
    </Card>
  );
};
