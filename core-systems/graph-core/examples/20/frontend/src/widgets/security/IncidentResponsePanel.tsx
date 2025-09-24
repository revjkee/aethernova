// src/widgets/Security/IncidentResponsePanel.tsx
import React, { useEffect, useState, useCallback } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { IncidentStatusBadge } from "@/components/security/IncidentStatusBadge";
import { IncidentTimeline } from "@/components/security/IncidentTimeline";
import { IncidentActionModal } from "@/components/security/IncidentActionModal";
import { useIncidentStore } from "@/hooks/security/useIncidentStore";
import { Loader2, ShieldAlert, CheckCircle, Activity } from "lucide-react";
import { formatDistanceToNowStrict } from "date-fns";
import { cn } from "@/lib/utils";

export const IncidentResponsePanel: React.FC = () => {
  const {
    incidents,
    loading,
    resolveIncident,
    escalateIncident,
    fetchIncidents,
  } = useIncidentStore();

  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(() => fetchIncidents(), 10000); // автообновление каждые 10 сек
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  const handleResolve = useCallback((id: string) => {
    resolveIncident(id);
  }, [resolveIncident]);

  const handleEscalate = useCallback((id: string) => {
    escalateIncident(id);
  }, [escalateIncident]);

  const openDetails = useCallback((id: string) => {
    setSelectedIncidentId(id);
  }, []);

  return (
    <Card className="w-full h-full shadow-md border bg-background border-border">
      <CardHeader className="flex items-center justify-between gap-4">
        <h2 className="text-lg font-semibold text-foreground">
          Реагирование на инциденты
        </h2>
        <div className="text-muted-foreground text-sm">
          {loading ? (
            <div className="flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" /> Обновление...
            </div>
          ) : (
            `Всего: ${incidents.length}`
          )}
        </div>
      </CardHeader>

      <CardContent>
        <ScrollArea className="h-[500px] pr-2">
          {incidents.length === 0 ? (
            <div className="text-sm text-muted-foreground text-center py-8">
              Нет активных инцидентов
            </div>
          ) : (
            <ul className="space-y-4">
              {incidents.map((incident) => (
                <li
                  key={incident.id}
                  className={cn(
                    "rounded-lg border border-muted px-4 py-3 hover:bg-muted/30 transition-all",
                    incident.status === "critical" && "border-red-500"
                  )}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex flex-col">
                      <div className="flex items-center gap-2 text-base font-medium text-foreground">
                        {incident.title}
                        <IncidentStatusBadge status={incident.status} />
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Источник: {incident.source} · {formatDistanceToNowStrict(new Date(incident.detectedAt))} назад
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => openDetails(incident.id)}
                      >
                        Анализ
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-green-600 hover:text-green-700"
                        onClick={() => handleResolve(incident.id)}
                      >
                        <CheckCircle className="w-4 h-4 mr-1" /> Решено
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => handleEscalate(incident.id)}
                      >
                        <ShieldAlert className="w-4 h-4 mr-1" /> Эскалация
                      </Button>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </ScrollArea>
      </CardContent>

      {selectedIncidentId && (
        <IncidentActionModal
          incidentId={selectedIncidentId}
          onClose={() => setSelectedIncidentId(null)}
        />
      )}
    </Card>
  );
};
