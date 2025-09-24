// src/widgets/Security/AccessAnomalyTracker.tsx

import React, { useEffect, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, ShieldAlert, User, Clock, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { useAccessAnomalyFeed } from "@/hooks/security/useAccessAnomalyFeed";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

dayjs.extend(relativeTime);

type AnomalySeverity = "low" | "medium" | "high" | "critical";

interface AccessAnomaly {
  id: string;
  user: string;
  location: string;
  ip: string;
  method: string;
  time: string;
  reason: string;
  severity: AnomalySeverity;
  confirmed: boolean;
  tags: string[];
}

const severityStyles: Record<AnomalySeverity, string> = {
  low: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

export const AccessAnomalyTracker: React.FC = () => {
  const { data, isLoading, refetch } = useAccessAnomalyFeed();
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!query.trim()) return data;
    return data?.filter((entry) =>
      [entry.user, entry.location, entry.ip, entry.method, entry.reason]
        .some(field => field.toLowerCase().includes(query.toLowerCase()))
    );
  }, [data, query]);

  return (
    <Card className="w-full h-full bg-background border shadow-sm">
      <CardHeader className="flex justify-between items-center pb-2">
        <div className="flex flex-col gap-1">
          <CardTitle className="text-lg">Access Anomaly Tracker</CardTitle>
          <span className="text-xs text-muted-foreground">
            Поведенческий анализ входов и отклонений от baseline
          </span>
        </div>
        <Button onClick={refetch} variant="outline" size="sm">Обновить</Button>
      </CardHeader>

      <CardContent className="pt-0">
        <div className="mb-4 flex gap-2 items-center">
          <Search className="h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Поиск пользователя, IP или причины..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full"
          />
        </div>

        <ScrollArea className="h-[480px] pr-2">
          <div className="flex flex-col gap-3">
            {isLoading && (
              <div className="text-center text-muted-foreground text-sm">
                Загрузка аномалий…
              </div>
            )}
            {!isLoading && (!filtered || filtered.length === 0) && (
              <div className="text-center text-muted-foreground text-sm">
                Аномалии не обнаружены.
              </div>
            )}
            {filtered?.map((a) => (
              <div key={a.id} className="border rounded-md px-4 py-3 bg-muted/40">
                <div className="flex items-center justify-between">
                  <div className="flex gap-2 items-center">
                    <User className="h-4 w-4" />
                    <span className="font-semibold">{a.user}</span>
                    <Badge className={cn(severityStyles[a.severity])}>
                      {a.severity.toUpperCase()}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {dayjs(a.time).fromNow()}
                  </div>
                </div>

                <div className="text-sm mt-2">
                  <ShieldAlert className="inline h-4 w-4 mr-1 text-destructive" />
                  Причина: <span className="font-medium">{a.reason}</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Метод: {a.method} • IP: {a.ip} • Регион: {a.location}
                </div>
                <div className="mt-2 flex gap-1 flex-wrap">
                  {a.tags.map((tag, i) => (
                    <Badge key={i} variant="secondary" className="text-xs">{tag}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
