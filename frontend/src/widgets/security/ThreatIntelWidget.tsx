// src/widgets/Security/ThreatIntelWidget.tsx
import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { useThreatIntelFeed } from "@/hooks/security/useThreatIntelFeed";
import { cn } from "@/lib/utils";
import dayjs from "dayjs";
import { ExternalLink } from "lucide-react";

type TISeverity = "low" | "medium" | "high" | "critical";
type TIType = "ip" | "domain" | "url" | "hash" | "signature" | "actor";

interface ThreatIntelEntry {
  id: string;
  type: TIType;
  value: string;
  source: string;
  severity: TISeverity;
  tags: string[];
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  link?: string;
}

const severityColors: Record<TISeverity, string> = {
  low: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

const typeLabel: Record<TIType, string> = {
  ip: "IP-адрес",
  domain: "Домен",
  url: "URL",
  hash: "Файл (хэш)",
  signature: "Сигнатура",
  actor: "Актор угроз",
};

export const ThreatIntelWidget: React.FC = () => {
  const { data, isLoading, refetch } = useThreatIntelFeed();
  const [selectedType, setSelectedType] = useState<TIType | "all">("all");

  const filtered = selectedType === "all" ? data : data?.filter(e => e.type === selectedType);

  return (
    <Card className="w-full h-full bg-background border">
      <CardHeader className="flex items-center justify-between">
        <CardTitle className="text-lg">Актуальные индикаторы угроз (TI)</CardTitle>
        <Button onClick={refetch} size="sm" variant="outline">
          Обновить
        </Button>
      </CardHeader>

      <CardContent className="h-[540px]">
        <Tabs value={selectedType} onValueChange={(val) => setSelectedType(val as TIType | "all")}>
          <TabsList className="mb-4 grid grid-cols-4 w-full">
            <TabsTrigger value="all">Все</TabsTrigger>
            <TabsTrigger value="ip">IP</TabsTrigger>
            <TabsTrigger value="domain">Домены</TabsTrigger>
            <TabsTrigger value="url">URL</TabsTrigger>
            <TabsTrigger value="hash">Файлы</TabsTrigger>
            <TabsTrigger value="signature">Сигнатуры</TabsTrigger>
            <TabsTrigger value="actor">Акторы</TabsTrigger>
          </TabsList>

          <TabsContent value={selectedType}>
            <ScrollArea className="h-[470px] pr-2">
              <div className="flex flex-col gap-3">
                {isLoading && (
                  <div className="text-center text-muted-foreground">Загрузка...</div>
                )}
                {!isLoading && (!filtered || filtered.length === 0) && (
                  <div className="text-center text-muted-foreground">Нет индикаторов.</div>
                )}
                {!isLoading &&
                  filtered?.map((entry) => (
                    <div key={entry.id} className="border rounded-md p-4">
                      <div className="flex justify-between items-center mb-2">
                        <div className="text-sm font-semibold">
                          {typeLabel[entry.type]}: {entry.value}
                        </div>
                        <Badge className={cn(severityColors[entry.severity])}>
                          {entry.severity.toUpperCase()}
                        </Badge>
                      </div>
                      <div className="text-xs text-muted-foreground mb-1">
                        Источник: {entry.source} | Достоверность: {entry.confidence}%
                      </div>
                      <div className="text-xs text-muted-foreground mb-2">
                        С: {dayjs(entry.firstSeen).format("DD.MM.YYYY")} до: {dayjs(entry.lastSeen).format("DD.MM.YYYY")}
                      </div>
                      <div className="flex gap-2 flex-wrap mb-2">
                        {entry.tags.map((tag, i) => (
                          <Badge key={i} variant="secondary" className="text-xs">{tag}</Badge>
                        ))}
                      </div>
                      {entry.link && (
                        <a
                          href={entry.link}
                          className="text-xs text-blue-600 hover:underline flex items-center gap-1"
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Подробнее <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  ))}
              </div>
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};
