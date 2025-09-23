// src/widgets/Security/PolicyViolationLog.tsx

import React, { useState, useMemo } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Filter, Search, ShieldX, RefreshCw, CheckCircle2 } from "lucide-react";
import { usePolicyViolations } from "@/hooks/security/usePolicyViolations";
import dayjs from "dayjs";
import { cn } from "@/lib/utils";

type ViolationSeverity = "low" | "medium" | "high" | "critical";

const severityColorMap: Record<ViolationSeverity, string> = {
  low: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-900",
  high: "bg-orange-100 text-orange-900",
  critical: "bg-red-100 text-red-900",
};

const policyColorMap: Record<string, string> = {
  "RBAC": "bg-blue-100 text-blue-900",
  "IAM": "bg-purple-100 text-purple-900",
  "MFA": "bg-pink-100 text-pink-900",
  "Geo-Fence": "bg-teal-100 text-teal-900",
  "DLP": "bg-amber-100 text-amber-900",
};

interface PolicyViolationEntry {
  id: string;
  timestamp: string;
  user: string;
  ip: string;
  location: string;
  policy: string;
  severity: ViolationSeverity;
  description: string;
  resolved: boolean;
  tags: string[];
}

export const PolicyViolationLog: React.FC = () => {
  const { data, isLoading, refetch } = usePolicyViolations();
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!query.trim()) return data;
    return data?.filter((item) =>
      [item.user, item.ip, item.location, item.description, item.policy]
        .some(f => f.toLowerCase().includes(query.toLowerCase()))
    );
  }, [data, query]);

  return (
    <Card className="w-full bg-background border shadow-sm">
      <CardHeader className="flex items-center justify-between pb-2">
        <div className="flex flex-col">
          <CardTitle className="text-lg flex items-center gap-2">
            <ShieldX className="h-5 w-5 text-destructive" />
            Журнал нарушений политик
          </CardTitle>
          <span className="text-xs text-muted-foreground">
            Последние инциденты безопасности и нарушения IAM / RBAC / DLP
          </span>
        </div>
        <Button variant="ghost" size="sm" onClick={refetch}>
          <RefreshCw className="h-4 w-4 mr-1" /> Обновить
        </Button>
      </CardHeader>

      <CardContent className="pt-0">
        <div className="mb-4 flex items-center gap-2">
          <Search className="h-4 w-4 text-muted-foreground" />
          <Input
            className="w-full"
            placeholder="Поиск по пользователю, IP, политике..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        <ScrollArea className="h-[480px] pr-2">
          <div className="flex flex-col gap-3">
            {isLoading && (
              <div className="text-center text-muted-foreground text-sm">
                Загрузка нарушений...
              </div>
            )}
            {!isLoading && (!filtered || filtered.length === 0) && (
              <div className="text-center text-muted-foreground text-sm">
                Нет зафиксированных нарушений.
              </div>
            )}
            {filtered?.map((violation) => (
              <div key={violation.id} className="border rounded-md px-4 py-3 bg-muted/50">
                <div className="flex justify-between items-center mb-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold">{violation.user}</span>
                    <Badge className={cn(severityColorMap[violation.severity])}>
                      {violation.severity.toUpperCase()}
                    </Badge>
                    <Badge className={cn(policyColorMap[violation.policy] || "bg-gray-100 text-gray-800")}>
                      {violation.policy}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {dayjs(violation.timestamp).format("DD MMM YYYY HH:mm")}
                  </div>
                </div>

                <div className="text-sm">
                  <span className="text-muted-foreground">Описание:</span> {violation.description}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  IP: {violation.ip} • Регион: {violation.location}
                </div>
                <div className="mt-2 flex gap-1 flex-wrap">
                  {violation.tags.map((tag, idx) => (
                    <Badge key={idx} variant="outline" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>
                <div className="mt-2 flex justify-end">
                  {violation.resolved ? (
                    <Badge variant="secondary" className="text-green-700 border-green-400">
                      <CheckCircle2 className="h-3 w-3 mr-1" /> Подтверждено
                    </Badge>
                  ) : (
                    <Badge variant="destructive">Ожидает проверки</Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
