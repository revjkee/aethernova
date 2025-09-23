// src/widgets/Security/SecurityStatusCard.tsx
import React, { useMemo } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, ShieldCheck, Clock, Activity, RefreshCw } from "lucide-react";
import { useSecurityStatus } from "@/hooks/security/useSecurityStatus";
import { cn } from "@/lib/utils";
import { formatDistanceToNowStrict } from "date-fns";
import { Skeleton } from "@/components/ui/skeleton";
import { AiAlertAnalyzer } from "@/widgets/Security/AiAlertAnalyzer";
import { AnimatedShield } from "@/widgets/Security/AnimatedShield";
import { ThreatRadar } from "@/widgets/Security/ThreatRadar";

export const SecurityStatusCard: React.FC = () => {
  const {
    data,
    isLoading,
    lastUpdated,
    isStale,
    refresh,
  } = useSecurityStatus();

  const status = useMemo(() => {
    if (!data) return "unknown";
    if (data.incidents > 0 || data.threatLevel === "critical") return "alert";
    if (data.threatLevel === "moderate") return "warning";
    return "secure";
  }, [data]);

  const renderStatusBadge = () => {
    switch (status) {
      case "alert":
        return <Badge variant="destructive"><ShieldAlert className="mr-1 h-4 w-4" /> Угроза</Badge>;
      case "warning":
        return <Badge variant="warning"><Activity className="mr-1 h-4 w-4" /> Уязвимость</Badge>;
      case "secure":
        return <Badge variant="success"><ShieldCheck className="mr-1 h-4 w-4" /> Безопасно</Badge>;
      default:
        return <Badge variant="secondary">Неизвестно</Badge>;
    }
  };

  return (
    <Card className="w-full shadow-xl border bg-background relative overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div className="text-lg font-semibold text-foreground">Статус безопасности</div>
        <div onClick={refresh} className="cursor-pointer text-muted-foreground hover:text-foreground transition">
          <RefreshCw className="w-4 h-4" />
        </div>
      </CardHeader>

      <CardContent className="pt-4 pb-6 space-y-4 relative z-10">
        {isLoading ? (
          <div className="space-y-3">
            <Skeleton className="w-1/2 h-4" />
            <Skeleton className="w-1/3 h-4" />
            <Skeleton className="w-full h-24 rounded-md" />
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between">
              {renderStatusBadge()}
              <div className="text-xs text-muted-foreground flex items-center gap-1">
                <Clock className="h-3 w-3" />
                Обновлено {formatDistanceToNowStrict(new Date(lastUpdated))} назад
              </div>
            </div>

            <div className="text-sm text-muted-foreground">
              Активные инциденты: <span className="font-medium text-foreground">{data?.incidents || 0}</span><br />
              Общий уровень угроз: <span className={cn("font-medium", {
                "text-green-500": data?.threatLevel === "low",
                "text-yellow-500": data?.threatLevel === "moderate",
                "text-red-500": data?.threatLevel === "critical",
              })}>{data?.threatLevel?.toUpperCase()}</span><br />
              RBAC-проверки: {data?.rbacIntegrity ? "пройдены" : "ошибка"}
            </div>

            <div className="mt-4">
              <AiAlertAnalyzer logs={data?.logs || []} />
            </div>
          </>
        )}
      </CardContent>

      <div className="absolute right-4 bottom-4 opacity-10 pointer-events-none z-0">
        <AnimatedShield status={status} />
      </div>

      <div className="absolute left-0 top-0 w-full z-0">
        <ThreatRadar level={data?.threatLevel || "unknown"} />
      </div>
    </Card>
  );
};
