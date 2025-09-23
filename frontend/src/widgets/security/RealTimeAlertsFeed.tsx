// src/widgets/Security/RealTimeAlertsFeed.tsx
import React, { useEffect, useRef, useState } from "react";
import { AlertCircle, CheckCircle, Timer, XCircle } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { useAlertsStream } from "@/hooks/security/useAlertsStream";
import { cn } from "@/lib/utils";
import dayjs from "dayjs";

type ThreatLevel = "low" | "medium" | "high" | "critical";
type AlertStatus = "new" | "acknowledged" | "resolved";

interface Alert {
  id: string;
  title: string;
  description: string;
  level: ThreatLevel;
  timestamp: string;
  status: AlertStatus;
  source?: string;
  location?: string;
}

const threatIcon = {
  low: <Timer className="w-4 h-4 text-muted-foreground" />,
  medium: <AlertCircle className="w-4 h-4 text-yellow-500" />,
  high: <AlertCircle className="w-4 h-4 text-orange-600" />,
  critical: <XCircle className="w-4 h-4 text-red-600" />,
};

const statusBadge = {
  new: "bg-red-100 text-red-800",
  acknowledged: "bg-yellow-100 text-yellow-800",
  resolved: "bg-green-100 text-green-800",
};

export const RealTimeAlertsFeed: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const { socket, connect, disconnect } = useAlertsStream();

  useEffect(() => {
    connect((newAlert: Alert) => {
      setAlerts((prev) => [newAlert, ...prev.slice(0, 99)]);
    });
    return () => disconnect();
  }, [connect, disconnect]);

  const renderAlert = (alert: Alert) => (
    <div
      key={alert.id}
      className={cn(
        "flex flex-col gap-1 p-3 rounded-md border",
        alert.level === "critical" && "border-red-500",
        alert.status === "resolved" && "opacity-60"
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 font-medium">
          {threatIcon[alert.level]}
          <span>{alert.title}</span>
        </div>
        <Badge className={cn("text-xs", statusBadge[alert.status])}>
          {alert.status.toUpperCase()}
        </Badge>
      </div>
      <p className="text-sm text-muted-foreground">{alert.description}</p>
      <div className="flex items-center justify-between text-xs text-muted-foreground pt-1">
        <span>{dayjs(alert.timestamp).format("HH:mm:ss · DD MMM")}</span>
        <span>
          {alert.source && `Источник: ${alert.source}`}{" "}
          {alert.location && `· Местоположение: ${alert.location}`}
        </span>
      </div>
    </div>
  );

  return (
    <Card className="h-full w-full bg-background border shadow-sm">
      <CardHeader className="flex items-center justify-between">
        <CardTitle className="text-lg font-semibold text-foreground">
          Поток оповещений об угрозах
        </CardTitle>
        <span className="text-sm text-muted-foreground">
          Последние события: {alerts.length}
        </span>
      </CardHeader>
      <CardContent className="h-[520px] overflow-hidden">
        <ScrollArea className="h-full pr-2">
          <div className="flex flex-col gap-2">
            {alerts.length === 0 ? (
              <p className="text-sm text-muted-foreground">Пока нет угроз.</p>
            ) : (
              alerts.map(renderAlert)
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
