import { useEffect, useState } from "react";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { FlameIcon, ThermometerIcon, ServerCrashIcon, CpuIcon, ZapIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { useTranslation } from "react-i18next";
import { cn } from "@/shared/utils/classNames";
import { subscribeOverheatStream } from "@/services/core/overheatMonitor";
import { Logger } from "@/shared/utils/logger";

interface OverheatMetrics {
  cpuLoad: number;          // 0–100
  gpuLoad: number;          // 0–100
  ramUsage: number;         // 0–100
  inferenceQueue: number;   // pending AI tasks
  wsSaturation: number;     // 0–100
  rpcLatency: number;       // ms
  critical: boolean;
  timestamp: string;
}

export const SystemOverheatAlert = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const [metrics, setMetrics] = useState<OverheatMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = subscribeOverheatStream((data: OverheatMetrics) => {
      setMetrics(data);
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const getColor = (val: number) => {
    if (val >= 90) return "bg-red-600";
    if (val >= 65) return "bg-yellow-500";
    return "bg-green-600";
  };

  const getCriticalBadge = () =>
    metrics?.critical ? (
      <Badge variant="destructive">
        <FlameIcon className="w-4 h-4 mr-1" />
        {t("overheat.critical")}
      </Badge>
    ) : (
      <Badge variant="secondary">
        <ThermometerIcon className="w-4 h-4 mr-1" />
        {t("overheat.stable")}
      </Badge>
    );

  const renderMetric = (label: string, value: number, icon: JSX.Element) => (
    <div className="space-y-1">
      <div className="flex justify-between items-center">
        <span className="text-sm font-medium flex items-center gap-2">
          {icon}
          {label}
        </span>
        <span className="text-xs text-muted-foreground font-mono">{value}%</span>
      </div>
      <Progress value={value} className={getColor(value)} />
    </div>
  );

  return (
    <div className={cn("w-full", className)}>
      {loading ? (
        <Skeleton className="h-24 w-full" />
      ) : (
        <Alert variant={metrics?.critical ? "destructive" : "default"}>
          <AlertTitle className="flex items-center justify-between">
            <span>{t("overheat.alert_title")}</span>
            {getCriticalBadge()}
          </AlertTitle>

          <AlertDescription className="space-y-4 pt-3 text-sm">
            {renderMetric(t("overheat.cpu"), metrics!.cpuLoad, <CpuIcon className="w-4 h-4" />)}
            {renderMetric(t("overheat.gpu"), metrics!.gpuLoad, <ZapIcon className="w-4 h-4" />)}
            {renderMetric(t("overheat.ram"), metrics!.ramUsage, <ServerCrashIcon className="w-4 h-4" />)}

            <div className="flex justify-between text-xs font-mono text-muted-foreground pt-2">
              <span>{t("overheat.queue")}: {metrics!.inferenceQueue}</span>
              <span>{t("overheat.latency")}: {metrics!.rpcLatency}ms</span>
            </div>

            <div className="text-right text-xs text-muted-foreground italic pt-1">
              {t("overheat.updated")}: {metrics!.timestamp}
            </div>
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};
