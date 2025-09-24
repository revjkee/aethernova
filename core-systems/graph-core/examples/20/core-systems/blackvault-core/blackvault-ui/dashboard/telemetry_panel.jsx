import React, { useEffect, useState } from "react";
import { Cpu, HardDrive, Zap, Timer, RefreshCcw } from "lucide-react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchSystemTelemetry } from "@/lib/api/telemetry";
import { cn } from "@/lib/utils";

const MetricRow = ({ icon: Icon, title, value, unit, progress }) => (
  <div className="flex items-center justify-between mb-3">
    <div className="flex items-center gap-2 text-sm">
      <Icon className="w-4 h-4 text-blue-400" />
      <span>{title}</span>
    </div>
    <div className="text-sm font-mono text-right w-28">{value} {unit}</div>
    <div className="w-40 ml-4">
      <Progress value={progress} className="h-1 bg-slate-700" />
    </div>
  </div>
);

export default function TelemetryPanel() {
  const [telemetry, setTelemetry] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    async function load() {
      try {
        const data = await fetchSystemTelemetry();
        if (mounted) {
          setTelemetry(data);
        }
      } catch (e) {
        console.error("Telemetry fetch error:", e);
      } finally {
        if (mounted) setLoading(false);
      }
    }

    load();
    const interval = setInterval(load, 5000); // 5 секунд интервал
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <Card className="shadow-xl rounded-2xl border border-slate-700 bg-zinc-900 text-white">
      <CardHeader className="flex items-center gap-2 text-lg font-bold">
        <RefreshCcw className="w-5 h-5 text-blue-400 animate-spin-slow" />
        Системная Телеметрия
      </CardHeader>
      <CardContent className="space-y-4">
        {loading || !telemetry ? (
          <>
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
          </>
        ) : (
          <>
            <MetricRow
              icon={Cpu}
              title="Загрузка CPU"
              value={telemetry.cpu.usage.toFixed(1)}
              unit="%"
              progress={telemetry.cpu.usage}
            />
            <MetricRow
              icon={HardDrive}
              title="Память"
              value={(telemetry.memory.used / 1024).toFixed(1)}
              unit="GB"
              progress={(telemetry.memory.used / telemetry.memory.total) * 100}
            />
            <MetricRow
              icon={Zap}
              title="IO-интенсивность"
              value={telemetry.io.rate.toFixed(2)}
              unit="ops/sec"
              progress={Math.min(telemetry.io.rate / 1000 * 100, 100)}
            />
            <MetricRow
              icon={Timer}
              title="Задержка AI"
              value={telemetry.latency.ms.toFixed(1)}
              unit="ms"
              progress={Math.min(telemetry.latency.ms / 300 * 100, 100)}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}
