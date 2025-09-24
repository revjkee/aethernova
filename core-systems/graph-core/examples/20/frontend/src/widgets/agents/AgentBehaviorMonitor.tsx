import { FC, useMemo } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Tooltip, LineChart, Line, ResponsiveContainer, YAxis, XAxis, CartesianGrid } from "recharts";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { useAgentBehavior } from "@/features/agents/hooks/useAgentBehavior";
import { useXAIAnomalyCheck } from "@/features/xai/hooks/useXAIAnomalyCheck";
import { Badge } from "@/components/ui/badge";
import { Flame, Zap, AlertTriangle, Activity } from "lucide-react";

interface AgentBehaviorMonitorProps {
  agentId: string;
  className?: string;
}

export const AgentBehaviorMonitor: FC<AgentBehaviorMonitorProps> = ({
  agentId,
  className
}) => {
  const { data: behaviorData, isLoading, error } = useAgentBehavior(agentId);
  const { anomalies } = useXAIAnomalyCheck(agentId, { type: "behavior" });

  const series = useMemo(() => {
    if (!behaviorData) return null;
    return behaviorData.activityTimeline.map((point) => ({
      ...point,
      deviation: point.deviationScore,
      impulse: point.impulseMagnitude,
    }));
  }, [behaviorData]);

  if (isLoading) {
    return <Skeleton className="h-[260px] w-full rounded-xl" />;
  }

  if (error || !series) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="w-5 h-5 text-red-600" />
        <AlertTitle>Сбой загрузки поведения агента</AlertTitle>
        <AlertDescription>Попробуйте позже или проверьте агентскую сеть</AlertDescription>
      </Alert>
    );
  }

  const currentStatus = behaviorData.status;
  const statusColor =
    currentStatus === "critical"
      ? "destructive"
      : currentStatus === "unstable"
        ? "warning"
        : "success";

  return (
    <Card className={cn("p-4 space-y-4", className)}>
      <CardHeader className="p-0">
        <CardTitle className="text-lg flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-600" />
          Поведенческий мониторинг
          <Badge variant={statusColor}>{currentStatus.toUpperCase()}</Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-3">
        <div className="text-sm text-muted-foreground">
          Анализ временных отклонений и импульсов активности агента
        </div>

        <ResponsiveContainer width="100%" height={160}>
          <LineChart data={series}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="timestamp" hide />
            <YAxis hide domain={[0, "auto"]} />
            <Tooltip
              formatter={(value: any, name: any) => [`${value}`, name === "impulse" ? "Импульс" : "Отклонение"]}
            />
            <Line
              type="monotone"
              dataKey="deviation"
              stroke="#ff0000"
              dot={false}
              strokeWidth={2}
              name="Отклонение"
            />
            <Line
              type="monotone"
              dataKey="impulse"
              stroke="#ffcc00"
              dot={false}
              strokeDasharray="5 2"
              strokeWidth={1.5}
              name="Импульс"
            />
          </LineChart>
        </ResponsiveContainer>

        {anomalies.length > 0 && (
          <Alert variant="warning" className="mt-2">
            <Zap className="w-4 h-4 text-yellow-600" />
            <AlertTitle>AI-анализ показал отклонения</AlertTitle>
            <AlertDescription className="text-xs whitespace-pre-wrap">
              {anomalies.map((a) => `— ${a.message}`).join("\n")}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};
