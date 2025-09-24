import { FC, useMemo } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useAgentKPI } from "@/widgets/Agents/hooks/useAgentKPI";
import { useXAIAnomalyCheck } from "@/features/xai/hooks/useXAIAnomalyCheck";
import { motion } from "framer-motion";
import { KPIThresholds, AgentKPIResult } from "@/entities/agent/types";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Flame, CheckCircle, AlertCircle } from "lucide-react";

interface AgentPerformanceWidgetProps {
  agentId: string;
  showAnomalies?: boolean;
  className?: string;
}

export const AgentPerformanceWidget: FC<AgentPerformanceWidgetProps> = ({
  agentId,
  showAnomalies = true,
  className
}) => {
  const { data: kpi, isLoading, error } = useAgentKPI(agentId);
  const { anomalies } = useXAIAnomalyCheck(agentId);

  const processed = useMemo<AgentKPIResult | null>(() => {
    if (!kpi) return null;
    return {
      successRate: Math.min(kpi.tasksCompleted / kpi.tasksAssigned * 100, 100),
      deviationRate: kpi.deviationRatio,
      escalationCount: kpi.escalations,
      taskVolume: kpi.taskVolumeHistory,
    };
  }, [kpi]);

  if (isLoading) {
    return <Skeleton className="h-[240px] w-full rounded-xl" />;
  }

  if (error || !processed) {
    return (
      <Alert variant="destructive" className="max-w-full">
        <AlertCircle className="h-5 w-5 text-red-600" />
        <AlertTitle>Ошибка загрузки KPI</AlertTitle>
        <AlertDescription>Проверьте сеть или агента</AlertDescription>
      </Alert>
    );
  }

  const isUnderperforming = processed.successRate < KPIThresholds.minSuccess;
  const isHighDeviation = processed.deviationRate > KPIThresholds.maxDeviation;

  return (
    <Card className={cn("p-4 space-y-4", className)}>
      <CardHeader className="p-0">
        <CardTitle className="text-lg flex items-center gap-2">
          <Flame className="text-orange-500 w-4 h-4" />
          KPI агента
          <Badge variant={isUnderperforming || isHighDeviation ? "destructive" : "success"}>
            {isUnderperforming ? "Риск" : "Норма"}
          </Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="grid gap-3">
        <div>
          <div className="text-sm mb-1 text-muted-foreground">Процент успешных задач</div>
          <motion.div whileInView={{ scale: [0.95, 1] }}>
            <Progress value={processed.successRate} />
          </motion.div>
        </div>

        <div>
          <div className="text-sm mb-1 text-muted-foreground">Коэффициент отклонений</div>
          <Progress value={processed.deviationRate * 100} color="yellow" />
        </div>

        <div>
          <div className="text-sm mb-1 text-muted-foreground">Эскалации</div>
          <Badge variant="outline">{processed.escalationCount}</Badge>
        </div>

        <div className="text-sm text-muted-foreground">Динамика задач (7 дней)</div>
        <ResponsiveContainer width="100%" height={120}>
          <BarChart data={processed.taskVolume}>
            <XAxis dataKey="date" hide />
            <YAxis hide />
            <Tooltip />
            <Bar dataKey="count" fill="#4f46e5" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>

        {showAnomalies && anomalies.length > 0 && (
          <Alert variant="warning">
            <AlertCircle className="h-4 w-4 text-yellow-600" />
            <AlertTitle>Обнаружены аномалии</AlertTitle>
            <AlertDescription className="text-xs">
              {anomalies.map((a) => `— ${a.message}`).join("\n")}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};
