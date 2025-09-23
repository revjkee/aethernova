import { FC, useMemo, useState } from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from "recharts";
import { useAgentActivityData } from "@/widgets/Agents/hooks/useAgentActivityData";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { format, parseISO } from "date-fns";
import { useTheme } from "@/shared/hooks/useTheme";
import { ActivityType, AgentActivityPoint } from "@/entities/agent/types";
import { ErrorBoundary } from "react-error-boundary";
import { AlertErrorFallback } from "@/components/fallbacks/AlertErrorFallback";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { TimeRangeFilter } from "@/components/filters/TimeRangeFilter";

interface AgentActivityChartProps {
  agentId: string;
  className?: string;
}

const activityColors: Record<ActivityType, string> = {
  "planning": "#36A2EB",
  "execution": "#4BC0C0",
  "review": "#9966FF",
  "idle": "#FF6384",
  "error": "#FF9F40"
};

export const AgentActivityChart: FC<AgentActivityChartProps> = ({ agentId, className }) => {
  const [timeRange, setTimeRange] = useState<"24h" | "7d" | "30d">("7d");
  const [groupBy, setGroupBy] = useState<"hour" | "day">("day");
  const { data, isLoading, error } = useAgentActivityData(agentId, timeRange, groupBy);
  const { theme } = useTheme();

  const chartData = useMemo(() => {
    if (!data) return [];

    const grouped: Record<string, Partial<Record<ActivityType, number>>> = {};
    data.forEach((point) => {
      const key = groupBy === "hour"
        ? format(parseISO(point.timestamp), "yyyy-MM-dd HH:00")
        : format(parseISO(point.timestamp), "yyyy-MM-dd");

      if (!grouped[key]) {
        grouped[key] = {};
      }
      grouped[key]![point.type] = (grouped[key]![point.type] || 0) + 1;
    });

    return Object.entries(grouped).map(([time, activities]) => ({
      time,
      ...activities,
    }));
  }, [data, groupBy]);

  if (isLoading) {
    return <Skeleton className="w-full h-[200px] rounded-xl" />;
  }

  if (error) {
    return <AlertErrorFallback error={error} />;
  }

  return (
    <Card className={cn("w-full", className)}>
      <CardHeader>
        <CardTitle>Активность агента</CardTitle>
        <div className="flex items-center gap-4 mt-2">
          <TimeRangeFilter value={timeRange} onChange={setTimeRange} />
          <Select value={groupBy} onValueChange={(value) => setGroupBy(value as any)}>
            <SelectTrigger className="w-[120px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="hour">По часам</SelectItem>
              <SelectItem value="day">По дням</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>
      <CardContent className="h-[320px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke={theme === "dark" ? "#444" : "#ccc"} />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} />
            <YAxis />
            <Tooltip />
            <Legend />
            {Object.keys(activityColors).map((type) => (
              <Bar
                key={type}
                dataKey={type}
                stackId="a"
                fill={activityColors[type as ActivityType]}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
};
