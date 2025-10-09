import React, { useEffect, useState, useMemo, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  ResponsiveContainer,
  LineChart,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  Line,
} from "recharts";
import { Loader2, RefreshCw } from "lucide-react";

// Типизация API-данных
interface LatencyPoint {
  timestamp: string;
  avg: number;
  p95: number;
  p99: number;
}

// Состояние загрузки
type FetchState = "idle" | "loading" | "success" | "error";

// Компонент skeleton для загрузки
const SkeletonLoader: React.FC = () => (
  <div className="animate-pulse space-y-4">
    <div className="h-6 bg-gray-300 rounded w-1/3" />
    <div className="h-72 bg-gray-200 rounded" />
  </div>
);

const LatencyStats: React.FC = () => {
  const [data, setData] = useState<LatencyPoint[]>([]);
  const [state, setState] = useState<FetchState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<number>(60); // минут

  // API вызов
  const fetchLatency = useCallback(async () => {
    try {
      setState("loading");
      setError(null);
      const res = await fetch(`/api/latency?minutes=${timeRange}`);
      if (!res.ok) throw new Error(`Ошибка ${res.status}`);
      const json: LatencyPoint[] = await res.json();
      setData(json);
      setState("success");
    } catch (err: any) {
      setError(err.message || "Неизвестная ошибка");
      setState("error");
    }
  }, [timeRange]);

  useEffect(() => {
    fetchLatency();
  }, [fetchLatency]);

  // Простая функция для форматирования времени
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-GB', { 
      hour: '2-digit', 
      minute: '2-digit',
      hour12: false 
    });
  };

  // Подготовка данных
  const chartData = useMemo(
    () =>
      data.map((d) => ({
        time: formatTime(d.timestamp),
        avg: d.avg,
        p95: d.p95,
        p99: d.p99,
      })),
    [data]
  );

  return (
    <div className="p-6 space-y-6">
      <Card>
        <CardHeader className="flex justify-between items-center">
          <CardTitle>Latency Statistics</CardTitle>
          <div className="flex gap-2">
            <select
              className="border rounded px-2 py-1 text-sm"
              value={timeRange}
              onChange={(e) => setTimeRange(Number(e.target.value))}
            >
              <option value={15}>15m</option>
              <option value={60}>1h</option>
              <option value={180}>3h</option>
              <option value={1440}>24h</option>
            </select>
            <Button
              size="sm"
              variant="outline"
              onClick={fetchLatency}
              disabled={state === "loading"}
            >
              {state === "loading" ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {state === "loading" && <SkeletonLoader />}
          {state === "error" && error && (
            <Alert variant="destructive">
              <AlertDescription>Ошибка загрузки: {error}</AlertDescription>
            </Alert>
          )}
          {state === "success" && chartData.length > 0 && (
            <ResponsiveContainer width="100%" height={400}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis
                  label={{
                    value: "ms",
                    angle: -90,
                    position: "insideLeft",
                  }}
                />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="avg" stroke="#3b82f6" dot={false} />
                <Line type="monotone" dataKey="p95" stroke="#f59e0b" dot={false} />
                <Line type="monotone" dataKey="p99" stroke="#ef4444" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
          {state === "success" && chartData.length === 0 && (
            <p className="text-gray-500">Нет данных за выбранный период</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default LatencyStats;
