// frontend/src/widgets/Agents/AgentMetricsPanel.tsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import clsx from "clsx";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import { AlertTriangle, Clock, Gauge, GaugeCircle, Cpu, MemoryStick, RefreshCw, Activity, BarChart4 } from "lucide-react";

// shadcn/ui components
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";

// ==============================
// Types
// ==============================

export type TimePoint = {
  ts: string; // ISO timestamp
  rpm?: number; // requests per minute
  success_rate?: number; // 0..1
  latency_p50_ms?: number;
  latency_p95_ms?: number;
  errors_per_min?: number;
  tokens_in_per_min?: number;
  tokens_out_per_min?: number;
  cpu_pct?: number; // 0..100
  mem_mb?: number; // megabytes
};

export type AgentMetrics = {
  agentId: string;
  agentName?: string;
  windowLabel?: string; // e.g. "Last 60 min"
  timeseries: TimePoint[];
  // Instant KPIs
  kpi: {
    rpm: number;
    successRate: number; // 0..1
    latencyP50Ms: number;
    latencyP95Ms: number;
    errorRatePerMin: number;
    tokensInPerMin: number;
    tokensOutPerMin: number;
    cpuPct: number; // 0..100
    memMb: number;
  };
};

type LoadFn = (signal?: AbortSignal) => Promise<AgentMetrics>;

export type AgentMetricsPanelProps = {
  data?: AgentMetrics;
  load?: LoadFn;
  refreshIntervalMs?: number; // default 15000
  className?: string;
  compact?: boolean; // fewer charts
};

// ==============================
// Utilities
// ==============================

const fmt = {
  int: (v: number | undefined) => (typeof v === "number" && isFinite(v) ? Math.round(v).toLocaleString() : "—"),
  pct: (v: number | undefined, digits = 1) =>
    typeof v === "number" && isFinite(v) ? `${(v * 100).toFixed(digits)}%` : "—",
  pct100: (v: number | undefined, digits = 0) =>
    typeof v === "number" && isFinite(v) ? `${v.toFixed(digits)}%` : "—",
  ms: (v: number | undefined) =>
    typeof v === "number" && isFinite(v)
      ? v >= 1000
        ? `${(v / 1000).toFixed(2)} s`
        : `${Math.round(v)} ms`
      : "—",
  num: (v: number | undefined, digits = 1) =>
    typeof v === "number" && isFinite(v) ? v.toFixed(digits) : "—",
  tsShort: (iso: string) => {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  },
};

const green = (ok: boolean) => (ok ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400");

function healthFromKPIs(kpi: AgentMetrics["kpi"]) {
  // Rudimentary health score (0..100) based on SR, latency, error rate.
  // Thresholds tuned for typical LLM agent services.
  const srScore = Math.max(0, Math.min(100, (kpi.successRate ?? 0) * 100));
  const p95 = kpi.latencyP95Ms ?? 0;
  const latScore = p95 <= 1500 ? 100 : p95 >= 5000 ? 30 : 100 - ((p95 - 1500) / (5000 - 1500)) * 70;
  const err = kpi.errorRatePerMin ?? 0;
  const errScore = err === 0 ? 100 : err >= 10 ? 30 : 100 - (err / 10) * 70;
  // Weighted
  return Math.round(srScore * 0.45 + latScore * 0.35 + errScore * 0.20);
}

// ==============================
// Skeletons / Error states
// ==============================

function PanelSkeleton() {
  return (
    <div className="grid grid-cols-12 gap-4">
      <div className="col-span-12 lg:col-span-3 space-y-4">
        {[...Array(5)].map((_, i) => (
          <Card key={i} className="p-4">
            <Skeleton className="h-4 w-24 mb-3" />
            <Skeleton className="h-8 w-32" />
            <Skeleton className="h-3 w-full mt-4" />
          </Card>
        ))}
      </div>
      <div className="col-span-12 lg:col-span-9 space-y-4">
        {[...Array(3)].map((_, i) => (
          <Card key={i} className="p-4 h-[300px]">
            <Skeleton className="h-full w-full" />
          </Card>
        ))}
      </div>
    </div>
  );
}

function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <Card className="p-6 border-rose-200 dark:border-rose-800">
      <div className="flex items-start gap-3">
        <AlertTriangle className="h-5 w-5 text-rose-600 mt-0.5" aria-hidden />
        <div className="flex-1">
          <h3 className="font-semibold">Не удалось загрузить метрики агента</h3>
          <p className="text-sm text-muted-foreground mt-1">{message}</p>
          {onRetry && (
            <Button variant="outline" size="sm" className="mt-3" onClick={onRetry}>
              Повторить
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

// ==============================
// Small KPI Cards
// ==============================

function StatCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  warning = false,
}: {
  title: string;
  value: string;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: React.ReactNode;
  warning?: boolean;
}) {
  return (
    <Card className={clsx("p-4", warning && "border-rose-300 dark:border-rose-800")}>
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">{title}</div>
          <div className="text-2xl font-semibold">{value}</div>
          {subtitle && <div className="text-xs text-muted-foreground">{subtitle}</div>}
        </div>
        <div className="shrink-0">{icon}</div>
      </div>
      {trend && <div className="mt-3">{trend}</div>}
    </Card>
  );
}

// ==============================
// Charts
// ==============================

function CommonTooltip({ active, payload, label }: any) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-md border bg-background p-2 shadow-sm text-sm">
      <div className="font-medium">{label}</div>
      <Separator className="my-1" />
      <div className="space-y-0.5">
        {payload.map((p: any, idx: number) => (
          <div key={idx} className="flex items-center justify-between gap-4">
            <span className="text-muted-foreground">{p.name}</span>
            <span className="font-mono">{p.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function buildChartData(ts: TimePoint[], pick: (t: TimePoint) => Record<string, number | string>) {
  return ts.map((t) => ({
    time: fmt.tsShort(t.ts),
    ...pick(t),
  }));
}

// ==============================
// Main component
// ==============================

export default function AgentMetricsPanel({
  data: initial,
  load,
  refreshIntervalMs = 15000,
  className,
  compact = false,
}: AgentMetricsPanelProps) {
  const [data, setData] = useState<AgentMetrics | undefined>(initial);
  const [loading, setLoading] = useState<boolean>(!initial && !!load);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const doLoad = useCallback(async () => {
    if (!load) return;
    setLoading(true);
    setError(null);
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      const next = await load(ac.signal);
      setData(next);
    } catch (e: any) {
      if (e?.name !== "AbortError") {
        setError(e?.message ?? "Unknown error");
      }
    } finally {
      setLoading(false);
    }
  }, [load]);

  useEffect(() => {
    if (!load) return;
    // Initial load
    if (!initial) {
      void doLoad();
    }
    // Auto refresh
    const id = setInterval(() => {
      void doLoad();
    }, Math.max(5000, refreshIntervalMs));
    return () => {
      clearInterval(id);
      abortRef.current?.abort();
    };
  }, [load, doLoad, initial, refreshIntervalMs]);

  const kpi = data?.kpi;
  const health = useMemo(() => (kpi ? healthFromKPIs(kpi) : undefined), [kpi]);

  const tsData = data?.timeseries ?? [];

  const rpmData = useMemo(
    () => buildChartData(tsData, (t) => ({ rpm: t.rpm ?? 0, errors: t.errors_per_min ?? 0 })),
    [tsData]
  );
  const srData = useMemo(
    () =>
      buildChartData(tsData, (t) => ({
        "Success %": Math.round((t.success_rate ?? 0) * 1000) / 10,
      })),
    [tsData]
  );
  const latData = useMemo(
    () =>
      buildChartData(tsData, (t) => ({
        "P50 ms": Math.round(t.latency_p50_ms ?? 0),
        "P95 ms": Math.round(t.latency_p95_ms ?? 0),
      })),
    [tsData]
  );
  const tokData = useMemo(
    () =>
      buildChartData(tsData, (t) => ({
        "Tokens In/min": Math.round(t.tokens_in_per_min ?? 0),
        "Tokens Out/min": Math.round(t.tokens_out_per_min ?? 0),
      })),
    [tsData]
  );
  const sysData = useMemo(
    () =>
      buildChartData(tsData, (t) => ({
        "CPU %": Math.round(t.cpu_pct ?? 0),
        "Mem MB": Math.round(t.mem_mb ?? 0),
      })),
    [tsData]
  );

  return (
    <section
      className={clsx(
        "w-full space-y-4",
        className
      )}
      aria-labelledby="agent-metrics-title"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 id="agent-metrics-title" className="text-xl font-semibold">
            {data?.agentName ?? data?.agentId ?? "Agent"}
          </h2>
          <div className="flex items-center gap-2 text-sm text-muted-foreground mt-1">
            <Clock className="h-4 w-4" aria-hidden />
            <span>{data?.windowLabel ?? "Последние 60 мин"}</span>
            <Separator orientation="vertical" className="h-4" />
            <span className="sr-only">Состояние</span>
            {typeof health === "number" ? (
              <Badge variant={health >= 85 ? "default" : health >= 60 ? "secondary" : "destructive"}>
                Health {health}/100
              </Badge>
            ) : (
              <Badge variant="secondary">Нет данных</Badge>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {loading ? (
            <Badge variant="secondary">Обновление…</Badge>
          ) : (
            <Badge variant="outline">Готово</Badge>
          )}
          {load && (
            <Button variant="outline" size="sm" onClick={() => void doLoad()} aria-label="Обновить метрики">
              <RefreshCw className="h-4 w-4 mr-2" />
              Обновить
            </Button>
          )}
        </div>
      </div>

      {error ? (
        <ErrorState message={error} onRetry={() => void doLoad()} />
      ) : loading && !data ? (
        <PanelSkeleton />
      ) : !data ? (
        <Card className="p-6">
          <p className="text-sm text-muted-foreground">Нет данных для отображения.</p>
        </Card>
      ) : (
        <div className="grid grid-cols-12 gap-4">
          {/* KPIs */}
          <div className="col-span-12 lg:col-span-3">
            <div className="grid grid-cols-1 gap-4">
              <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
                <StatCard
                  title="Requests/min"
                  value={fmt.int(kpi.rpm)}
                  subtitle="Пропускная способность"
                  icon={<Activity className="h-5 w-5 text-muted-foreground" aria-hidden />}
                />
              </motion.div>
              <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
                <StatCard
                  title="Success rate"
                  value={fmt.pct(kpi.successRate, 1)}
                  subtitle={kpi.successRate >= 0.98 ? "Отлично" : kpi.successRate >= 0.95 ? "Хорошо" : "Ниже нормы"}
                  icon={<Gauge className="h-5 w-5 text-muted-foreground" aria-hidden />}
                  warning={kpi.successRate < 0.95}
                />
              </motion.div>
              <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
                <StatCard
                  title="Latency P50/P95"
                  value={`${fmt.ms(kpi.latencyP50Ms)} / ${fmt.ms(kpi.latencyP95Ms)}`}
                  subtitle="Задержка (медиана/хвост)"
                  icon={<GaugeCircle className="h-5 w-5 text-muted-foreground" aria-hidden />}
                  warning={(kpi.latencyP95Ms ?? 0) > 3000}
                />
              </motion.div>
              <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
                <StatCard
                  title="Errors/min"
                  value={fmt.int(kpi.errorRatePerMin)}
                  subtitle={kpi.errorRatePerMin > 0 ? "Есть ошибки" : "Ошибок нет"}
                  icon={<AlertTriangle className="h-5 w-5 text-muted-foreground" aria-hidden />}
                  warning={kpi.errorRatePerMin > 0}
                />
              </motion.div>
              {!compact && (
                <>
                  <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
                    <StatCard
                      title="Tokens In/Out"
                      value={`${fmt.int(kpi.tokensInPerMin)} / ${fmt.int(kpi.tokensOutPerMin)}`}
                      subtitle="Токены в минуту"
                      icon={<BarChart4 className="h-5 w-5 text-muted-foreground" aria-hidden />}
                    />
                  </motion.div>
                  <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
                    <StatCard
                      title="CPU / Memory"
                      value={`${fmt.pct100(kpi.cpuPct)} / ${fmt.int(kpi.memMb)} MB`}
                      subtitle="Ресурсы"
                      icon={<Cpu className="h-5 w-5 text-muted-foreground" aria-hidden />}
                      trend={
                        <div className="flex items-center gap-2 text-xs">
                          <Cpu className="h-3.5 w-3.5" />
                          <span className={green(kpi.cpuPct < 85)}>CPU OK</span>
                          <Separator orientation="vertical" className="h-3" />
                          <MemoryStick className="h-3.5 w-3.5" />
                          <span className={green(kpi.memMb < 8192)}>Mem OK</span>
                        </div>
                      }
                      warning={kpi.cpuPct >= 90 || kpi.memMb >= 12288}
                    />
                  </motion.div>
                </>
              )}
            </div>
          </div>

          {/* Charts */}
          <div className="col-span-12 lg:col-span-9 space-y-4">
            {/* Throughput & Errors */}
            <Card className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="font-medium">Пропускная способность и ошибки</div>
                <div className="text-xs text-muted-foreground">Requests/min, Errors/min</div>
              </div>
              <div className="h-[280px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={rpmData} margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis yAxisId="l" />
                    <YAxis yAxisId="r" orientation="right" />
                    <Tooltip content={<CommonTooltip />} />
                    <Legend />
                    <Bar yAxisId="l" dataKey="rpm" name="Req/min" />
                    <Bar yAxisId="r" dataKey="errors" name="Errors/min" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Success rate */}
            <Card className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="font-medium">Успешность</div>
                <div className="text-xs text-muted-foreground">Success %</div>
              </div>
              <div className="h-[260px]">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={srData} margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis domain={[0, 100]} />
                    <Tooltip content={<CommonTooltip />} />
                    <Legend />
                    <ReferenceLine y={95} strokeDasharray="4 4" />
                    <Line type="monotone" dataKey="Success %" name="Success %" dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Latency */}
            <Card className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="font-medium">Задержка</div>
                <div className="text-xs text-muted-foreground">P50/P95 ms</div>
              </div>
              <div className="h-[260px]">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={latData} margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip content={<CommonTooltip />} />
                    <Legend />
                    <Line type="monotone" dataKey="P50 ms" name="P50 ms" dot={false} />
                    <Line type="monotone" dataKey="P95 ms" name="P95 ms" dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {!compact && (
              <>
                {/* Tokens */}
                <Card className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium">Токены</div>
                    <div className="text-xs text-muted-foreground">In/Out per min</div>
                  </div>
                  <div className="h-[260px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={tokData} margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis />
                        <Tooltip content={<CommonTooltip />} />
                        <Legend />
                        <Line type="monotone" dataKey="Tokens In/min" name="Tokens In/min" dot={false} />
                        <Line type="monotone" dataKey="Tokens Out/min" name="Tokens Out/min" dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </Card>

                {/* System */}
                <Card className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium">Системные ресурсы</div>
                    <div className="text-xs text-muted-foreground">CPU %, Mem MB</div>
                  </div>
                  <div className="h-[260px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={sysData} margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis yAxisId="l" domain={[0, 100]} />
                        <YAxis yAxisId="r" orientation="right" />
                        <Tooltip content={<CommonTooltip />} />
                        <Legend />
                        <Line yAxisId="l" type="monotone" dataKey="CPU %" name="CPU %" dot={false} />
                        <Line yAxisId="r" type="monotone" dataKey="Mem MB" name="Mem MB" dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              </>
            )}
          </div>

          {/* Raw timeseries (scrollable) */}
          {!compact && (
            <div className="col-span-12">
              <Card className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="font-medium">Сырые точки временного ряда</div>
                  <div className="text-xs text-muted-foreground">Для отладки и аудита</div>
                </div>
                <ScrollArea className="h-56 w-full rounded-md border">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-background z-10">
                      <tr className="text-left">
                        <th className="px-3 py-2">Time</th>
                        <th className="px-3 py-2">Req/min</th>
                        <th className="px-3 py-2">Success</th>
                        <th className="px-3 py-2">P50</th>
                        <th className="px-3 py-2">P95</th>
                        <th className="px-3 py-2">Err/min</th>
                        <th className="px-3 py-2">Tok In</th>
                        <th className="px-3 py-2">Tok Out</th>
                        <th className="px-3 py-2">CPU %</th>
                        <th className="px-3 py-2">Mem MB</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tsData.map((t, i) => (
                        <tr key={i} className="border-t">
                          <td className="px-3 py-2 font-mono">{fmt.tsShort(t.ts)}</td>
                          <td className="px-3 py-2">{fmt.int(t.rpm)}</td>
                          <td className="px-3 py-2">{fmt.pct(t.success_rate, 1)}</td>
                          <td className="px-3 py-2">{fmt.ms(t.latency_p50_ms)}</td>
                          <td className="px-3 py-2">{fmt.ms(t.latency_p95_ms)}</td>
                          <td className="px-3 py-2">{fmt.int(t.errors_per_min)}</td>
                          <td className="px-3 py-2">{fmt.int(t.tokens_in_per_min)}</td>
                          <td className="px-3 py-2">{fmt.int(t.tokens_out_per_min)}</td>
                          <td className="px-3 py-2">{fmt.pct100(t.cpu_pct)}</td>
                          <td className="px-3 py-2">{fmt.int(t.mem_mb)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </ScrollArea>
              </Card>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
