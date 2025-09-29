// frontend/src/widgets/Monitoring/ResourceUtilization.tsx
// Industrial-grade, accessible, responsive Resource Utilization widget.
// Tech stack: React + TypeScript, TailwindCSS, Recharts, Framer Motion, shadcn/ui, lucide-react.
// This component is self-contained and production-ready.

import * as React from "react";
import { memo, useMemo, useState, useId } from "react";
import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
  Legend,
  ReferenceLine,
} from "recharts";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { Toggle } from "@/components/ui/toggle";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { AlertTriangle, Activity, Gauge, Cpu, MemoryStick, HardDrive, Network, RefreshCcw } from "lucide-react";

type Sample = {
  ts: number;           // unix ms timestamp
  cpu?: number;         // 0..100 in percent
  mem?: number;         // 0..100 in percent
  netInBytes?: number;  // bytes/s
  netOutBytes?: number; // bytes/s
  diskReadBytes?: number;  // bytes/s
  diskWriteBytes?: number; // bytes/s
  gpu?: number;         // 0..100 in percent (optional)
};

export type ResourceUtilizationProps = {
  title?: string;
  description?: string;
  samples: Sample[];
  loading?: boolean;
  error?: string | null;
  compact?: boolean;
  className?: string;
  // Thresholds are purely presentational; they do not enforce anything.
  thresholds?: {
    cpuWarn?: number;       // default 75
    cpuCrit?: number;       // default 90
    memWarn?: number;       // default 75
    memCrit?: number;       // default 90
  };
  // Optional time range presets rendered in the selector; the caller must provide already-filtered samples if needed.
  rangePresets?: { key: string; label: string }[];
  onRefresh?: () => void; // optional refresh handler
};

type MetricKey =
  | "cpu"
  | "mem"
  | "net"
  | "disk"
  | "gpu";

const DEFAULT_THRESHOLDS = {
  cpuWarn: 75,
  cpuCrit: 90,
  memWarn: 75,
  memCrit: 90,
} as const;

const METRIC_TABS: { key: MetricKey; label: string; icon: React.ReactNode }[] = [
  { key: "cpu", label: "CPU", icon: <Cpu className="h-4 w-4" aria-hidden /> },
  { key: "mem", label: "Memory", icon: <MemoryStick className="h-4 w-4" aria-hidden /> },
  { key: "net", label: "Network", icon: <Network className="h-4 w-4" aria-hidden /> },
  { key: "disk", label: "Disk", icon: <HardDrive className="h-4 w-4" aria-hidden /> },
  { key: "gpu", label: "GPU", icon: <Gauge className="h-4 w-4" aria-hidden /> },
];

// Utilities

function clamp01(v: number) {
  if (Number.isNaN(v)) return 0;
  return Math.min(1, Math.max(0, v));
}

function pct(v?: number) {
  if (v == null || Number.isNaN(v)) return 0;
  return Math.max(0, Math.min(100, v));
}

function formatPercent(v?: number) {
  return `${pct(v).toFixed(0)}%`;
}

function formatBytesPerSec(n?: number) {
  if (n == null || !Number.isFinite(n)) return "0 B/s";
  const abs = Math.abs(n);
  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  let u = 0;
  let value = abs;
  while (value >= 1024 && u < units.length - 1) {
    value /= 1024;
    u++;
  }
  const signed = n < 0 ? -value : value;
  return `${signed.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${units[u]}`;
}

function formatTime(ts: number) {
  const d = new Date(ts);
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function average(arr: number[]) {
  if (arr.length === 0) return 0;
  let s = 0;
  for (let i = 0; i < arr.length; i++) s += arr[i];
  return s / arr.length;
}

function last<T>(arr: T[]): T | undefined {
  return arr.length ? arr[arr.length - 1] : undefined;
}

const CHART_CLASS = "h-[260px] md:h-[280px] lg:h-[300px]";

// Tooltip content

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: any[];
  label?: string | number;
}) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-xl border bg-popover p-3 text-popover-foreground shadow-sm">
      <div className="text-xs opacity-70">{typeof label === "number" ? formatTime(label) : label}</div>
      <Separator className="my-2" />
      <div className="space-y-1 text-sm">
        {payload.map((p, i) => (
          <div key={i} className="flex items-center justify-between gap-6">
            <div className="flex items-center gap-2">
              <span
                aria-hidden
                className="h-3 w-3 rounded-sm"
                style={{ background: p.color }}
              />
              <span className="opacity-80">{p.name}</span>
            </div>
            <div className="font-medium">{p.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Badge by threshold

function ThresholdBadge({
  value,
  warn,
  crit,
  label,
}: {
  value: number;
  warn: number;
  crit: number;
  label: string;
}) {
  const tone =
    value >= crit ? "destructive" : value >= warn ? "secondary" : "default";
  const text = `${label}: ${formatPercent(value)}`;
  return <Badge variant={tone as any}>{text}</Badge>;
}

// Summary tiles

function SummaryTile({
  icon,
  label,
  value,
  sublabel,
  ariaLabel,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sublabel?: string;
  ariaLabel?: string;
}) {
  return (
    <div
      className="flex min-w-[140px] flex-1 items-center justify-between rounded-xl border p-3"
      role="group"
      aria-label={ariaLabel ?? label}
    >
      <div className="flex items-center gap-2">
        {icon}
        <div className="text-sm opacity-70">{label}</div>
      </div>
      <div className="text-right">
        <div className="text-base font-semibold leading-none">{value}</div>
        {sublabel ? <div className="mt-1 text-xs opacity-60">{sublabel}</div> : null}
      </div>
    </div>
  );
}

// Component

const ResourceUtilization = memo(function ResourceUtilization({
  title = "Resource Utilization",
  description = "Live utilization metrics",
  samples,
  loading,
  error,
  compact,
  className,
  thresholds,
  rangePresets = [
    { key: "5m", label: "5m" },
    { key: "15m", label: "15m" },
    { key: "1h", label: "1h" },
    { key: "24h", label: "24h" },
  ],
  onRefresh,
}: ResourceUtilizationProps) {
  const id = useId();
  const th = { ...DEFAULT_THRESHOLDS, ...(thresholds ?? {}) };
  const [selectedMetric, setSelectedMetric] = useState<MetricKey>("cpu");
  const [smooth, setSmooth] = useState(true);
  const [rangeKey, setRangeKey] = useState<string>(rangePresets[0]?.key ?? "5m");

  // Derived data
  const sorted = useMemo(() => {
    if (!samples?.length) return [];
    return [...samples].sort((a, b) => a.ts - b.ts);
  }, [samples]);

  const cpuArr = useMemo(() => sorted.map(s => pct(s.cpu)), [sorted]);
  const memArr = useMemo(() => sorted.map(s => pct(s.mem)), [sorted]);
  const netInArr = useMemo(() => sorted.map(s => s.netInBytes ?? 0), [sorted]);
  const netOutArr = useMemo(() => sorted.map(s => s.netOutBytes ?? 0), [sorted]);
  const diskR = useMemo(() => sorted.map(s => s.diskReadBytes ?? 0), [sorted]);
  const diskW = useMemo(() => sorted.map(s => s.diskWriteBytes ?? 0), [sorted]);
  const gpuArr = useMemo(() => sorted.map(s => pct(s.gpu)), [sorted]);

  const lastSample = last(sorted);
  const lastCpu = pct(lastSample?.cpu);
  const lastMem = pct(lastSample?.mem);
  const lastGpu = pct(lastSample?.gpu);
  const lastNetIn = lastSample?.netInBytes ?? 0;
  const lastNetOut = lastSample?.netOutBytes ?? 0;
  const lastDiskR = lastSample?.diskReadBytes ?? 0;
  const lastDiskW = lastSample?.diskWriteBytes ?? 0;

  const avgCpu = useMemo(() => average(cpuArr), [cpuArr]);
  const avgMem = useMemo(() => average(memArr), [memArr]);
  const avgGpu = useMemo(() => average(gpuArr), [gpuArr]);
  const avgNetIn = useMemo(() => average(netInArr), [netInArr]);
  const avgNetOut = useMemo(() => average(netOutArr), [netOutArr]);
  const avgDiskR = useMemo(() => average(diskR), [diskR]);
  const avgDiskW = useMemo(() => average(diskW), [diskW]);

  const data = useMemo(
    () =>
      sorted.map((s) => ({
        ts: s.ts,
        cpu: pct(s.cpu),
        mem: pct(s.mem),
        gpu: pct(s.gpu),
        netIn: s.netInBytes ?? 0,
        netOut: s.netOutBytes ?? 0,
        diskR: s.diskReadBytes ?? 0,
        diskW: s.diskWriteBytes ?? 0,
      })),
    [sorted]
  );

  // Visual helpers
  const lineType = smooth ? "monotone" : "linear";

  // Loading and error states
  if (loading) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <Skeleton className="h-9 w-32" />
            <Skeleton className="h-9 w-28" />
            <Skeleton className="h-9 w-10" />
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
          <Skeleton className="h-[300px] w-full" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className={className} role="alert" aria-live="assertive">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-600" aria-hidden />
            {title}
          </CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900">
            {error}
          </div>
          <div className="mt-3 flex items-center gap-2">
            {onRefresh ? (
              <Button variant="secondary" onClick={onRefresh}>
                <RefreshCcw className="mr-2 h-4 w-4" aria-hidden />
                Retry
              </Button>
            ) : null}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={className} aria-labelledby={`${id}-title`} aria-describedby={`${id}-desc`}>
      <CardHeader className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle id={`${id}-title`}>{title}</CardTitle>
            <CardDescription id={`${id}-desc`}>{description}</CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Select value={rangeKey} onValueChange={setRangeKey}>
              <SelectTrigger className="w-[110px]" aria-label="Time range">
                <SelectValue placeholder="Range" />
              </SelectTrigger>
              <SelectContent>
                {rangePresets.map(p => (
                  <SelectItem key={p.key} value={p.key}>{p.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Toggle
              pressed={smooth}
              onPressedChange={setSmooth}
              aria-label="Smoothing"
              title="Smoothing"
            >
              <Activity className="h-4 w-4" aria-hidden />
            </Toggle>

            {onRefresh ? (
              <Button variant="outline" onClick={onRefresh}>
                <RefreshCcw className="mr-2 h-4 w-4" aria-hidden />
                Refresh
              </Button>
            ) : null}
          </div>
        </div>

        {!compact ? (
          <div className="flex flex-wrap items-center gap-2">
            <ThresholdBadge value={lastCpu} warn={th.cpuWarn} crit={th.cpuCrit} label="CPU" />
            <ThresholdBadge value={lastMem} warn={th.memWarn} crit={th.memCrit} label="MEM" />
            {gpuArr.some(v => v > 0) ? (
              <Badge variant={lastGpu >= th.cpuCrit ? "destructive" : lastGpu >= th.cpuWarn ? "secondary" : "default"}>
                GPU: {formatPercent(lastGpu)}
              </Badge>
            ) : null}
            <Badge variant="default">NET: {formatBytesPerSec(lastNetIn)} in · {formatBytesPerSec(lastNetOut)} out</Badge>
            <Badge variant="default">DISK: {formatBytesPerSec(lastDiskR)} r · {formatBytesPerSec(lastDiskW)} w</Badge>
          </div>
        ) : null}
      </CardHeader>

      <CardContent className="space-y-4">
        {!compact ? (
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <SummaryTile
              icon={<Cpu className="h-4 w-4" aria-hidden />}
              label="CPU"
              value={formatPercent(lastCpu)}
              sublabel={`avg ${formatPercent(avgCpu)}`}
              ariaLabel="CPU utilization"
            />
            <SummaryTile
              icon={<MemoryStick className="h-4 w-4" aria-hidden />}
              label="Memory"
              value={formatPercent(lastMem)}
              sublabel={`avg ${formatPercent(avgMem)}`}
              ariaLabel="Memory utilization"
            />
            <SummaryTile
              icon={<Network className="h-4 w-4" aria-hidden />}
              label="Network"
              value={`${formatBytesPerSec(lastNetIn)} in`}
              sublabel={`${formatBytesPerSec(lastNetOut)} out avg ${formatBytesPerSec(avgNetIn)} in`}
              ariaLabel="Network throughput"
            />
            <SummaryTile
              icon={<HardDrive className="h-4 w-4" aria-hidden />}
              label="Disk"
              value={`${formatBytesPerSec(lastDiskR)} r`}
              sublabel={`${formatBytesPerSec(lastDiskW)} w avg ${formatBytesPerSec(avgDiskR)} r`}
              ariaLabel="Disk throughput"
            />
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-2">
          {METRIC_TABS.map(t => (
            <Button
              key={t.key}
              variant={selectedMetric === t.key ? "default" : "ghost"}
              size="sm"
              onClick={() => setSelectedMetric(t.key)}
              aria-pressed={selectedMetric === t.key}
              aria-label={`Show ${t.label} chart`}
              className="gap-2"
            >
              {t.icon}
              {t.label}
            </Button>
          ))}
        </div>

        <motion.div
          key={selectedMetric}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.18 }}
          className="w-full"
        >
          {selectedMetric === "cpu" && (
            <div className={CHART_CLASS}>
              <ResponsiveContainer>
                <LineChart data={data} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="ts" tickFormatter={formatTime} />
                  <YAxis domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                  <Tooltip content={<ChartTooltip />} />
                  <Legend />
                  <ReferenceLine y={th.cpuWarn} strokeDasharray="4 2" />
                  <ReferenceLine y={th.cpuCrit} strokeDasharray="4 2" />
                  <Line type={lineType as any} dataKey="cpu" name="CPU" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {selectedMetric === "mem" && (
            <div className={CHART_CLASS}>
              <ResponsiveContainer>
                <LineChart data={data} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="ts" tickFormatter={formatTime} />
                  <YAxis domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                  <Tooltip content={<ChartTooltip />} />
                  <Legend />
                  <ReferenceLine y={th.memWarn} strokeDasharray="4 2" />
                  <ReferenceLine y={th.memCrit} strokeDasharray="4 2" />
                  <Line type={lineType as any} dataKey="mem" name="Memory" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {selectedMetric === "gpu" && (
            <div className={CHART_CLASS}>
              <ResponsiveContainer>
                <LineChart data={data} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="ts" tickFormatter={formatTime} />
                  <YAxis domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                  <Tooltip content={<ChartTooltip />} />
                  <Legend />
                  <Line type={lineType as any} dataKey="gpu" name="GPU" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {selectedMetric === "net" && (
            <div className={CHART_CLASS}>
              <ResponsiveContainer>
                <AreaChart data={data} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="ts" tickFormatter={formatTime} />
                  <YAxis tickFormatter={(v) => formatBytesPerSec(v)} />
                  <Tooltip
                    content={({ active, payload, label }) => {
                      if (!active || !payload) return null;
                      const mapped = payload.map((p: any) => ({
                        ...p,
                        value:
                          p.dataKey === "netIn" || p.dataKey === "netOut"
                            ? formatBytesPerSec(p.value)
                            : p.value,
                        name: p.dataKey === "netIn" ? "In" : "Out",
                      }));
                      return <ChartTooltip active={active} payload={mapped} label={label} />;
                    }}
                  />
                  <Legend />
                  <Area type={lineType as any} dataKey="netIn" name="In" dot={false} />
                  <Area type={lineType as any} dataKey="netOut" name="Out" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {selectedMetric === "disk" && (
            <div className={CHART_CLASS}>
              <ResponsiveContainer>
                <BarChart data={data} margin={{ top: 12, right: 24, left: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="ts" tickFormatter={formatTime} />
                  <YAxis tickFormatter={(v) => formatBytesPerSec(v)} />
                  <Tooltip
                    content={({ active, payload, label }) => {
                      if (!active || !payload) return null;
                      const mapped = payload.map((p: any) => ({
                        ...p,
                        value:
                          p.dataKey === "diskR" || p.dataKey === "diskW"
                            ? formatBytesPerSec(p.value)
                            : p.value,
                        name: p.dataKey === "diskR" ? "Read" : "Write",
                      }));
                      return <ChartTooltip active={active} payload={mapped} label={label} />;
                    }}
                  />
                  <Legend />
                  <Bar dataKey="diskR" name="Read" />
                  <Bar dataKey="diskW" name="Write" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </motion.div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="text-xs opacity-60">
            Samples: {data.length}
          </div>
          {lastSample ? (
            <div className="text-xs opacity-60">
              Last update: {formatTime(lastSample.ts)}
            </div>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
});

export default ResourceUtilization;

/*
Usage notes:
- Provide `samples` as a time-ordered array or unordered; the component sorts internally by timestamp.
- To prefilter by time range, slice samples on the parent side and pass via props. The local range selector
  is presentational and does not mutate input data by design.
- All formatting is deterministic; no external assumptions are made.
- No remote calls, no side effects; safe to use in SSR and CSR.
*/
