// frontend/src/pages/SystemMonitor.tsx
import React, {
  useEffect,
  useMemo,
  useRef,
  useState,
  useCallback,
  PropsWithChildren,
} from "react";
import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart,
  Bar,
  BarChart,
  Legend,
} from "recharts";
import {
  Activity,
  Cpu,
  HardDrive,
  Network,
  Gauge,
  AlertTriangle,
  RefreshCw,
  TimerReset,
  Webhook,
  PauseCircle,
  PlayCircle,
  Download,
} from "lucide-react";

// shadcn/ui components (предполагается установленный shadcn)
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";

// ============================================================================
// Типы данных
// ============================================================================
type ISODate = string;

type MetricSample = {
  ts: ISODate;
  cpu: number;        // 0..100
  mem: number;        // 0..100
  netIn: number;      // bytes/sec
  netOut: number;     // bytes/sec
  diskR: number;      // bytes/sec
  diskW: number;      // bytes/sec
  reqPerSec: number;  // rps
  errRate: number;    // 0..100 (%)
};

type HealthStatus = "healthy" | "degraded" | "critical" | "unknown";

type NodeInfo = {
  id: string;
  name: string;
  uptimeSec: number;
  version: string;
  region: string;
  status: HealthStatus;
  lastSeen: ISODate;
};

type Snapshot = {
  nodes: NodeInfo[];
  latest: MetricSample | null;
  series: MetricSample[];          // отсортировано по ts
  generatedAt: ISODate;
};

type Thresholds = {
  cpuWarn: number;
  cpuCrit: number;
  memWarn: number;
  memCrit: number;
  errWarn: number; // %
  errCrit: number; // %
};

type FetchMode = "websocket" | "polling";

// ============================================================================
// Константы и утилиты
// ============================================================================
const DEFAULT_THRESHOLDS: Thresholds = {
  cpuWarn: 70,
  cpuCrit: 90,
  memWarn: 75,
  memCrit: 90,
  errWarn: 1,
  errCrit: 5,
};

const RING_BUFFER_MAX = 600; // 10 минут при шаге 1 сек.
const POLL_INTERVAL_MS = 3000;

function clamp01(n: number) {
  return Math.max(0, Math.min(1, n));
}

function formatPercent(n: number) {
  const v = Math.max(0, Math.min(100, n));
  return `${v.toFixed(1)}%`;
}

function formatBytesPerSec(n: number) {
  if (!isFinite(n)) return "0 B/s";
  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  let idx = 0;
  let val = n;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val.toFixed(1)} ${units[idx]}`;
}

function formatTime(ts: ISODate) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString();
  } catch {
    return ts;
  }
}

function healthFromSample(s: MetricSample | null, t: Thresholds): HealthStatus {
  if (!s) return "unknown";
  const cpu = s.cpu;
  const mem = s.mem;
  const err = s.errRate;
  if (cpu >= t.cpuCrit || mem >= t.memCrit || err >= t.errCrit) return "critical";
  if (cpu >= t.cpuWarn || mem >= t.memWarn || err >= t.errWarn) return "degraded";
  return "healthy";
}

function classForHealth(h: HealthStatus) {
  switch (h) {
    case "healthy":
      return "text-green-600";
    case "degraded":
      return "text-amber-600";
    case "critical":
      return "text-red-600";
    default:
      return "text-muted-foreground";
  }
}

function badgeVariantForHealth(h: HealthStatus) {
  switch (h) {
    case "healthy":
      return "outline";
    case "degraded":
      return "secondary";
    case "critical":
      return "destructive";
    default:
      return "outline";
  }
}

// Фиксированный буфер для серий
class RingBuffer<T> {
  private arr: T[] = [];
  constructor(private readonly max: number) {}
  push(item: T) {
    this.arr.push(item);
    if (this.arr.length > this.max) this.arr.shift();
  }
  toArray(): T[] {
    return [...this.arr];
  }
  clear() {
    this.arr = [];
  }
}

// Детерминированный мок на случай недоступности бекенда
function seedRandom(seed: number) {
  // Линейный конгруэнтный генератор
  let x = seed;
  return () => {
    x = (1664525 * x + 1013904223) % 4294967296;
    return x / 4294967296;
  };
}

function generateMockSnapshot(len = 120): Snapshot {
  const rnd = seedRandom(1337);
  const now = Date.now();
  const series: MetricSample[] = Array.from({ length: len }, (_, i) => {
    const ts = new Date(now - (len - 1 - i) * 1000).toISOString();
    const cpu = 40 + Math.sin(i / 9) * 20 + rnd() * 10;
    const mem = 50 + Math.cos(i / 11) * 15 + rnd() * 8;
    const netIn = 200000 + rnd() * 800000;
    const netOut = 150000 + rnd() * 600000;
    const diskR = 50000 + rnd() * 250000;
    const diskW = 50000 + rnd() * 250000;
    const reqPerSec = 120 + Math.sin(i / 7) * 40 + rnd() * 30;
    const errRate = Math.max(0, 0.3 + (rnd() - 0.5) * 0.4);
    return {
      ts,
      cpu: Math.max(0, Math.min(100, cpu)),
      mem: Math.max(0, Math.min(100, mem)),
      netIn,
      netOut,
      diskR,
      diskW,
      reqPerSec,
      errRate,
    };
  });

  const nodes: NodeInfo[] = [
    {
      id: "n-1",
      name: "core-api-1",
      uptimeSec: 86400 * 4 + 3600 * 3 + 42,
      version: "2.3.1",
      region: "eu-central-1",
      status: "healthy",
      lastSeen: new Date(now).toISOString(),
    },
    {
      id: "n-2",
      name: "core-api-2",
      uptimeSec: 86400 * 2 + 610,
      version: "2.3.1",
      region: "eu-west-1",
      status: "degraded",
      lastSeen: new Date(now).toISOString(),
    },
    {
      id: "n-3",
      name: "jobs-worker-1",
      uptimeSec: 7200 + 33,
      version: "1.9.0",
      region: "eu-north-1",
      status: "healthy",
      lastSeen: new Date(now).toISOString(),
    },
  ];

  const latest = series.at(-1) ?? null;
  return {
    nodes,
    latest,
    series,
    generatedAt: new Date(now).toISOString(),
  };
}

function secondsToDhms(sec: number) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d}d ${pad(h)}:${pad(m)}:${pad(s)}`;
}

// ============================================================================
// Error Boundary для жесткой изоляции сбоев
// ============================================================================
class ErrorBoundary extends React.Component<PropsWithChildren, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error) {
    // Можно добавить отправку логов
    // console.error(error);
  }
  render() {
    if (this.state.error) {
      return (
        <Card className="border-red-500/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-700">
              <AlertTriangle className="h-5 w-5" />
              Ошибка интерфейса мониторинга
            </CardTitle>
            <CardDescription>Компонент перешел в безопасный режим отображения.</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="text-sm overflow-auto p-3 bg-red-50 rounded-md">
              {this.state.error.message}
            </pre>
          </CardContent>
        </Card>
      );
    }
    return this.props.children;
  }
}

// ============================================================================
// Основной компонент
// ============================================================================
export type SystemMonitorProps = {
  className?: string;
  streamUrl?: string;    // ws://... или wss://... (приоритет)
  snapshotUrl?: string;  // https://.../api/metrics/snapshot
  fetchMode?: FetchMode; // "websocket" | "polling"
  pollingMs?: number;
  thresholds?: Partial<Thresholds>;
  autoStart?: boolean;
};

const DEFAULT_PROPS: Required<Omit<SystemMonitorProps, "className">> = {
  streamUrl: "ws://localhost:8080/api/metrics/stream",
  snapshotUrl: "/api/metrics/snapshot",
  fetchMode: "websocket",
  pollingMs: POLL_INTERVAL_MS,
  thresholds: DEFAULT_THRESHOLDS,
  autoStart: true,
};

export default function SystemMonitor(props: SystemMonitorProps) {
  const {
    className,
    streamUrl,
    snapshotUrl,
    fetchMode,
    pollingMs,
    thresholds,
    autoStart,
  } = { ...DEFAULT_PROPS, ...props, thresholds: { ...DEFAULT_THRESHOLDS, ...props.thresholds } };

  const { toast } = useToast();

  // Состояния
  const [connected, setConnected] = useState(false);
  const [running, setRunning] = useState(!!autoStart);
  const [activeTab, setActiveTab] = useState<"overview" | "traffic" | "storage" | "nodes">("overview");
  const [search, setSearch] = useState("");
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [mode, setMode] = useState<FetchMode>(fetchMode);
  const [th, setTh] = useState<Thresholds>(thresholds as Thresholds);

  // Буфер для отображаемых серий
  const bufRef = useRef(new RingBuffer<MetricSample>(RING_BUFFER_MAX));
  const wsRef = useRef<WebSocket | null>(null);
  const pollRef = useRef<number | null>(null);

  const latestSample = snap?.latest ?? null;
  const health = useMemo(() => healthFromSample(latestSample, th), [latestSample, th]);

  // Инициализация: первичная загрузка снапшота и запуск стрима/пуллинга
  useEffect(() => {
    let cancelled = false;

    async function loadInitial() {
      try {
        const res = await fetch(snapshotUrl, { headers: { "Accept": "application/json" } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as Snapshot;
        if (cancelled) return;

        // Заполнить буфер
        bufRef.current.clear();
        for (const s of data.series) bufRef.current.push(s);
        setSnap(data);
      } catch {
        // Фоллбэк на мок
        const mock = generateMockSnapshot();
        bufRef.current.clear();
        for (const s of mock.series) bufRef.current.push(s);
        setSnap(mock);

        toast({
          title: "Режим офлайн-данных",
          description: "Бэкенд недоступен. Отображаются тестовые метрики.",
          variant: "default",
        });
      }
    }

    loadInitial();

    return () => {
      cancelled = true;
    };
  }, [snapshotUrl, toast]);

  // Управление стримом/пуллингом
  const stopAll = useCallback(() => {
    setConnected(false);
    if (wsRef.current) {
      try {
        wsRef.current.close(1000, "user stop");
      } catch {}
      wsRef.current = null;
    }
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startWebSocket = useCallback(() => {
    stopAll();
    try {
      const ws = new WebSocket(streamUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
      };
      ws.onmessage = (evt) => {
        try {
          const payload = JSON.parse(evt.data) as MetricSample | Snapshot;
          if ("series" in payload) {
            // Пришёл снапшот
            bufRef.current.clear();
            for (const s of payload.series) bufRef.current.push(s);
            setSnap({
              ...(payload as Snapshot),
              series: bufRef.current.toArray(),
              latest: payload.latest,
            });
          } else {
            // Одна точка
            bufRef.current.push(payload as MetricSample);
            const latest = payload as MetricSample;
            setSnap((prev) => {
              const base = prev ?? generateMockSnapshot(0);
              return {
                ...base,
                latest,
                series: bufRef.current.toArray(),
                generatedAt: new Date().toISOString(),
              };
            });
          }
        } catch {
          // Игнор одиночных сбойных сообщений
        }
      };
      ws.onerror = () => {
        setConnected(false);
      };
      ws.onclose = () => {
        setConnected(false);
        // Автовосстановление в режиме WS, если включено
        if (running && mode === "websocket") {
          setTimeout(() => startWebSocket(), 1500);
        }
      };
    } catch {
      setConnected(false);
    }
  }, [mode, running, stopAll, streamUrl]);

  const startPolling = useCallback(() => {
    stopAll();
    async function pull() {
      try {
        const res = await fetch(snapshotUrl, { headers: { "Accept": "application/json" } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as Snapshot;
        bufRef.current.clear();
        for (const s of data.series) bufRef.current.push(s);
        setSnap({
          ...data,
          series: bufRef.current.toArray(),
        });
        setConnected(true);
      } catch {
        setConnected(false);
      }
    }
    pull();
    pollRef.current = window.setInterval(pull, pollingMs);
  }, [pollingMs, snapshotUrl, stopAll]);

  useEffect(() => {
    if (!running) {
      stopAll();
      return;
    }
    if (mode === "websocket") startWebSocket();
    else startPolling();

    return stopAll;
  }, [mode, running, startPolling, startWebSocket, stopAll]);

  // Управление порогами
  const setThreshold = (key: keyof Thresholds, val: number) => {
    setTh((prev) => ({ ...prev, [key]: Math.max(0, val) }));
  };

  // Фильтрация узлов
  const filteredNodes = useMemo(() => {
    const q = search.trim().toLowerCase();
    const nodes = snap?.nodes ?? [];
    if (!q) return nodes;
    return nodes.filter(
      (n) =>
        n.name.toLowerCase().includes(q) ||
        n.region.toLowerCase().includes(q) ||
        n.version.toLowerCase().includes(q)
    );
  }, [snap?.nodes, search]);

  // Вычислим агрегированные показатели
  const series = useMemo(() => snap?.series ?? [], [snap?.series]);

  const agg = useMemo(() => {
    if (series.length === 0) {
      return {
        avgCpu: 0,
        avgMem: 0,
        peakRps: 0,
        errNow: 0,
        netInNow: 0,
        netOutNow: 0,
      };
    }
    const sumCpu = series.reduce((a, s) => a + s.cpu, 0) / series.length;
    const sumMem = series.reduce((a, s) => a + s.mem, 0) / series.length;
    const peakRps = series.reduce((m, s) => Math.max(m, s.reqPerSec), 0);
    const last = series[series.length - 1];
    return {
      avgCpu: sumCpu,
      avgMem: sumMem,
      peakRps,
      errNow: last.errRate,
      netInNow: last.netIn,
      netOutNow: last.netOut,
    };
  }, [series]);

  // Экспорт CSV
  const exportCsv = () => {
    const rows = [
      ["ts", "cpu", "mem", "netIn", "netOut", "diskR", "diskW", "rps", "errRate"],
      ...series.map((s) => [
        s.ts,
        s.cpu.toFixed(3),
        s.mem.toFixed(3),
        Math.round(s.netIn),
        Math.round(s.netOut),
        Math.round(s.diskR),
        Math.round(s.diskW),
        s.reqPerSec.toFixed(3),
        s.errRate.toFixed(5),
      ]),
    ];
    const csv = rows.map((r) => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `system-metrics_${new Date().toISOString()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Визуальные карточки
  function StatCard({
    icon,
    title,
    value,
    subtitle,
    danger,
    testId,
  }: {
    icon: React.ReactNode;
    title: string;
    value: string;
    subtitle?: string;
    danger?: boolean;
    testId?: string;
  }) {
    return (
      <Card data-testid={testId}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
          <div className={danger ? "text-red-600" : "text-muted-foreground"}>{icon}</div>
        </CardHeader>
        <CardContent>
          <div className={`text-2xl font-bold ${danger ? "text-red-700" : ""}`}>{value}</div>
          {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
        </CardContent>
      </Card>
    );
  }

  const headerRight = (
    <div className="flex items-center gap-2">
      <Badge variant={badgeVariantForHealth(health)} data-testid="badge-health">
        Состояние: {health}
      </Badge>
      <Badge variant={connected ? "outline" : "secondary"} data-testid="badge-conn">
        {connected ? "Подключено" : "Нет соединения"}
      </Badge>
      <Separator orientation="vertical" className="h-6" />
      <div className="flex items-center gap-2">
        <Label htmlFor="auto-run" className="text-sm">Автообновление</Label>
        <Switch
          id="auto-run"
          checked={running}
          onCheckedChange={(v) => setRunning(v)}
          aria-label="Переключить автообновление"
          data-testid="switch-running"
        />
        <Button
          variant="outline"
          size="icon"
          onClick={() => (mode === "websocket" ? startWebSocket() : startPolling())}
          aria-label="Принудительно обновить"
          data-testid="btn-refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          onClick={() => setMode((m) => (m === "websocket" ? "polling" : "websocket"))}
          aria-label="Переключить режим получения данных"
          data-testid="btn-toggle-mode"
          title={mode === "websocket" ? "WebSocket" : "Polling"}
        >
          {mode === "websocket" ? <Webhook className="h-4 w-4" /> : <TimerReset className="h-4 w-4" />}
        </Button>
        <Button
          variant={running ? "secondary" : "default"}
          size="sm"
          onClick={() => setRunning((r) => !r)}
          aria-label={running ? "Пауза" : "Старт"}
          data-testid="btn-run"
          className="gap-1"
        >
          {running ? <PauseCircle className="h-4 w-4" /> : <PlayCircle className="h-4 w-4" />}
          {running ? "Пауза" : "Старт"}
        </Button>
        <Button variant="outline" size="sm" onClick={exportCsv} className="gap-1" data-testid="btn-export">
          <Download className="h-4 w-4" />
          Экспорт CSV
        </Button>
      </div>
    </div>
  );

  return (
    <ErrorBoundary>
      <div className={`flex flex-col gap-4 ${className ?? ""}`} role="main" aria-label="Системный монитор">
        {/* Заголовок */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-semibold flex items-center gap-2">
              <Activity className="h-5 w-5" />
              System Monitor
            </h1>
            <p className="text-sm text-muted-foreground">
              Последнее обновление: {snap?.generatedAt ? formatTime(snap.generatedAt) : "—"}
            </p>
          </div>
          {headerRight}
        </div>

        {/* Сводные метрики */}
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
            <StatCard
              icon={<Cpu className="h-4 w-4" />}
              title="Средняя загрузка CPU"
              value={formatPercent(agg.avgCpu)}
              subtitle={`Текущая: ${formatPercent(latestSample?.cpu ?? 0)}`}
              danger={(latestSample?.cpu ?? 0) >= th.cpuWarn}
              testId="stat-cpu"
            />
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
            <StatCard
              icon={<HardDrive className="h-4 w-4" />}
              title="Средняя загрузка памяти"
              value={formatPercent(agg.avgMem)}
              subtitle={`Текущая: ${formatPercent(latestSample?.mem ?? 0)}`}
              danger={(latestSample?.mem ?? 0) >= th.memWarn}
              testId="stat-mem"
            />
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
            <StatCard
              icon={<Network className="h-4 w-4" />}
              title="Сетевой трафик (вход/выход)"
              value={`${formatBytesPerSec(agg.netInNow)} / ${formatBytesPerSec(agg.netOutNow)}`}
              subtitle="Текущие значения"
              testId="stat-net"
            />
          </motion.div>
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
            <StatCard
              icon={<Gauge className="h-4 w-4" />}
              title="Пиковый RPS"
              value={agg.peakRps.toFixed(0)}
              subtitle={`Ошибки сейчас: ${formatPercent((agg.errNow ?? 0))}`}
              danger={(agg.errNow ?? 0) >= th.errWarn}
              testId="stat-rps"
            />
          </motion.div>
        </div>

        {/* Табы */}
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)} data-testid="tabs">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="overview" data-testid="tab-overview">Обзор</TabsTrigger>
            <TabsTrigger value="traffic" data-testid="tab-traffic">Сеть</TabsTrigger>
            <TabsTrigger value="storage" data-testid="tab-storage">Диск</TabsTrigger>
            <TabsTrigger value="nodes" data-testid="tab-nodes">Узлы</TabsTrigger>
          </TabsList>

          {/* Обзор */}
          <TabsContent value="overview" className="mt-4">
            <div className="grid gap-4 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>CPU / Память</CardTitle>
                  <CardDescription>Динамика загрузки в реальном времени</CardDescription>
                </CardHeader>
                <CardContent className="h-[320px]">
                  {series.length === 0 ? (
                    <SkeletonChart ariaLabel="График CPU/Память" />
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={series} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="ts" tickFormatter={formatTime} minTickGap={32} />
                        <YAxis domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                        <Tooltip
                          labelFormatter={(l) => `Время: ${formatTime(String(l))}`}
                          formatter={(val: any, name: string) =>
                            name === "cpu" || name === "mem"
                              ? [`${Number(val).toFixed(1)} %`, name.toUpperCase()]
                              : [String(val), name]
                          }
                        />
                        <Legend />
                        <Area type="monotone" dataKey="cpu" name="CPU" fillOpacity={0.2} strokeWidth={2} />
                        <Area type="monotone" dataKey="mem" name="MEM" fillOpacity={0.2} strokeWidth={2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Ошибки (%) и RPS</CardTitle>
                  <CardDescription>Текущая нагрузка и уровень ошибок</CardDescription>
                </CardHeader>
                <CardContent className="h-[320px]">
                  {series.length === 0 ? (
                    <SkeletonChart ariaLabel="График RPS/Errors" />
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={series} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="ts" tickFormatter={formatTime} minTickGap={32} />
                        <YAxis yAxisId="left" orientation="left" tickFormatter={(v) => `${v.toFixed(0)}`} />
                        <YAxis yAxisId="right" orientation="right" tickFormatter={(v) => `${v.toFixed(1)}%`} />
                        <Tooltip
                          labelFormatter={(l) => `Время: ${formatTime(String(l))}`}
                          formatter={(val: any, name: string) => {
                            if (name === "reqPerSec") return [Number(val).toFixed(0), "RPS"];
                            if (name === "errRate") return [`${Number(val).toFixed(2)} %`, "Ошибки"];
                            return [String(val), name];
                          }}
                        />
                        <Legend />
                        <Bar yAxisId="left" dataKey="reqPerSec" name="RPS" />
                        <Bar yAxisId="right" dataKey="errRate" name="Ошибки (%)" />
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>
            </div>

            <Card className="mt-4">
              <CardHeader>
                <CardTitle>Пороги алертов</CardTitle>
                <CardDescription>Значения, при которых состояние переходит в degraded/critical</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4 md:grid-cols-3">
                <ThresholdInput
                  id="th-cpu-warn"
                  label="CPU warn %"
                  value={th.cpuWarn}
                  onChange={(v) => setThreshold("cpuWarn", v)}
                />
                <ThresholdInput
                  id="th-cpu-crit"
                  label="CPU critical %"
                  value={th.cpuCrit}
                  onChange={(v) => setThreshold("cpuCrit", v)}
                />
                <ThresholdInput
                  id="th-mem-warn"
                  label="MEM warn %"
                  value={th.memWarn}
                  onChange={(v) => setThreshold("memWarn", v)}
                />
                <ThresholdInput
                  id="th-mem-crit"
                  label="MEM critical %"
                  value={th.memCrit}
                  onChange={(v) => setThreshold("memCrit", v)}
                />
                <ThresholdInput
                  id="th-err-warn"
                  label="Errors warn %"
                  value={th.errWarn}
                  onChange={(v) => setThreshold("errWarn", v)}
                />
                <ThresholdInput
                  id="th-err-crit"
                  label="Errors critical %"
                  value={th.errCrit}
                  onChange={(v) => setThreshold("errCrit", v)}
                />
              </CardContent>
            </Card>
          </TabsContent>

          {/* Сеть */}
          <TabsContent value="traffic" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Сетевой трафик</CardTitle>
                <CardDescription>Входящий/исходящий трафик, байт/с</CardDescription>
              </CardHeader>
              <CardContent className="h-[360px]">
                {series.length === 0 ? (
                  <SkeletonChart ariaLabel="График сети" />
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={series} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="ts" tickFormatter={formatTime} minTickGap={32} />
                      <YAxis tickFormatter={(v) => v >= 1000 ? `${(v / 1024).toFixed(1)}K` : `${v}`} />
                      <Tooltip
                        labelFormatter={(l) => `Время: ${formatTime(String(l))}`}
                        formatter={(val: any, name: string) => {
                          if (name === "netIn") return [formatBytesPerSec(Number(val)), "Входящий"];
                          if (name === "netOut") return [formatBytesPerSec(Number(val)), "Исходящий"];
                          return [String(val), name];
                        }}
                      />
                      <Legend />
                      <Line type="monotone" dataKey="netIn" name="Входящий" dot={false} strokeWidth={2} />
                      <Line type="monotone" dataKey="netOut" name="Исходящий" dot={false} strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Диск */}
          <TabsContent value="storage" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Дисковые операции</CardTitle>
                <CardDescription>Чтение/запись, байт/с</CardDescription>
              </CardHeader>
              <CardContent className="h-[360px]">
                {series.length === 0 ? (
                  <SkeletonChart ariaLabel="График диска" />
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={series} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="ts" tickFormatter={formatTime} minTickGap={32} />
                      <YAxis tickFormatter={(v) => v >= 1000 ? `${(v / 1024).toFixed(1)}K` : `${v}`} />
                      <Tooltip
                        labelFormatter={(l) => `Время: ${formatTime(String(l))}`}
                        formatter={(val: any, name: string) => {
                          if (name === "diskR") return [formatBytesPerSec(Number(val)), "Чтение"];
                          if (name === "diskW") return [formatBytesPerSec(Number(val)), "Запись"];
                          return [String(val), name];
                        }}
                      />
                      <Legend />
                      <Area type="monotone" dataKey="diskR" name="Чтение" fillOpacity={0.2} strokeWidth={2} />
                      <Area type="monotone" dataKey="diskW" name="Запись" fillOpacity={0.2} strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Узлы */}
          <TabsContent value="nodes" className="mt-4">
            <Card>
              <CardHeader className="space-y-2">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Кластерные узлы</CardTitle>
                    <CardDescription>Статус, аптайм, версия, регион</CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Input
                      placeholder="Поиск по имени/региону/версии"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      data-testid="input-search"
                      className="w-[260px]"
                      aria-label="Поиск узла"
                    />
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Узел</TableHead>
                      <TableHead>Состояние</TableHead>
                      <TableHead>Аптайм</TableHead>
                      <TableHead>Версия</TableHead>
                      <TableHead>Регион</TableHead>
                      <TableHead>Последняя активность</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(filteredNodes ?? []).map((n) => (
                      <TableRow key={n.id} data-testid={`node-${n.id}`}>
                        <TableCell className="font-medium">{n.name}</TableCell>
                        <TableCell>
                          <span className={`flex items-center gap-2 ${classForHealth(n.status)}`}>
                            <span className="h-2.5 w-2.5 rounded-full bg-current" aria-hidden />
                            {n.status}
                          </span>
                        </TableCell>
                        <TableCell>{secondsToDhms(n.uptimeSec)}</TableCell>
                        <TableCell>{n.version}</TableCell>
                        <TableCell>{n.region}</TableCell>
                        <TableCell>{formatTime(n.lastSeen)}</TableCell>
                      </TableRow>
                    ))}
                    {filteredNodes.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={6} className="text-center text-muted-foreground">
                          Нет узлов по текущему фильтру
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </ErrorBoundary>
  );
}

// ============================================================================
// Мелкие подкомпоненты
// ============================================================================
function SkeletonChart({ ariaLabel }: { ariaLabel?: string }) {
  return (
    <div
      className="h-full w-full animate-pulse rounded-md bg-muted/40"
      role="img"
      aria-label={ariaLabel ?? "График загружается"}
    />
  );
}

function ThresholdInput({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type="number"
        min={0}
        max={1000}
        step={0.5}
        value={String(value)}
        onChange={(e) => onChange(Number(e.target.value))}
        inputMode="decimal"
      />
    </div>
  );
}
