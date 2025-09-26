// frontend/src/widgets/Monitoring/LiveAnalytics.tsx
import * as React from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Activity,
  Pause,
  Play,
  RefreshCcw,
  Wifi,
  WifiOff,
  AlertTriangle,
  Gauge,
  Timer,
  CircleDot,
} from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip as RTooltip,
  CartesianGrid,
  Legend,
  AreaChart,
  Area,
} from "recharts";

// -----------------------------
// Types
// -----------------------------

export type MetricPoint = {
  ts: number;           // unix ms
  cpu: number;          // 0..100
  mem: number;          // 0..100
  latency: number;      // ms
  rps: number;          // requests per second
  errors: number;       // errors per second
};

export type LiveAnalyticsProps = {
  title?: string;
  /**
   * Endpoint для стрима:
   * - ws://... или wss://...  -> WebSocket
   * - http(s)://.../sse       -> EventSource (SSE)
   * - http(s)://.../poll      -> polling (GET)
   */
  endpoint?: string;
  /**
   * Максимальная длина кольцевого буфера
   */
  bufferSize?: number;
  /**
   * Интервал поллинга, мс (используется при protocol === "poll" или как фолбэк)
   */
  pollIntervalMs?: number;
  /**
   * Начальная пауза воспроизведения
   */
  initiallyPaused?: boolean;
  /**
   * Таймаут реконнекта, мс (максимальный при экспоненциальном бэкоффе)
   */
  maxReconnectDelayMs?: number;
  /**
   * Пользовательский парсер входящих событий (если формат отличается)
   */
  parseEvent?: (raw: any) => MetricPoint | null;
};

type Protocol = "ws" | "sse" | "poll";

// -----------------------------
// Utilities
// -----------------------------

class RingBuffer<T> {
  private arr: T[];
  private head = 0;
  private length_ = 0;

  constructor(private capacity: number) {
    this.arr = new Array(capacity);
  }
  push(item: T) {
    this.arr[(this.head + this.length_) % this.capacity] = item;
    if (this.length_ < this.capacity) {
      this.length_++;
    } else {
      this.head = (this.head + 1) % this.capacity;
    }
  }
  toArray(): T[] {
    const out: T[] = [];
    for (let i = 0; i < this.length_; i++) {
      out.push(this.arr[(this.head + i) % this.capacity]!);
    }
    return out;
  }
  size() {
    return this.length_;
  }
  clear() {
    this.head = 0;
    this.length_ = 0;
  }
}

function pct95(values: number[]): number {
  if (!values.length) return 0;
  const a = [...values].sort((x, y) => x - y);
  const idx = Math.min(a.length - 1, Math.floor(0.95 * (a.length - 1)));
  return a[idx];
}

function average(values: number[]): number {
  if (!values.length) return 0;
  return values.reduce((s, v) => s + v, 0) / values.length;
}

function formatNumber(n: number, digits = 0) {
  return Intl.NumberFormat(undefined, {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  }).format(n);
}

function safeParseDefault(raw: any): MetricPoint | null {
  // Ожидаем сырой объект с полями cpu, mem, latency, rps, errors, ts (ms|iso)
  if (!raw || typeof raw !== "object") return null;
  const tsNum = typeof raw.ts === "number" ? raw.ts : Date.parse(raw.ts);
  if (!Number.isFinite(tsNum)) return null;
  const cpu = Number(raw.cpu);
  const mem = Number(raw.mem);
  const latency = Number(raw.latency);
  const rps = Number(raw.rps);
  const errors = Number(raw.errors);
  if ([cpu, mem, latency, rps, errors].some((v) => !Number.isFinite(v))) return null;
  return { ts: tsNum, cpu, mem, latency, rps, errors };
}

function detectProtocol(endpoint?: string): Protocol {
  if (!endpoint) return "poll";
  if (endpoint.startsWith("ws://") || endpoint.startsWith("wss://")) return "ws";
  // простая эвристика: путь содержит /sse -> SSE
  if (/\/sse(\?|$)/i.test(endpoint)) return "sse";
  return "poll";
}

// -----------------------------
// Live stream hook
// -----------------------------

type StreamState = {
  connected: boolean;
  protocol: Protocol;
  lastError?: string;
  reconnectAttempts: number;
  lastLatencyMs?: number; // сеть: RTT грубо
};

function useLiveStream(opts: {
  endpoint?: string;
  protocol?: Protocol;
  pollIntervalMs: number;
  maxReconnectDelayMs: number;
  paused: boolean;
  onMessage: (point: MetricPoint) => void;
  parseEvent?: (raw: any) => MetricPoint | null;
}) {
  const {
    endpoint,
    protocol: protocolProp,
    pollIntervalMs,
    maxReconnectDelayMs,
    paused,
    onMessage,
    parseEvent,
  } = opts;

  const protocol = protocolProp ?? detectProtocol(endpoint);
  const [state, setState] = useState<StreamState>({
    connected: false,
    protocol,
    reconnectAttempts: 0,
  });

  const wsRef = useRef<WebSocket | null>(null);
  const sseRef = useRef<EventSource | null>(null);
  const pollRef = useRef<number | null>(null);
  const rttStartRef = useRef<number | null>(null);
  const stopAll = () => {
    try {
      wsRef.current?.close();
    } catch {}
    try {
      sseRef.current?.close();
    } catch {}
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  useEffect(() => {
    if (!endpoint || paused) {
      stopAll();
      setState((s) => ({ ...s, connected: false }));
      return;
    }

    let cancelled = false;
    let attempts = 0;

    const connect = () => {
      if (cancelled) return;
      const proto = protocol;
      if (proto === "ws") connectWS();
      else if (proto === "sse") connectSSE();
      else connectPoll();
    };

    const scheduleReconnect = (reason?: string) => {
      attempts += 1;
      const delay = Math.min(maxReconnectDelayMs, 300 * Math.pow(2, attempts));
      setState((s) => ({
        ...s,
        connected: false,
        reconnectAttempts: attempts,
        lastError: reason,
      }));
      window.setTimeout(() => {
        if (!cancelled && !paused) connect();
      }, delay);
    };

    const onPoint = (raw: any) => {
      const t0 = rttStartRef.current;
      if (t0 != null) {
        const rtt = performance.now() - t0;
        rttStartRef.current = null;
        setState((s) => ({ ...s, lastLatencyMs: Math.round(rtt) }));
      }
      const parsed = (parseEvent ?? safeParseDefault)(raw);
      if (parsed) onMessage(parsed);
    };

    const connectWS = () => {
      try {
        const ws = new WebSocket(endpoint!);
        wsRef.current = ws;
        ws.onopen = () => {
          setState((s) => ({
            ...s,
            protocol: "ws",
            connected: true,
            lastError: undefined,
          }));
          attempts = 0;
        };
        ws.onmessage = (ev) => {
          let data: any = null;
          try {
            data = JSON.parse(ev.data);
          } catch {
            data = ev.data;
          }
          onPoint(data);
        };
        ws.onerror = () => {
          // noop; onclose покроет
        };
        ws.onclose = () => {
          setState((s) => ({ ...s, connected: false }));
          scheduleReconnect("ws closed");
        };
        // RTT ping
        const pingId = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            rttStartRef.current = performance.now();
            try {
              ws.send(JSON.stringify({ type: "ping", t: Date.now() }));
            } catch {}
          }
        }, 5000);
        const clearPing = () => window.clearInterval(pingId);
        ws.addEventListener("close", clearPing);
      } catch (e: any) {
        scheduleReconnect(e?.message || "ws error");
      }
    };

    const connectSSE = () => {
      try {
        const es = new EventSource(endpoint!, { withCredentials: false });
        sseRef.current = es;
        es.onopen = () => {
          setState((s) => ({
            ...s,
            protocol: "sse",
            connected: true,
            lastError: undefined,
          }));
          attempts = 0;
        };
        es.onmessage = (ev) => {
          let data: any = null;
          try {
            data = JSON.parse(ev.data);
          } catch {
            data = ev.data;
          }
          onPoint(data);
        };
        es.onerror = () => {
          setState((s) => ({ ...s, connected: false }));
          // EventSource автоматически реконнектится, но подстрахуемся
          scheduleReconnect("sse error");
        };
      } catch (e: any) {
        scheduleReconnect(e?.message || "sse error");
      }
    };

    const connectPoll = () => {
      const tick = async () => {
        try {
          rttStartRef.current = performance.now();
          const res = await fetch(endpoint!, { cache: "no-cache" });
          const data = await res.json();
          // допускаем массив или одиночный объект
          if (Array.isArray(data)) {
            for (const d of data) onPoint(d);
          } else {
            onPoint(data);
          }
          setState((s) => ({
            ...s,
            protocol: "poll",
            connected: true,
            lastError: undefined,
          }));
          attempts = 0;
        } catch (e: any) {
          setState((s) => ({ ...s, connected: false }));
          // не рвем интервал, просто отметим ошибку
          setState((s) => ({ ...s, lastError: e?.message || "poll error" }));
        }
      };
      tick();
      pollRef.current = window.setInterval(tick, Math.max(1000, pollIntervalMs));
    };

    connect();

    return () => {
      cancelled = true;
      stopAll();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [endpoint, protocol, pollIntervalMs, paused, maxReconnectDelayMs, parseEvent, onMessage]);

  return state;
}

// -----------------------------
// Fallback generator (dev/demo)
// -----------------------------

function useFallbackGenerator(enabled: boolean, push: (p: MetricPoint) => void) {
  useEffect(() => {
    if (!enabled) return;
    let t = 0;
    const id = window.setInterval(() => {
      const now = Date.now();
      // Простая псевдонагрузка
      const cpu = 50 + 35 * Math.sin(t / 17) + 10 * Math.random();
      const mem = 40 + 25 * Math.sin(t / 11 + 1) + 8 * Math.random();
      const rps = 120 + 80 * Math.sin(t / 13 + 2) + 20 * Math.random();
      const baseLatency = 120 + 60 * Math.sin(t / 19 + 3);
      const jitter = Math.random() * 40;
      const latency = Math.max(20, baseLatency + jitter);
      const errBase = 2 + Math.max(0, 6 * Math.sin(t / 23 - 1));
      const errors = Math.max(0, errBase + (Math.random() < 0.05 ? 10 : 0));

      push({
        ts: now,
        cpu: Math.max(0, Math.min(100, cpu)),
        mem: Math.max(0, Math.min(100, mem)),
        rps: Math.max(0, rps),
        latency,
        errors,
      });
      t++;
    }, 1000);
    return () => window.clearInterval(id);
  }, [enabled, push]);
}

// -----------------------------
// Main component
// -----------------------------

const DEFAULT_BUFFER = 600; // 10 минут при 1 Hz
const DEFAULT_POLL_MS = 3000;
const DEFAULT_MAX_BACKOFF = 15000;

export default function LiveAnalytics({
  title = "Live Analytics",
  endpoint,
  bufferSize = DEFAULT_BUFFER,
  pollIntervalMs = DEFAULT_POLL_MS,
  initiallyPaused = false,
  maxReconnectDelayMs = DEFAULT_MAX_BACKOFF,
  parseEvent,
}: LiveAnalyticsProps) {
  const protocol = detectProtocol(endpoint);
  const bufferRef = useRef(new RingBuffer<MetricPoint>(bufferSize));
  const [, force] = useState(0);
  const [paused, setPaused] = useState(initiallyPaused);
  const [useDemo, setUseDemo] = useState(!endpoint);

  const pushPoint = (p: MetricPoint) => {
    bufferRef.current.push(p);
    // Тригерим рендер
    force((x) => x + 1);
  };

  const stream = useLiveStream({
    endpoint,
    protocol,
    pollIntervalMs,
    maxReconnectDelayMs,
    paused: paused || useDemo, // если демо включен, реальное соединение не нужно
    onMessage: pushPoint,
    parseEvent,
  });

  useFallbackGenerator(useDemo && !paused, pushPoint);

  const data = useMemo(() => bufferRef.current.toArray(), [bufferRef.current.size()]);

  const stats = useMemo(() => {
    const lat = data.map((d) => d.latency);
    const cpu = data.map((d) => d.cpu);
    const rps = data.map((d) => d.rps);
    const err = data.map((d) => d.errors);
    return {
      p95Latency: Math.round(pct95(lat)),
      avgCpu: average(cpu),
      avgRps: average(rps),
      avgErr: average(err),
    };
  }, [data]);

  const statusBadge = (() => {
    if (useDemo) {
      return (
        <Badge variant="secondary" className="gap-1">
          <CircleDot className="h-3 w-3" />
          Demo
        </Badge>
      );
    }
    if (stream.connected) {
      return (
        <Badge className="gap-1">
          <Wifi className="h-3 w-3" />
          Online
        </Badge>
      );
    }
    return (
      <Badge variant="destructive" className="gap-1">
        <WifiOff className="h-3 w-3" />
        Offline
      </Badge>
    );
  })();

  const connectionInfo = (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      <span>Protocol: {useDemo ? "demo" : stream.protocol}</span>
      <span>•</span>
      <span>Reconnects: {stream.reconnectAttempts}</span>
      {stream.lastLatencyMs != null && (
        <>
          <span>•</span>
          <span className="inline-flex items-center gap-1">
            <Timer className="h-3 w-3" />
            {stream.lastLatencyMs} ms RTT
          </span>
        </>
      )}
      {stream.lastError && (
        <>
          <span>•</span>
          <span className="inline-flex items-center gap-1 text-red-600 dark:text-red-500">
            <AlertTriangle className="h-3 w-3" />
            {stream.lastError}
          </span>
        </>
      )}
    </div>
  );

  const formattedData = useMemo(
    () =>
      data.map((d) => ({
        ...d,
        time: new Date(d.ts).toLocaleTimeString(undefined, {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
      })),
    [data]
  );

  const resetBuffer = () => {
    bufferRef.current.clear();
    force((x) => x + 1);
  };

  return (
    <Card className="w-full">
      <CardHeader className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            <CardTitle>{title}</CardTitle>
            {statusBadge}
          </div>
          <div className="flex items-center gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => setPaused((p) => !p)}
                  aria-label={paused ? "Resume" : "Pause"}
                >
                  {paused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
                </Button>
              </TooltipTrigger>
              <TooltipContent>{paused ? "Resume stream" : "Pause stream"}</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="outline" size="icon" onClick={resetBuffer} aria-label="Reset buffer">
                  <RefreshCcw className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Reset in-memory buffer</TooltipContent>
            </Tooltip>
            <div className="flex items-center gap-2 pl-2">
              <Switch id="demo" checked={useDemo} onCheckedChange={setUseDemo} />
              <label htmlFor="demo" className="text-sm text-muted-foreground select-none">
                Demo data
              </label>
            </div>
          </div>
        </div>
        {connectionInfo}
      </CardHeader>

      <CardContent className="space-y-6">
        {/* KPI row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <KpiCard
            title="P95 latency"
            icon={<Timer className="h-4 w-4" />}
            value={`${stats.p95Latency} ms`}
            sparkline={formattedData.map((d) => ({ time: d.time, v: d.latency }))}
          />
          <KpiCard
            title="Average CPU"
            icon={<Gauge className="h-4 w-4" />}
            value={`${formatNumber(stats.avgCpu, 1)} %`}
            sparkline={formattedData.map((d) => ({ time: d.time, v: d.cpu }))}
          />
          <KpiCard
            title="Avg RPS"
            icon={<Activity className="h-4 w-4" />}
            value={formatNumber(stats.avgRps, 1)}
            sparkline={formattedData.map((d) => ({ time: d.time, v: d.rps }))}
          />
          <KpiCard
            title="Avg errors/s"
            icon={<AlertTriangle className="h-4 w-4" />}
            value={formatNumber(stats.avgErr, 2)}
            sparkline={formattedData.map((d) => ({ time: d.time, v: d.errors }))}
          />
        </div>

        {/* Main chart */}
        <div className="h-80 rounded-2xl border">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={formattedData} margin={{ top: 8, right: 24, left: 8, bottom: 8 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" tick={{ fontSize: 12 }} />
              <YAxis
                yAxisId="left"
                tick={{ fontSize: 12 }}
                domain={[0, 100]}
                tickFormatter={(v) => `${v}%`}
              />
              <YAxis
                yAxisId="right"
                orientation="right"
                tick={{ fontSize: 12 }}
                tickFormatter={(v) => `${v}`}
              />
              <RTooltip
                formatter={(value: any, name: any) => [formatNumber(Number(value), 2), name]}
              />
              <Legend />
              <Line
                yAxisId="left"
                type="monotone"
                dataKey="cpu"
                name="CPU %"
                dot={false}
                isAnimationActive={false}
                strokeWidth={2}
              />
              <Line
                yAxisId="left"
                type="monotone"
                dataKey="mem"
                name="MEM %"
                dot={false}
                isAnimationActive={false}
                strokeDasharray="4 2"
                strokeWidth={2}
              />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="rps"
                name="RPS"
                dot={false}
                isAnimationActive={false}
                strokeWidth={2}
              />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="errors"
                name="Errors/s"
                dot={false}
                isAnimationActive={false}
                strokeDasharray="2 2"
                strokeWidth={2}
              />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="latency"
                name="Latency ms"
                dot={false}
                isAnimationActive={false}
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Secondary area chart */}
        <div className="h-48 rounded-2xl border">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={formattedData} margin={{ top: 8, right: 24, left: 8, bottom: 8 }}>
              <defs>
                <linearGradient id="gradLatency" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopOpacity={0.4} />
                  <stop offset="95%" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <RTooltip formatter={(value: any, name: any) => [formatNumber(Number(value), 2), name]} />
              <Area
                type="monotone"
                dataKey="latency"
                name="Latency ms"
                fillOpacity={1}
                fill="url(#gradLatency)"
                strokeWidth={2}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

// -----------------------------
// KPI Card with sparkline
// -----------------------------

function KpiCard({
  title,
  value,
  icon,
  sparkline,
}: {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  sparkline: { time: string; v: number }[];
}) {
  return (
    <motion.div
      initial={{ opacity: 0.6, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      <Card className="h-full">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="text-sm text-muted-foreground">{title}</div>
            <div className="text-muted-foreground">{icon}</div>
          </div>
          <div className="mt-1 text-2xl font-semibold">{value}</div>
          <div className="mt-3 h-12">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sparkline}>
                <XAxis dataKey="time" hide />
                <YAxis hide />
                <Line
                  type="monotone"
                  dataKey="v"
                  dot={false}
                  isAnimationActive={false}
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
