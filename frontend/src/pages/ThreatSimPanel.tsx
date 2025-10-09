// frontend/src/pages/ThreatSimPanel.tsx
// Industrial-grade Threat Simulation Panel
// Dependencies expected in project: react, framer-motion, lucide-react, recharts, class-variance-authority or clsx, shadcn/ui, tailwindcss
// If shadcn/ui path aliases differ, update "@/components/ui/*" imports accordingly.

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  Suspense,
} from "react";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bug,
  Clock,
  Download,
  Filter,
  LineChart as LineChartIcon,
  Pause,
  Play,
  RefreshCw,
  Save,
  ServerCrash,
  Shield,
  ShieldAlert,
  TerminalSquare,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

// shadcn/ui components (adjust import paths to your project setup)
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/components/ui/use-toast";

// ---------- Types ----------
type Severity = "low" | "medium" | "high" | "critical";

type ThreatEvent = {
  id: string;
  ts: string; // ISO
  tactic: string; // e.g., Initial Access, Lateral Movement
  technique: string; // e.g., T1059
  src: string;
  dst: string;
  severity: Severity;
  status: "detected" | "blocked" | "missed";
  latencyMs?: number;
};

type Scenario = {
  id: string;
  name: string;
  description: string;
  defaultIntensity: number; // 1..100
  defaultDurationMin: number; // 1..180
  tags: string[];
};

type RunStatus = {
  activeRuns: number;
  alerts: number;
  mttdSec: number; // Mean Time To Detect (sec)
  mttrMin: number; // Mean Time To Respond (min)
};

type TimeSeriesPoint = { t: string; attacks: number; alerts: number; blocked: number };
type TacticAgg = { tactic: string; count: number };
type RadarPoint = { subject: string; A: number; fullMark: number };

// ---------- Constants ----------
const API_BASE = "/api/threatsim";
const WS_URL = ((): string => {
  if (typeof window === "undefined") return "";
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/ws/threatsim`;
})();

const LOG_LIMIT = 1500; // max log lines kept in memory
const TABLE_PAGE_SIZE = 50;

// ---------- Utilities ----------
function cn(...classes: Array<string | undefined | false>) {
  return classes.filter(Boolean).join(" ");
}

function useDebounced<T>(value: T, delay = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), delay);
    return () => clearTimeout(id);
  }, [value, delay]);
  return v;
}

function usePersistedState<T>(key: string, initial: T) {
  const [state, setState] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      return raw ? (JSON.parse(raw) as T) : initial;
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(state));
    } catch {
      // ignore quotas
    }
  }, [key, state]);
  return [state, setState] as const;
}

// ---------- Data hooks ----------
function useThreatData(params: {
  from?: string;
  to?: string;
  tactic?: string;
  severity?: Severity | "any";
  q?: string;
}) {
  const abortRef = useRef<AbortController | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [series, setSeries] = useState<TimeSeriesPoint[]>([]);
  const [tactics, setTactics] = useState<TacticAgg[]>([]);
  const [status, setStatus] = useState<RunStatus | null>(null);

  const debouncedParams = useDebounced(params, 400);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    const qs = new URLSearchParams();
    if (debouncedParams.from) qs.set("from", debouncedParams.from);
    if (debouncedParams.to) qs.set("to", debouncedParams.to);
    if (debouncedParams.tactic) qs.set("tactic", debouncedParams.tactic);
    if (debouncedParams.severity && debouncedParams.severity !== "any")
      qs.set("severity", debouncedParams.severity);
    if (debouncedParams.q) qs.set("q", debouncedParams.q);

    try {
      const [ev, ts, tac, st] = await Promise.all([
        fetch(`${API_BASE}/events?${qs.toString()}`, { signal: ac.signal }),
        fetch(`${API_BASE}/series?${qs.toString()}`, { signal: ac.signal }),
        fetch(`${API_BASE}/tactics?${qs.toString()}`, { signal: ac.signal }),
        fetch(`${API_BASE}/status`, { signal: ac.signal }),
      ]);

      if (!ev.ok || !ts.ok || !tac.ok || !st.ok) {
        const detail =
          `events:${ev.status} series:${ts.status} tactics:${tac.status} status:${st.status}`;
        throw new Error(`Backend error: ${detail}`);
      }

      const [evJson, tsJson, tacJson, stJson] = await Promise.all([
        ev.json(),
        ts.json(),
        tac.json(),
        st.json(),
      ]);

      setEvents(evJson as ThreatEvent[]);
      setSeries(tsJson as TimeSeriesPoint[]);
      setTactics(tacJson as TacticAgg[]);
      setStatus(stJson as RunStatus);
    } catch (e: any) {
      if (e?.name !== "AbortError") setError(e?.message || "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [debouncedParams]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  return { loading, error, events, series, tactics, status, reload: load };
}

function useScenarios() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    setLoading(true);
    fetch(`${API_BASE}/scenarios`)
      .then(async (r) => {
        if (!r.ok) throw new Error(`Failed: ${r.status}`);
        const data = (await r.json()) as Scenario[];
        if (active) setScenarios(data);
      })
      .catch((e: any) => setError(e?.message || "Failed scenarios"))
      .finally(() => setLoading(false));
    return () => {
      active = false;
    };
  }, []);
  return { scenarios, loading, error };
}

function useThreatLogs(enabled: boolean) {
  const [connected, setConnected] = useState(false);
  const [lines, setLines] = useState<string[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!enabled || !WS_URL) return;
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    ws.onmessage = (msg) => {
      const text = typeof msg.data === "string" ? msg.data : "";
      // Batch append with limit
      setLines((prev) => {
        const next = [...prev, text];
        if (next.length > LOG_LIMIT) next.splice(0, next.length - LOG_LIMIT);
        return next;
      });
    };

    return () => {
      ws.close();
      setConnected(false);
    };
  }, [enabled]);

  const clear = useCallback(() => setLines([]), []);

  return { connected, lines, clear };
}

// ---------- Components ----------
function ErrorBoundaryWrapper({ children }: { children: React.ReactNode }) {
  return (
    <ErrorBoundary
      fallback={
        <Card className="border-destructive/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ServerCrash className="h-5 w-5" />
              Ошибка загрузки панели
            </CardTitle>
            <CardDescription>
              Попробуйте обновить данные или проверьте доступность бэкенда.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => location.reload()} variant="secondary" className="gap-2">
              <RefreshCw className="h-4 w-4" />
              Обновить страницу
            </Button>
          </CardContent>
        </Card>
      }
    >
      {children}
    </ErrorBoundary>
  );
}

class ErrorBoundary extends React.Component<
  { fallback: React.ReactNode; children: React.ReactNode },
  { hasError: boolean }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(error: any, info: any) {
    // Optionally report to Sentry/otel
    console.error("ThreatSimPanel crashed:", error, info);
  }
  render() {
    if (this.state.hasError) return this.props.fallback;
    return this.props.children;
  }
}

function SkeletonCard({ title }: { title: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>Загрузка…</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-24 w-full animate-pulse rounded-xl bg-muted" />
      </CardContent>
    </Card>
  );
}

function KpiCard(props: {
  title: string;
  value: string | number;
  icon: React.ComponentType<any>;
  delta?: string;
  tone?: "default" | "warning" | "critical" | "success";
  testId?: string;
}) {
  const color =
    props.tone === "critical"
      ? "text-red-600"
      : props.tone === "warning"
      ? "text-amber-600"
      : props.tone === "success"
      ? "text-emerald-600"
      : "text-foreground";
  const Icon = props.icon;
  return (
    <Card data-testid={props.testId}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{props.title}</CardTitle>
        <Icon className={cn("h-5 w-5", color)} aria-hidden />
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-bold">{props.value}</div>
        {props.delta && <p className="text-xs text-muted-foreground mt-1">{props.delta}</p>}
      </CardContent>
    </Card>
  );
}

// ---------- Main Page ----------
export default function ThreatSimPanel() {
  const { toast } = useToast();

  // Filters state
  const [from, setFrom] = usePersistedState<string>(
    "threatsim.from",
    new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
  );
  const [to, setTo] = usePersistedState<string>("threatsim.to", new Date().toISOString());
  const [tactic, setTactic] = usePersistedState<string>("threatsim.tactic", "");
  const [severity, setSeverity] = usePersistedState<Severity | "any">("threatsim.sev", "any");
  const [q, setQ] = usePersistedState<string>("threatsim.q", "");
  const [liveLogs, setLiveLogs] = usePersistedState<boolean>("threatsim.livelogs", true);

  const { loading, error, events, series, tactics, status, reload } = useThreatData({
    from,
    to,
    tactic: tactic || undefined,
    severity,
    q,
  });

  const { connected, lines, clear } = useThreatLogs(liveLogs);
  const { scenarios } = useScenarios();

  // Pagination for table
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(events.length / TABLE_PAGE_SIZE));
  useEffect(() => {
    if (page >= pages) setPage(0);
  }, [events.length, pages, page]);

  const pageSlice = useMemo(() => {
    const start = page * TABLE_PAGE_SIZE;
    return events.slice(start, start + TABLE_PAGE_SIZE);
  }, [events, page]);

  // Simulation dialog
  const [openRun, setOpenRun] = useState(false);
  const [scenarioId, setScenarioId] = useState<string>("");
  const activeScenario = useMemo(
    () => scenarios.find((s) => s.id === scenarioId),
    [scenarios, scenarioId],
  );
  const [intensity, setIntensity] = useState<number>(70);
  const [duration, setDuration] = useState<number>(30);
  useEffect(() => {
    if (activeScenario) {
      setIntensity(activeScenario.defaultIntensity);
      setDuration(activeScenario.defaultDurationMin);
    }
  }, [activeScenario]);

  const runSimulation = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenarioId,
          intensity,
          durationMin: duration,
          from: new Date().toISOString(),
        }),
      });
      if (!r.ok) throw new Error(`Run failed: ${r.status}`);
      toast({ title: "Симуляция запущена", description: "Следите за логами и метриками." });
      setOpenRun(false);
      reload();
    } catch (e: any) {
      toast({
        title: "Не удалось запустить",
        description: e?.message || "Ошибка запуска",
        variant: "destructive",
      });
    }
  }, [scenarioId, intensity, duration, reload, toast]);

  // Export data
  const exportCSV = useCallback(() => {
    const headers = [
      "id",
      "ts",
      "tactic",
      "technique",
      "src",
      "dst",
      "severity",
      "status",
      "latencyMs",
    ];
    const rows = events.map((e) =>
      [
        e.id,
        e.ts,
        e.tactic,
        e.technique,
        e.src,
        e.dst,
        e.severity,
        e.status,
        e.latencyMs ?? "",
      ].join(","),
    );
    const blob = new Blob([headers.join(",") + "\n" + rows.join("\n")], {
      type: "text/csv;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.download = `threatsim_${Date.now()}.csv`;
    a.href = url;
    a.click();
    URL.revokeObjectURL(url);
  }, [events]);

  const resetFilters = useCallback(() => {
    setFrom(new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString());
    setTo(new Date().toISOString());
    setTactic("");
    setSeverity("any");
    setQ("");
    setPage(0);
  }, [setFrom, setTo, setTactic, setSeverity, setQ]);

  // Derived charts data
  const radarData: RadarPoint[] = useMemo(() => {
    const agg = new Map<string, number>();
    tactics.forEach((t) => agg.set(t.tactic, (agg.get(t.tactic) ?? 0) + t.count));
    const entries = [...agg.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    const max = entries.reduce((m, [, v]) => Math.max(m, v), 0) || 1;
    return entries.map(([tactic, cnt]) => ({
      subject: tactic,
      A: cnt,
      fullMark: max,
    }));
  }, [tactics]);

  // Accessibility: announce errors
  useEffect(() => {
    if (error) {
      toast({
        title: "Ошибка загрузки",
        description: error,
        variant: "destructive",
      });
    }
  }, [error, toast]);

  // Render
  return (
    <ErrorBoundaryWrapper>
      <div className="flex flex-col gap-4 p-4 md:p-6" aria-label="Threat Simulation Panel">
        <Header reload={reload} exportCSV={exportCSV} />

        <Filters
          from={from}
          to={to}
          tactic={tactic}
          severity={severity}
          q={q}
          setFrom={setFrom}
          setTo={setTo}
          setTactic={setTactic}
          setSeverity={setSeverity}
          setQ={setQ}
          reset={resetFilters}
        />

        <section className="grid gap-4 md:gap-6 grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
          {status ? (
            <>
              <KpiCard
                title="Активные симуляции"
                value={status.activeRuns}
                icon={Activity}
                tone={status.activeRuns > 0 ? "success" : "default"}
                testId="kpi-active"
              />
              <KpiCard
                title="Детектов за период"
                value={status.alerts}
                icon={ShieldAlert}
                tone={status.alerts > 0 ? "warning" : "default"}
                testId="kpi-alerts"
              />
              <KpiCard
                title="MTTD, сек"
                value={status.mttdSec}
                icon={Clock}
                tone={status.mttdSec > 60 ? "warning" : "default"}
                testId="kpi-mttd"
              />
              <KpiCard
                title="MTTR, мин"
                value={status.mttrMin}
                icon={Shield}
                tone={status.mttrMin > 15 ? "warning" : "default"}
                testId="kpi-mttr"
              />
            </>
          ) : (
            <>
              <SkeletonCard title="Активные симуляции" />
              <SkeletonCard title="Детекты" />
              <SkeletonCard title="MTTD" />
              <SkeletonCard title="MTTR" />
            </>
          )}
        </section>

        <section className="grid grid-cols-1 2xl:grid-cols-2 gap-4 md:gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <LineChartIcon className="h-5 w-5" />
                  Динамика атак и реакций
                </CardTitle>
                <CardDescription>События по времени</CardDescription>
              </div>
              <Badge variant="secondary">{series.length} точек</Badge>
            </CardHeader>
            <CardContent className="h-[320px]">
              {loading ? (
                <div className="h-full w-full animate-pulse rounded-xl bg-muted" />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedTimeChart data={series} />
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5" />
                  Тактики MITRE ATT&CK
                </CardTitle>
                <CardDescription>Агрегация по тактикам</CardDescription>
              </div>
              <Badge variant="secondary">{tactics.length} тактик</Badge>
            </CardHeader>
            <CardContent className="h-[320px]">
              {loading ? (
                <div className="h-full w-full animate-pulse rounded-xl bg-muted" />
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 h-full">
                  <div className="h-[280px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={tactics}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="tactic" hide />
                        <YAxis allowDecimals={false} />
                        <Tooltip />
                        <Bar dataKey="count" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="h-[280px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart data={radarData}>
                        <PolarGrid />
                        <PolarAngleAxis dataKey="subject" />
                        <PolarRadiusAxis />
                        <Radar dataKey="A" />
                        <Tooltip />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4 md:gap-6">
          <EventsTable
            loading={loading}
            events={pageSlice}
            total={events.length}
            page={page}
            pages={pages}
            setPage={setPage}
          />

          <LogsCard
            enabled={liveLogs}
            setEnabled={setLiveLogs}
            connected={connected}
            lines={lines}
            clear={clear}
          />
        </section>

        <ActionsBar
          openRun={openRun}
          setOpenRun={setOpenRun}
          setScenarioId={setScenarioId}
          scenarioId={scenarioId}
          scenarios={scenarios}
          duration={duration}
          setDuration={setDuration}
          intensity={intensity}
          setIntensity={setIntensity}
          runSimulation={runSimulation}
        />
      </div>
    </ErrorBoundaryWrapper>
  );
}

// ---------- Sub-components ----------
function Header({ reload, exportCSV }: { reload: () => void; exportCSV: () => void }) {
  return (
    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
      <motion.h1
        className="text-2xl md:text-3xl font-semibold tracking-tight"
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
      >
        Threat Simulation Panel
      </motion.h1>
      <div className="flex items-center gap-2">
        <Button variant="outline" className="gap-2" onClick={reload} aria-label="Обновить данные">
          <RefreshCw className="h-4 w-4" />
          Обновить
        </Button>
        <Button variant="outline" className="gap-2" onClick={exportCSV} aria-label="Экспорт CSV">
          <Download className="h-4 w-4" />
          Экспорт CSV
        </Button>
        <Badge variant="secondary" className="text-xs">
          Build: {import.meta?.env?.VITE_APP_BUILD || "dev"}
        </Badge>
      </div>
    </div>
  );
}

function Filters(props: {
  from: string;
  to: string;
  tactic: string;
  severity: Severity | "any";
  q: string;
  setFrom: (v: string) => void;
  setTo: (v: string) => void;
  setTactic: (v: string) => void;
  setSeverity: (v: Severity | "any") => void;
  setQ: (v: string) => void;
  reset: () => void;
}) {
  // Human-friendly inputs bound to ISO state
  const [fromLocal, setFromLocal] = useState(props.from);
  const [toLocal, setToLocal] = useState(props.to);
  useEffect(() => setFromLocal(props.from), [props.from]);
  useEffect(() => setToLocal(props.to), [props.to]);

  const onApplyDates = () => {
    props.setFrom(new Date(fromLocal).toISOString());
    props.setTo(new Date(toLocal).toISOString());
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <Filter className="h-5 w-5" />
          <CardTitle>Фильтры</CardTitle>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={props.reset}>
            Сбросить
          </Button>
        </div>
      </CardHeader>
      <CardContent className="grid grid-cols-1 md:grid-cols-12 gap-3 md:gap-4">
        <div className="md:col-span-3">
          <Label htmlFor="from">От</Label>
          <Input
            id="from"
            type="datetime-local"
            value={toLocalDateTimeLocal(fromLocal)}
            onChange={(e) => setFromLocal(fromLocalToIso(e.target.value))}
            aria-label="Дата от"
          />
        </div>
        <div className="md:col-span-3">
          <Label htmlFor="to">До</Label>
          <Input
            id="to"
            type="datetime-local"
            value={toLocalDateTimeLocal(toLocal)}
            onChange={(e) => setToLocal(fromLocalToIso(e.target.value))}
            aria-label="Дата до"
          />
        </div>
        <div className="md:col-span-2">
          <Label htmlFor="tactic">Тактика</Label>
          <Input
            id="tactic"
            placeholder="Напр. Lateral Movement"
            value={props.tactic}
            onChange={(e) => props.setTactic(e.target.value)}
            aria-label="Фильтр тактики"
          />
        </div>
        <div className="md:col-span-2">
          <Label>Критичность</Label>
          <Select
            value={props.severity}
            onValueChange={(v) => props.setSeverity(v as Severity | "any")}
          >
            <SelectTrigger aria-label="Фильтр критичности">
              <SelectValue placeholder="Любая" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">Любая</SelectItem>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="md:col-span-2">
          <Label htmlFor="q">Поиск</Label>
          <Input
            id="q"
            placeholder="host:user, T1059, 10.0.0.1"
            value={props.q}
            onChange={(e) => props.setQ(e.target.value)}
            aria-label="Поиск по событиям"
          />
        </div>
        <div className="md:col-span-12 flex justify-end gap-2">
          <Button variant="outline" onClick={onApplyDates}>
            Применить даты
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function ComposedTimeChart({ data }: { data: TimeSeriesPoint[] }) {
  return (
    <AreaChart data={data}>
      <defs>
        <linearGradient id="attacks" x1="0" y1="0" x2="0" y2="1">
          <stop offset="5%" stopOpacity={0.35} />
          <stop offset="95%" stopOpacity={0.05} />
        </linearGradient>
      </defs>
      <CartesianGrid strokeDasharray="3 3" />
      <XAxis dataKey="t" tickFormatter={(v) => shortTime(v)} />
      <YAxis allowDecimals={false} />
      <Tooltip labelFormatter={(v) => formatDate(new Date(v), "yyyy-MM-dd HH:mm:ss")} />
      <Legend />
      <Area type="monotone" dataKey="attacks" fill="url(#attacks)" />
      <Line type="monotone" dataKey="alerts" />
      <Line type="monotone" dataKey="blocked" />
    </AreaChart>
  );
}

function EventsTable(props: {
  loading: boolean;
  events: ThreatEvent[];
  total: number;
  page: number;
  pages: number;
  setPage: (p: number) => void;
}) {
  return (
    <Card className="overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Bug className="h-5 w-5" />
            События
          </CardTitle>
          <CardDescription>Всего: {props.total}</CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={props.page <= 0}
            onClick={() => props.setPage(Math.max(0, props.page - 1))}
          >
            Назад
          </Button>
          <span className="text-sm">
            Стр. {props.page + 1} / {props.pages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={props.page >= props.pages - 1}
            onClick={() => props.setPage(Math.min(props.pages - 1, props.page + 1))}
          >
            Вперед
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div role="table" className="w-full">
          <div className="grid grid-cols-12 px-4 py-2 text-xs font-medium text-muted-foreground" role="row">
            <div className="col-span-2">Время</div>
            <div className="col-span-2">Тактика</div>
            <div className="col-span-2">Техника</div>
            <div className="col-span-2">Источник</div>
            <div className="col-span-2">Назначение</div>
            <div className="col-span-1">Sev</div>
            <div className="col-span-1">Статус</div>
          </div>
          <Separator />
          <ScrollArea className="h-[360px]">
            {props.loading ? (
              <div className="p-4">
                <div className="h-10 animate-pulse rounded bg-muted mb-2" />
                <div className="h-10 animate-pulse rounded bg-muted mb-2" />
                <div className="h-10 animate-pulse rounded bg-muted" />
              </div>
            ) : props.events.length === 0 ? (
              <div className="p-6 text-sm text-muted-foreground">Нет данных для выбранных фильтров.</div>
            ) : (
              <ul role="rowgroup">
                {props.events.map((e) => (
                  <li
                    key={e.id}
                    role="row"
                    className="grid grid-cols-12 px-4 py-2 hover:bg-muted/50 transition-colors"
                  >
                    <div className="col-span-2 text-sm">{formatDate(new Date(e.ts), "yyyy-MM-dd HH:mm:ss")}</div>
                    <div className="col-span-2 text-sm">{e.tactic}</div>
                    <div className="col-span-2 text-sm">{e.technique}</div>
                    <div className="col-span-2 text-sm">{e.src}</div>
                    <div className="col-span-2 text-sm">{e.dst}</div>
                    <div className="col-span-1">
                      <SeverityBadge sev={e.severity} />
                    </div>
                    <div className="col-span-1">
                      <StatusBadge status={e.status} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </ScrollArea>
        </div>
      </CardContent>
    </Card>
  );
}

function LogsCard(props: {
  enabled: boolean;
  setEnabled: (v: boolean) => void;
  connected: boolean;
  lines: string[];
  clear: () => void;
}) {
  const endRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [props.lines.length]);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <TerminalSquare className="h-5 w-5" />
            Live-логи
          </CardTitle>
          <CardDescription>
            {props.enabled ? (props.connected ? "Подключено" : "Подключение…") : "Отключено"}
          </CardDescription>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Label htmlFor="live">Live</Label>
            <Switch id="live" checked={props.enabled} onCheckedChange={props.setEnabled} />
          </div>
          <Button variant="outline" size="sm" onClick={props.clear} aria-label="Очистить логи">
            Очистить
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div
          className="h-[360px] w-full rounded-lg bg-black text-green-300 font-mono text-xs p-3 overflow-auto"
          role="log"
          aria-live="polite"
        >
          {props.lines.length === 0 ? (
            <span className="text-neutral-500">Нет сообщений</span>
          ) : (
            props.lines.map((l, i) => (
              <div key={i} className="whitespace-pre-wrap">
                {l}
              </div>
            ))
          )}
          <div ref={endRef} />
        </div>
      </CardContent>
    </Card>
  );
}

function ActionsBar(props: {
  openRun: boolean;
  setOpenRun: (v: boolean) => void;
  scenarios: Scenario[];
  scenarioId: string;
  setScenarioId: (v: string) => void;
  intensity: number;
  setIntensity: (v: number) => void;
  duration: number;
  setDuration: (v: number) => void;
  runSimulation: () => Promise<void>;
}) {
  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Управление симуляциями
          </CardTitle>
          <CardDescription>Запуск и параметры</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-3 flex-wrap">
          <Button className="gap-2" onClick={() => props.setOpenRun(true)}>
            <Play className="h-4 w-4" />
            Запустить симуляцию
          </Button>
          <Tabs defaultValue="charts" className="w-full">
            <TabsList>
              <TabsTrigger value="charts">Графики</TabsTrigger>
              <TabsTrigger value="table">Таблица</TabsTrigger>
            </TabsList>
            <TabsContent value="charts" className="text-sm text-muted-foreground">
              Просматривайте динамику атак, детектов и блокировок.
            </TabsContent>
            <TabsContent value="table" className="text-sm text-muted-foreground">
              В таблице — детальные события с критичностью и статусом.
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <Dialog open={props.openRun} onOpenChange={props.setOpenRun}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Запуск симуляции</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label>Сценарий</Label>
              <Select value={props.scenarioId} onValueChange={props.setScenarioId}>
                <SelectTrigger>
                  <SelectValue placeholder="Выберите сценарий" />
                </SelectTrigger>
                <SelectContent>
                  {props.scenarios.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {props.scenarioId && (
                <ScenarioPreview scenario={props.scenarios.find((s) => s.id === props.scenarioId)!} />
              )}
            </div>

            <div className="grid gap-2">
              <Label>Интенсивность: {props.intensity}%</Label>
              <Slider
                value={[props.intensity]}
                min={1}
                max={100}
                step={1}
                onValueChange={(v) => props.setIntensity(v[0])}
              />
            </div>
            <div className="grid gap-2">
              <Label>Длительность: {props.duration} мин</Label>
              <Slider
                value={[props.duration]}
                min={1}
                max={180}
                step={1}
                onValueChange={(v) => props.setDuration(v[0])}
              />
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="secondary" onClick={() => props.setOpenRun(false)}>
              Отмена
            </Button>
            <Button className="gap-2" onClick={props.runSimulation} disabled={!props.scenarioId}>
              <Play className="h-4 w-4" />
              Запустить
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function ScenarioPreview({ scenario }: { scenario: Scenario }) {
  return (
    <div className="text-sm text-muted-foreground border rounded-lg p-3">
      <div className="font-medium text-foreground mb-1">{scenario.name}</div>
      <div className="mb-2">{scenario.description}</div>
      <div className="flex flex-wrap gap-2">
        {scenario.tags.map((t) => (
          <Badge key={t} variant="outline">
            {t}
          </Badge>
        ))}
      </div>
    </div>
  );
}

function SeverityBadge({ sev }: { sev: Severity }) {
  const tone =
    sev === "critical"
      ? "bg-red-100 text-red-700"
      : sev === "high"
      ? "bg-amber-100 text-amber-700"
      : sev === "medium"
      ? "bg-blue-100 text-blue-700"
      : "bg-emerald-100 text-emerald-700";
  return <span className={cn("px-2 py-1 rounded text-xs", tone)}>{sev}</span>;
}

function StatusBadge({ status }: { status: ThreatEvent["status"] }) {
  const tone =
    status === "blocked"
      ? "bg-emerald-100 text-emerald-700"
      : status === "detected"
      ? "bg-blue-100 text-blue-700"
      : "bg-red-100 text-red-700";
  return <span className={cn("px-2 py-1 rounded text-xs", tone)}>{status}</span>;
}

// ---------- Helpers ----------
// Simple date formatting function to replace date-fns
function formatDate(date: Date, formatStr: string): string {
  if (formatStr === "yyyy-MM-dd HH:mm:ss") {
    return date.toISOString().replace('T', ' ').split('.')[0];
  }
  
  // Fallback
  return date.toISOString();
}

function shortTime(iso: string) {
  try {
    const d = new Date(iso);
    return `${d.getHours().toString().padStart(2, "0")}:${d
      .getMinutes()
      .toString()
      .padStart(2, "0")}`;
  } catch {
    return iso;
  }
}

function toLocalDateTimeLocal(iso: string) {
  try {
    const d = new Date(iso);
    const yy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const hh = String(d.getHours()).padStart(2, "0");
    const mi = String(d.getMinutes()).padStart(2, "0");
    return `${yy}-${mm}-${dd}T${hh}:${mi}`;
  } catch {
    return "";
  }
}

function fromLocalToIso(local: string) {
  // local is yyyy-MM-ddTHH:mm
  try {
    const d = new Date(local);
    return d.toISOString();
  } catch {
    return new Date().toISOString();
  }
}

// ---------- End of file ----------
