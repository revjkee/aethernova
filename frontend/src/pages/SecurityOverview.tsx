import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  AlertCircle,
  BellRing,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  Clock,
  Download,
  FileWarning,
  Filter,
  History,
  Info,
  Loader2,
  Lock,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  Siren,
  Zap,
} from "lucide-react";

// shadcn/ui components (assumed available in the project)
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/components/ui/use-toast";

// Utility to merge class names
function cn(...args: Array<string | undefined | false | null>) {
  return args.filter(Boolean).join(" ");
}

/**
 * Types
 */
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface Kpi {
  id: string;
  label: string;
  value: number;
  delta?: number; // percent vs previous period
  icon: React.ReactNode;
  tone: "ok" | "warn" | "alert";
  hint?: string;
}

export interface TrendPoint {
  ts: string; // ISO time
  value: number;
}

export interface IncidentRow {
  id: string;
  detectedAt: string; // ISO
  severity: RiskLevel;
  type: string;
  source: string;
  status: "open" | "mitigating" | "resolved";
  owner?: string;
  description?: string;
}

export interface OverviewPayload {
  kpis: Kpi[];
  trafficTrend: TrendPoint[];
  detectionsTrend: TrendPoint[];
  riskDistribution: Array<{ name: string; value: number }>;
  incidents: IncidentRow[];
  updatedAt: string;
}

/**
 * Data fetching with robust controls
 */
async function fetchJSON<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal, headers: { "Content-Type": "application/json" } });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Request failed ${res.status}: ${text || res.statusText}`);
  }
  return (await res.json()) as T;
}

function useInterval(cb: () => void, delay: number | null) {
  const saved = useRef(cb);
  useEffect(() => {
    saved.current = cb;
  }, [cb]);
  useEffect(() => {
    if (delay === null) return;
    const id = setInterval(() => saved.current(), delay);
    return () => clearInterval(id);
  }, [delay]);
}

function useOverview(autoRefreshMs = 30_000) {
  const [data, setData] = useState<OverviewPayload | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const ctrlRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    try {
      // Endpoint must exist in backend: GET /api/security/overview
      const payload = await fetchJSON<OverviewPayload>("/api/security/overview", ctrl.signal);
      setData(payload);
    } catch (e: any) {
      setError(e?.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    return () => ctrlRef.current?.abort();
  }, [load]);

  useInterval(() => {
    if (!document.hidden) {
      load();
    }
  }, autoRefreshMs);

  return { data, loading, error, reload: load };
}

/** Skeletons **/
const LineSkeleton: React.FC = () => (
  <div className="h-48 w-full animate-pulse rounded-xl bg-muted" />
);
const BarSkeleton: React.FC = () => (
  <div className="h-64 w-full animate-pulse rounded-xl bg-muted" />
);
const TableSkeleton: React.FC = () => (
  <div className="space-y-3">
    {Array.from({ length: 6 }).map((_, i) => (
      <div key={i} className="h-10 w-full animate-pulse rounded-md bg-muted" />
    ))}
  </div>
);

/** Helpers **/
function riskBadge(level: RiskLevel) {
  const map: Record<RiskLevel, { label: string; variant: string }> = {
    low: { label: "Низкий", variant: "outline" },
    medium: { label: "Средний", variant: "secondary" },
    high: { label: "Высокий", variant: "destructive" },
    critical: { label: "Критический", variant: "destructive" },
  };
  return <Badge variant={map[level].variant as any}>{map[level].label}</Badge>;
}

function statusBadge(s: IncidentRow["status"]) {
  const map: Record<IncidentRow["status"], { label: string; icon: React.ReactNode; variant: any }> = {
    open: { label: "Открыт", icon: <Siren className="h-3.5 w-3.5" />, variant: "destructive" },
    mitigating: { label: "В работе", icon: <ShieldHalf className="h-3.5 w-3.5" />, variant: "secondary" },
    resolved: { label: "Закрыт", icon: <ShieldCheck className="h-3.5 w-3.5" />, variant: "outline" },
  };
  const cfg = map[s];
  return (
    <Badge variant={cfg.variant} className="gap-1.5">
      {cfg.icon}
      {cfg.label}
    </Badge>
  );
}

/**
 * Error boundary within the page
 */
class LocalErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean; message?: string }> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError(err: any) {
    return { hasError: true, message: err?.message ?? "Unknown" };
  }
  componentDidCatch(err: any) {
    // In real app, send to observability
    // console.error(err);
  }
  render() {
    if (this.state.hasError) {
      return (
        <Alert variant="destructive" role="alert" aria-live="assertive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Ошибка рендеринга</AlertTitle>
          <AlertDescription>
            Компонент столкнулся с ошибкой: {this.state.message}. Попробуйте обновить страницу.
          </AlertDescription>
        </Alert>
      );
    }
    return this.props.children as any;
  }
}

/**
 * KPI Card
 */
const KpiCard: React.FC<{ kpi: Kpi }> = ({ kpi }) => {
  const tone = {
    ok: "text-emerald-600 dark:text-emerald-400",
    warn: "text-amber-600 dark:text-amber-400",
    alert: "text-red-600 dark:text-red-400",
  }[kpi.tone];
  return (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">
          {kpi.label}
        </CardTitle>
        <div className={cn("rounded-full p-2 bg-muted", tone)} aria-hidden>
          {kpi.icon}
        </div>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-bold tabular-nums">{kpi.value.toLocaleString("ru-RU")}</div>
        {typeof kpi.delta === "number" && (
          <p className="text-xs text-muted-foreground mt-1">
            Изменение за период: {kpi.delta > 0 ? "+" : ""}
            {kpi.delta.toFixed(1)}%
          </p>
        )}
        {kpi.hint && (
          <p className="mt-2 text-xs text-muted-foreground">{kpi.hint}</p>
        )}
      </CardContent>
    </Card>
  );
};

/**
 * Charts wrappers
 */
const TrendAreaChart: React.FC<{ data: TrendPoint[]; height?: number; label?: string }> = ({ data, height = 220, label }) => (
  <div className="w-full" role="img" aria-label={label ?? "График тренда"}>
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ left: 8, right: 8, top: 10, bottom: 0 }}>
        <defs>
          <linearGradient id="fillArea" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopOpacity={0.3} />
            <stop offset="95%" stopOpacity={0.05} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
        <XAxis dataKey="ts" tickFormatter={(v) => new Date(v).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })} minTickGap={24} />
        <YAxis width={40} />
        <RechartsTooltip contentStyle={{ backdropFilter: "blur(8px)" }} labelFormatter={(v) => new Date(v).toLocaleString("ru-RU")} />
        <Area type="monotone" dataKey="value" strokeWidth={2} fill="url(#fillArea)" />
        <Line type="monotone" dataKey="value" strokeWidth={2} dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  </div>
);

const DistributionBarChart: React.FC<{ data: Array<{ name: string; value: number }>; height?: number }> = ({ data, height = 260 }) => (
  <div className="w-full" role="img" aria-label="Распределение рисков">
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ left: 8, right: 8, top: 10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
        <XAxis dataKey="name" />
        <YAxis width={40} />
        <RechartsTooltip contentStyle={{ backdropFilter: "blur(8px)" }} />
        <Bar dataKey="value" radius={[6, 6, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  </div>
);

/**
 * Incidents table
 */
interface IncidentsTableProps {
  rows: IncidentRow[];
}

const IncidentRowView: React.FC<{ row: IncidentRow }> = ({ row }) => {
  return (
    <div className="grid grid-cols-12 items-center gap-3 py-2 px-2 rounded-md hover:bg-muted/50">
      <div className="col-span-2 tabular-nums text-sm text-muted-foreground" title={new Date(row.detectedAt).toLocaleString("ru-RU")}> 
        {new Date(row.detectedAt).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })}
      </div>
      <div className="col-span-2 flex items-center gap-2 text-sm">{riskBadge(row.severity)}</div>
      <div className="col-span-3 text-sm font-medium truncate" title={row.type}>{row.type}</div>
      <div className="col-span-2 text-sm text-muted-foreground truncate" title={row.source}>{row.source}</div>
      <div className="col-span-2 text-sm">{statusBadge(row.status)}</div>
      <div className="col-span-1 flex justify-end">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon" aria-label="Подробнее">
                <Info className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="left" className="max-w-xs text-xs leading-relaxed">
              <p className="font-medium">Описание</p>
              <p className="text-muted-foreground mt-1">{row.description || "Нет описания"}</p>
              {row.owner && <p className="mt-2">Ответственный: <span className="font-mono">{row.owner}</span></p>}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>
    </div>
  );
};

const IncidentsTable: React.FC<IncidentsTableProps> = ({ rows }) => {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<RiskLevel | "all">("all");
  const [status, setStatus] = useState<IncidentRow["status"] | "all">("all");

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return rows.filter((r) => {
      const passQ = !ql || [r.type, r.source, r.description, r.owner].filter(Boolean).some(v => String(v).toLowerCase().includes(ql));
      const passSev = sev === "all" || r.severity === sev;
      const passStatus = status === "all" || r.status === status;
      return passQ && passSev && passStatus;
    });
  }, [rows, q, sev, status]);

  return (
    <Card>
      <CardHeader className="space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div>
            <CardTitle>Инциденты</CardTitle>
            <CardDescription>Последние события безопасности</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="gap-2" onClick={() => window.print()} aria-label="Экспорт в PDF">
              <Download className="h-4 w-4" /> Экспорт
            </Button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Поиск по типу, источнику, описанию, владельцу"
              className="pl-8 w-72"
              aria-label="Поиск инцидентов"
            />
          </div>
          <Separator orientation="vertical" className="h-8" />
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2" aria-label="Фильтр по серьёзности">
                <Filter className="h-4 w-4" /> Серьёзность
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuLabel>Серьёзность</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {(["all", "low", "medium", "high", "critical"] as const).map((r) => (
                <DropdownMenuItem key={r} onClick={() => setSev(r as any)} className={cn(sev === r && "bg-muted")}>{r}</DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2" aria-label="Фильтр по статусу">
                <History className="h-4 w-4" /> Статус
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuLabel>Статус</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {(["all", "open", "mitigating", "resolved"] as const).map((r) => (
                <DropdownMenuItem key={r} onClick={() => setStatus(r as any)} className={cn(status === r && "bg-muted")}>{r}</DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>
      <CardContent>
        <div role="table" aria-label="Таблица инцидентов" className="w-full">
          <div role="rowgroup" className="grid grid-cols-12 gap-3 px-2 text-xs uppercase text-muted-foreground mb-2">
            <div role="columnheader" className="col-span-2">Время</div>
            <div role="columnheader" className="col-span-2">Серьёзность</div>
            <div role="columnheader" className="col-span-3">Тип</div>
            <div role="columnheader" className="col-span-2">Источник</div>
            <div role="columnheader" className="col-span-2">Статус</div>
            <div role="columnheader" className="col-span-1 text-right">Детали</div>
          </div>
          <Separator />
          <ScrollArea className="h-[360px] pr-2 mt-2">
            <div role="rowgroup" className="space-y-1">
              {filtered.map((r) => (
                <IncidentRowView key={r.id} row={r} />
              ))}
              {filtered.length === 0 && (
                <div className="text-center text-sm text-muted-foreground py-12">Нет данных по текущим фильтрам</div>
              )}
            </div>
          </ScrollArea>
        </div>
      </CardContent>
    </Card>
  );
};

/**
 * Header actions
 */
const HeaderBar: React.FC<{ updatedAt?: string; onRefresh(): void; refreshing?: boolean }> = ({ updatedAt, onRefresh, refreshing }) => {
  const ts = updatedAt ? new Date(updatedAt).toLocaleString("ru-RU") : "—";
  return (
    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
      <div className="flex items-center gap-3">
        <div className="rounded-xl p-2 bg-primary/10">
          <Lock className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Обзор безопасности</h1>
          <p className="text-sm text-muted-foreground">Сводные метрики, тренды и инциденты</p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2" onClick={onRefresh} aria-label="Обновить">
                {refreshing ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                Обновить
              </Button>
            </TooltipTrigger>
            <TooltipContent>Перезагрузить сводные данные</TooltipContent>
          </Tooltip>
        </TooltipProvider>
        <Separator orientation="vertical" className="h-6" />
        <div className="text-xs text-muted-foreground">Обновлено: {ts}</div>
      </div>
    </div>
  );
};

/**
 * Risk banner
 */
const RiskBanner: React.FC<{ riskScore: number }> = ({ riskScore }) => {
  const pct = Math.max(0, Math.min(100, Math.round(riskScore)));
  const label = pct >= 80 ? "Критический риск" : pct >= 60 ? "Высокий риск" : pct >= 35 ? "Средний риск" : "Низкий риск";
  const Icon = pct >= 80 ? ShieldAlert : pct >= 60 ? FileWarning : pct >= 35 ? ShieldHalf : ShieldCheck;
  return (
    <Alert className="border-amber-500/40">
      <Icon className="h-4 w-4" />
      <AlertTitle className="flex items-center gap-2">
        Совокупный риск: <span className="font-mono">{pct}</span>
        <Badge variant={pct >= 60 ? "destructive" : pct >= 35 ? "secondary" : "outline"}>{label}</Badge>
      </AlertTitle>
      <AlertDescription>
        <div className="mt-2 flex items-center gap-3">
          <Progress value={pct} className="h-2" aria-label="Индекс совокупного риска" />
          <span className="text-xs text-muted-foreground">0 — безопасно, 100 — критично</span>
        </div>
      </AlertDescription>
    </Alert>
  );
};

/**
 * Main page
 */
const SecurityOverview: React.FC = () => {
  const { data, loading, error, reload } = useOverview(30_000);
  const { toast } = useToast();

  useEffect(() => {
    if (error) {
      toast({ title: "Ошибка загрузки", description: error, variant: "destructive" });
    }
  }, [error, toast]);

  const kpis = data?.kpis ?? [
    {
      id: "alerts",
      label: "Аномалии за 24ч",
      value: 0,
      delta: 0,
      icon: <BellRing className="h-4 w-4" />,
      tone: "ok" as const,
      hint: "Нет данных — показан placeholder",
    },
    {
      id: "incidents",
      label: "Инциденты",
      value: 0,
      delta: 0,
      icon: <Siren className="h-4 w-4" />,
      tone: "ok" as const,
    },
    {
      id: "uptime",
      label: "Uptime защитных сервисов, %",
      value: 100,
      delta: 0.0,
      icon: <Server className="h-4 w-4" />,
      tone: "ok" as const,
    },
    {
      id: "mttr",
      label: "MTTR, мин",
      value: 0,
      delta: 0,
      icon: <Clock className="h-4 w-4" />,
      tone: "ok" as const,
    },
  ];

  const riskScore = useMemo(() => {
    // Simple derived metric: normalize detections trend last point
    const last = data?.detectionsTrend?.at(-1)?.value ?? 0;
    const normalized = Math.min(100, Math.round((last / 100) * 100));
    return normalized;
  }, [data]);

  return (
    <LocalErrorBoundary>
      <div className="space-y-5">
        <HeaderBar updatedAt={data?.updatedAt} onRefresh={reload} refreshing={loading} />

        <RiskBanner riskScore={riskScore} />

        {/* KPIs */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {kpis.map((k) => (
            <motion.div
              key={k.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25 }}
            >
              <KpiCard kpi={k} />
            </motion.div>
          ))}
        </div>

        <Tabs defaultValue="detections" className="w-full">
          <div className="flex items-center justify-between">
            <TabsList>
              <TabsTrigger value="detections" className="gap-2">
                <ShieldAlert className="h-4 w-4" /> Детекции
              </TabsTrigger>
              <TabsTrigger value="traffic" className="gap-2">
                <Zap className="h-4 w-4" /> Трафик
              </TabsTrigger>
              <TabsTrigger value="distribution" className="gap-2">
                <CircleAlert className="h-4 w-4" /> Распределение
              </TabsTrigger>
            </TabsList>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <Switch id="autorefresh" defaultChecked />
                <Label htmlFor="autorefresh" className="text-xs">Автообновление</Label>
              </div>
            </div>
          </div>

          <TabsContent value="detections">
            <Card>
              <CardHeader>
                <CardTitle>Динамика детекций</CardTitle>
                <CardDescription>Количество срабатываний детекторов по времени</CardDescription>
              </CardHeader>
              <CardContent>
                {loading && !data ? <LineSkeleton /> : (
                  <TrendAreaChart data={data?.detectionsTrend ?? []} label="График детекций" />
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="traffic">
            <Card>
              <CardHeader>
                <CardTitle>Нагрузочный профиль</CardTitle>
                <CardDescription>Трафик и интенсивность событий</CardDescription>
              </CardHeader>
              <CardContent>
                {loading && !data ? <LineSkeleton /> : (
                  <div className="w-full" role="img" aria-label="Профиль трафика">
                    <ResponsiveContainer width="100%" height={220}>
                      <LineChart data={data?.trafficTrend ?? []} margin={{ left: 8, right: 8, top: 10, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                        <XAxis dataKey="ts" tickFormatter={(v) => new Date(v).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })} minTickGap={24} />
                        <YAxis width={40} />
                        <RechartsTooltip contentStyle={{ backdropFilter: "blur(8px)" }} labelFormatter={(v) => new Date(v).toLocaleString("ru-RU")} />
                        <Line type="monotone" dataKey="value" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="distribution">
            <Card>
              <CardHeader>
                <CardTitle>Распределение рисков</CardTitle>
                <CardDescription>Агрегат по категориям угроз</CardDescription>
              </CardHeader>
              <CardContent>
                {loading && !data ? <BarSkeleton /> : (
                  <DistributionBarChart data={data?.riskDistribution ?? []} />
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Incidents */}
        {loading && !data ? (
          <Card>
            <CardHeader>
              <CardTitle>Инциденты</CardTitle>
              <CardDescription>Последние события безопасности</CardDescription>
            </CardHeader>
            <CardContent>
              <TableSkeleton />
            </CardContent>
          </Card>
        ) : (
          <IncidentsTable rows={data?.incidents ?? []} />
        )}

        {/* Footer info */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Info className="h-3.5 w-3.5" />
            <span>
              Данные обновляются каждые 30 секунд. Источник: internal /api/security/overview.
            </span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span>Готово к печати через системный диалог печати браузера.</span>
          </div>
        </div>
      </div>
    </LocalErrorBoundary>
  );
};

export default SecurityOverview;
