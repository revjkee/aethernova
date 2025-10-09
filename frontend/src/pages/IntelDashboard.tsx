// frontend/src/pages/IntelDashboard.tsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FC } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import {
  AlertCircle,
  ArrowDownAZ,
  ArrowUpAZ,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  Download,
  ExternalLink,
  Filter,
  Flag,
  History,
  ListFilter,
  Loader2,
  PauseCircle,
  PlayCircle,
  RefreshCcw,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  Legend,
} from "recharts";

// ==============================
// Types
// ==============================
type Severity = "low" | "medium" | "high" | "critical";
type IntelSource = "sensor-a" | "sensor-b" | "edr" | "siem" | "threat-feed" | "api";
type IntelStatus = "open" | "in_progress" | "closed";
type TimeRange = "1h" | "6h" | "24h" | "7d" | "30d";

interface IntelEvent {
  id: string;
  ts: number; // epoch ms
  title: string;
  source: IntelSource;
  severity: Severity;
  status: IntelStatus;
  entity: string; // host/user/service
  tags: string[];
  score: number; // 0..100
  details: string;
  link?: string;
}

interface FetchParams {
  range: TimeRange;
  severity?: Severity | "all";
  source?: IntelSource | "all";
  status?: IntelStatus | "all";
  search?: string;
  limit?: number;
  offset?: number;
  sort?: { field: keyof IntelEvent; dir: "asc" | "desc" };
}

interface IntelData {
  events: IntelEvent[];
  total: number;
  aggregated: {
    byHour: Array<{ t: string; count: number }>;
    bySeverity: Array<{ name: Severity; value: number }>;
    bySource: Array<{ name: IntelSource; value: number }>;
  };
}

// ==============================
// Utilities
// ==============================
const fmt = (d: Date) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate()
  ).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(
    d.getMinutes()
  ).padStart(2, "0")}`;

const sevColor: Record<Severity, string> = {
  low: "bg-emerald-600",
  medium: "bg-amber-600",
  high: "bg-orange-600",
  critical: "bg-red-600",
};

const statusBadge: Record<IntelStatus, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> =
  {
    open: { label: "Открыто", variant: "destructive" },
    in_progress: { label: "В работе", variant: "secondary" },
    closed: { label: "Закрыто", variant: "outline" },
  };

function debounce<T extends (...args: any[]) => void>(fn: T, ms = 300) {
  let h: number | undefined;
  return (...args: Parameters<T>) => {
    if (h) window.clearTimeout(h);
    h = window.setTimeout(() => fn(...args), ms);
  };
}

function downloadCsv(filename: string, rows: Record<string, any>[]) {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const esc = (v: any) =>
    `"${String(v ?? "").replace(/"/g, '""').replace(/\n/g, " ")}"`;
  const csv =
    headers.join(",") +
    "\n" +
    rows.map((r) => headers.map((h) => esc(r[h])).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function randChoice<T>(arr: T[]) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// ==============================
// Mocked data source (replace with real API)
// ==============================

const MOCK_SOURCES: IntelSource[] = ["sensor-a", "sensor-b", "edr", "siem", "threat-feed", "api"];
const MOCK_SEVS: Severity[] = ["low", "medium", "high", "critical"];
const MOCK_STATUS: IntelStatus[] = ["open", "in_progress", "closed"];
const MOCK_TAGS = ["auth", "network", "api", "k8s", "db", "ransom", "policy", "anomaly", "login", "exfil"];

function generateMockEvent(id: string, baseTs: number): IntelEvent {
  const ts = baseTs - Math.floor(Math.random() * 1000 * 60 * 60 * 24 * 7);
  const severity = randChoice(MOCK_SEVS);
  const status = randChoice(MOCK_STATUS);
  const source = randChoice(MOCK_SOURCES);
  const entity = `svc-${Math.floor(Math.random() * 30)}`;
  const title = `Событие безопасности ${Math.floor(Math.random() * 9999)}`;
  const details = `Подробности по событию ${id} для ${entity} из источника ${source}. Автоматическая корреляция, эвристики и сигнатуры совпали.`;
  return {
    id,
    ts,
    title,
    source,
    severity,
    status,
    entity,
    tags: Array.from({ length: 1 + Math.floor(Math.random() * 3) }, () => randChoice(MOCK_TAGS)),
    score: Math.floor(Math.random() * 100),
    details,
    link: Math.random() > 0.7 ? "https://example.com/incidents/" + id : undefined,
  };
}

function mockAggregate(events: IntelEvent[], range: TimeRange): IntelData["aggregated"] {
  // Group by hour bucket
  const buckets = new Map<string, number>();
  const now = Date.now();
  const rangeMs: Record<TimeRange, number> = {
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
    "30d": 30 * 24 * 60 * 60 * 1000,
  };
  const startTs = now - rangeMs[range];
  for (let t = startTs; t <= now; t += 60 * 60 * 1000) {
    const key = fmt(new Date(t));
    buckets.set(key, 0);
  }
  events.forEach((e) => {
    const d = new Date(Math.floor(e.ts / (60 * 60 * 1000)) * (60 * 60 * 1000));
    const key = fmt(d);
    if (buckets.has(key)) buckets.set(key, (buckets.get(key) || 0) + 1);
  });

  const byHour = Array.from(buckets.entries()).map(([t, count]) => ({ t, count }));
  const sevMap: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const srcMap: Record<IntelSource, number> = {
    "sensor-a": 0,
    "sensor-b": 0,
    edr: 0,
    siem: 0,
    "threat-feed": 0,
    api: 0,
  };
  events.forEach((e) => {
    sevMap[e.severity] += 1;
    srcMap[e.source] += 1;
  });

  return {
    byHour,
    bySeverity: Object.entries(sevMap).map(([name, value]) => ({ name: name as Severity, value })),
    bySource: Object.entries(srcMap).map(([name, value]) => ({ name: name as IntelSource, value })),
  };
}

async function mockFetchIntel(params: FetchParams): Promise<IntelData> {
  // Simulate network latency & occasional failures
  await new Promise((r) => setTimeout(r, 350 + Math.random() * 400));
  if (Math.random() < 0.03) {
    const err = new Error("Сервис временно недоступен");
    // @ts-ignore
    err.code = 503;
    throw err;
  }

  const total = 4200; // pretend server-side total
  const limit = params.limit ?? 50;
  const offset = params.offset ?? 0;

  // generate deterministic-ish base timestamp window
  const baseTs = Date.now();
  const genCount = Math.min(limit, Math.max(0, total - offset));
  const events = Array.from({ length: genCount }, (_, i) =>
    generateMockEvent(`ev-${offset + i + 1}`, baseTs)
  );

  // Apply simple client filtering for demo; in prod these should be server-side
  const filtered = events.filter((e) => {
    const sevOk = params.severity && params.severity !== "all" ? e.severity === params.severity : true;
    const srcOk = params.source && params.source !== "all" ? e.source === params.source : true;
    const stOk = params.status && params.status !== "all" ? e.status === params.status : true;
    const s = (params.search || "").trim().toLowerCase();
    const searchOk = s
      ? e.title.toLowerCase().includes(s) ||
        e.entity.toLowerCase().includes(s) ||
        e.details.toLowerCase().includes(s) ||
        e.tags.some((t) => t.toLowerCase().includes(s))
      : true;
    return sevOk && srcOk && stOk && searchOk;
  });

  // Sorting
  if (params.sort) {
    const { field, dir } = params.sort;
    filtered.sort((a, b) => {
      const va = a[field];
      const vb = b[field];
      if (va === vb) return 0;
      if (va == null) return 1;
      if (vb == null) return -1;
      const res = va > vb ? 1 : -1;
      return dir === "asc" ? res : -res;
    });
  }

  return {
    events: filtered,
    total,
    aggregated: mockAggregate(filtered, params.range),
  };
}

// ==============================
// Hooks
// ==============================

function useIntelData(params: FetchParams, enabled = true, refreshMs?: number) {
  const [data, setData] = useState<IntelData | null>(null);
  const [loading, setLoading] = useState<boolean>(enabled);
  const [error, setError] = useState<Error | null>(null);
  const tick = useRef<number | null>(null);

  const fetcher = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await mockFetchIntel(params);
      setData(res);
    } catch (e: any) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, [params]);

  useEffect(() => {
    if (!enabled) return;
    fetcher();
  }, [enabled, fetcher]);

  useEffect(() => {
    if (!enabled || !refreshMs) return;
    tick.current = window.setInterval(fetcher, refreshMs);
    return () => {
      if (tick.current) window.clearInterval(tick.current);
    };
  }, [enabled, refreshMs, fetcher]);

  const retry = useCallback(() => fetcher(), [fetcher]);

  return { data, loading, error, retry, setData };
}

// ==============================
// Component
// ==============================

const DEFAULT_COLUMNS = [
  { key: "ts", label: "Время" },
  { key: "title", label: "Событие" },
  { key: "severity", label: "Уровень" },
  { key: "source", label: "Источник" },
  { key: "entity", label: "Сущность" },
  { key: "status", label: "Статус" },
  { key: "score", label: "Риск" },
  { key: "tags", label: "Теги" },
  { key: "link", label: "Ссылка" },
] as const;

type ColumnKey = typeof DEFAULT_COLUMNS[number]["key"];

const IntelDashboard: FC = () => {
  // Filters & state
  const [range, setRange] = useState<TimeRange>("24h");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [source, setSource] = useState<IntelSource | "all">("all");
  const [status, setStatus] = useState<IntelStatus | "all">("all");
  const [search, setSearch] = useState<string>("");
  const [query, setQuery] = useState<string>("");
  const [limit, setLimit] = useState<number>(50);
  const [offset, setOffset] = useState<number>(0);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [refreshMs, setRefreshMs] = useState<number>(15000);
  const [sort, setSort] = useState<FetchParams["sort"]>({ field: "ts", dir: "desc" });
  const [visibleCols, setVisibleCols] = useState<Record<ColumnKey, boolean>>(
    () => DEFAULT_COLUMNS.reduce((acc, c) => ({ ...acc, [c.key]: true }), {} as Record<ColumnKey, boolean>)
  );

  const params = useMemo<FetchParams>(
    () => ({ range, severity, source, status, search: query, limit, offset, sort }),
    [range, severity, source, status, query, limit, offset, sort]
  );

  const { data, loading, error, retry } = useIntelData(params, true, autoRefresh ? refreshMs : undefined);

  const onSearchChange = useMemo(
    () =>
      debounce((v: string) => {
        setQuery(v);
        setOffset(0);
      }, 400),
    []
  );

  const toggleSort = useCallback(
    (field: ColumnKey) => {
      setSort((prev) => {
        if (prev?.field === field) {
          return { field, dir: prev.dir === "asc" ? "desc" : "asc" };
        }
        return { field, dir: "asc" };
      });
    },
    [setSort]
  );

  const pagedInfo = useMemo(() => {
    const total = data?.total ?? 0;
    const start = offset + 1;
    const end = Math.min(offset + limit, total);
    return { start, end, total };
  }, [data?.total, offset, limit]);

  const exportCsv = useCallback(() => {
    const rows =
      data?.events.map((e) => ({
        id: e.id,
        ts: new Date(e.ts).toISOString(),
        title: e.title,
        source: e.source,
        severity: e.severity,
        status: e.status,
        entity: e.entity,
        score: e.score,
        tags: e.tags.join("|"),
        link: e.link ?? "",
      })) ?? [];
    downloadCsv(`intel-${Date.now()}.csv`, rows);
  }, [data?.events]);

  // ==============================
  // UI
  // ==============================
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Intel Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Сводная панель телеметрии и инцидентов. Обновление каждые {autoRefresh ? Math.round(refreshMs / 1000) : 0} сек.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => retry()} aria-label="Обновить">
            <RefreshCcw className="mr-2 h-4 w-4" />
            Обновить
          </Button>
          <Button variant="outline" size="sm" onClick={exportCsv} aria-label="Экспорт CSV">
            <Download className="mr-2 h-4 w-4" />
            Экспорт CSV
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Settings className="mr-2 h-4 w-4" />
                Настройки
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel>Автообновление</DropdownMenuLabel>
              <div className="px-2 py-1.5 flex items-center justify-between">
                <span className="text-sm">Включено</span>
                <Switch checked={autoRefresh} onCheckedChange={setAutoRefresh} />
              </div>
              <div className="px-2 py-1.5">
                <Label htmlFor="refresh">Интервал (мс)</Label>
                <Input
                  id="refresh"
                  type="number"
                  min={3000}
                  step={1000}
                  value={refreshMs}
                  onChange={(e) => setRefreshMs(Number(e.target.value || 0))}
                />
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuLabel>Колонки</DropdownMenuLabel>
              {DEFAULT_COLUMNS.map((c) => (
                <DropdownMenuCheckboxItem
                  key={c.key}
                  checked={visibleCols[c.key]}
                  onCheckedChange={(v) =>
                    setVisibleCols((prev) => ({ ...prev, [c.key]: Boolean(v) }))
                  }
                >
                  {c.label}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Filters */}
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ListFilter className="h-5 w-5" />
            Фильтры
          </CardTitle>
          <CardDescription>Сузьте выдачу по временным рамкам, уровню, источнику и статусу.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
          <div className="space-y-1.5">
            <Label>Период</Label>
            <Select value={range} onValueChange={(v: TimeRange) => setRange(v)}>
              <SelectTrigger aria-label="Выбор периода">
                <SelectValue placeholder="Период" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectLabel>Интервалы</SelectLabel>
                  <SelectItem value="1h">1 час</SelectItem>
                  <SelectItem value="6h">6 часов</SelectItem>
                  <SelectItem value="24h">24 часа</SelectItem>
                  <SelectItem value="7d">7 дней</SelectItem>
                  <SelectItem value="30d">30 дней</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Уровень</Label>
            <Select value={severity} onValueChange={(v: any) => setSeverity(v)}>
              <SelectTrigger aria-label="Выбор уровня">
                <SelectValue placeholder="Уровень" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Источник</Label>
            <Select value={source} onValueChange={(v: any) => setSource(v)}>
              <SelectTrigger aria-label="Выбор источника">
                <SelectValue placeholder="Источник" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все</SelectItem>
                {MOCK_SOURCES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Статус</Label>
            <Select value={status} onValueChange={(v: any) => setStatus(v)}>
              <SelectTrigger aria-label="Выбор статуса">
                <SelectValue placeholder="Статус" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все</SelectItem>
                <SelectItem value="open">Открыто</SelectItem>
                <SelectItem value="in_progress">В работе</SelectItem>
                <SelectItem value="closed">Закрыто</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5 lg:col-span-2">
            <Label>Поиск</Label>
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Искать по названию, сущности, тегам, описанию"
                className="pl-8"
                onChange={(e) => onSearchChange(e.target.value)}
                aria-label="Строка поиска"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Summary & charts */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              Динамика событий
            </CardTitle>
            <CardDescription>Суммарное количество по часам</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {loading && !data ? (
              <Skeleton className="h-full w-full" />
            ) : error ? (
              <ErrorBox error={error} onRetry={() => retry()} />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data?.aggregated.byHour || []} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                  <defs>
                    <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopOpacity={0.6} />
                      <stop offset="95%" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="t" tick={{ fontSize: 10 }} />
                  <YAxis allowDecimals={false} />
                  <RechartsTooltip />
                  <Legend />
                  <Area type="monotone" dataKey="count" strokeWidth={2} fillOpacity={1} fill="url(#colorCount)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              Распределение по уровню
            </CardTitle>
            <CardDescription>Количество событий по severity</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {loading && !data ? (
              <Skeleton className="h-full w-full" />
            ) : error ? (
              <ErrorBox error={error} onRetry={() => retry()} />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data?.aggregated.bySeverity || []} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis allowDecimals={false} />
                  <RechartsTooltip />
                  <Legend />
                  <Bar dataKey="value" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Flag className="h-5 w-5" />
              Источники
            </CardTitle>
            <CardDescription>События по источникам телеметрии</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {loading && !data ? (
              <Skeleton className="h-full w-full" />
            ) : error ? (
              <ErrorBox error={error} onRetry={() => retry()} />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data?.aggregated.bySource || []} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis allowDecimals={false} />
                  <RechartsTooltip />
                  <Legend />
                  <Line type="monotone" dataKey="value" dot={false} strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Incidents table */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              Инциденты
              <Badge variant="outline">{pagedInfo.total.toLocaleString()} всего</Badge>
            </CardTitle>
            <CardDescription>Последние события с учетом фильтров</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setSort({ field: "score", dir: "desc" })}
              aria-label="Сортировать по риску"
            >
              <ArrowDownAZ className="mr-2 h-4 w-4" />
              Риск
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setSort({ field: "ts", dir: "desc" })}
              aria-label="Сортировать по времени"
            >
              <History className="mr-2 h-4 w-4" />
              Время
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setSort({ field: "title", dir: "asc" })}
              aria-label="Сортировать по названию"
            >
              <ArrowUpAZ className="mr-2 h-4 w-4" />
              Название
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border overflow-x-auto">
            <Table>
              <TableCaption>Показаны события {pagedInfo.start}–{pagedInfo.end} из {pagedInfo.total}</TableCaption>
              <TableHeader>
                <TableRow>
                  {DEFAULT_COLUMNS.map((c) =>
                    visibleCols[c.key] ? (
                      <TableHead
                        key={c.key}
                        className="whitespace-nowrap cursor-pointer select-none"
                        onClick={() => toggleSort(c.key as ColumnKey)}
                        aria-sort={sort?.field === c.key ? (sort?.dir === "asc" ? "ascending" : "descending") : "none"}
                      >
                        <div className="flex items-center gap-1">
                          {c.label}
                          <ChevronDown className="h-3.5 w-3.5 opacity-60" />
                        </div>
                      </TableHead>
                    ) : null
                  )}
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && !data ? (
                  Array.from({ length: 8 }).map((_, i) => (
                    <TableRow key={`s-${i}`}>
                      {DEFAULT_COLUMNS.map(
                        (c) => visibleCols[c.key] && <TableCell key={c.key}><Skeleton className="h-5 w-full" /></TableCell>
                      )}
                    </TableRow>
                  ))
                ) : error ? (
                  <TableRow>
                    <TableCell colSpan={DEFAULT_COLUMNS.filter((c) => visibleCols[c.key]).length}>
                      <ErrorBox error={error} onRetry={retry} />
                    </TableCell>
                  </TableRow>
                ) : (data?.events?.length ?? 0) === 0 ? (
                  <TableRow>
                    <TableCell colSpan={DEFAULT_COLUMNS.filter((c) => visibleCols[c.key]).length}>
                      <div className="py-8 text-center text-sm text-muted-foreground">
                        Данных нет для текущих фильтров.
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  data!.events.map((e) => (
                    <TableRow key={e.id} className="hover:bg-muted/40">
                      {visibleCols.ts && (
                        <TableCell className="whitespace-nowrap">{fmt(new Date(e.ts))}</TableCell>
                      )}
                      {visibleCols.title && (
                        <TableCell className="min-w-[240px]">
                          <div className="flex items-center gap-2">
                            {e.severity === "critical" ? (
                              <XCircle className="h-4 w-4 text-red-600" />
                            ) : e.severity === "high" ? (
                              <AlertCircle className="h-4 w-4 text-orange-600" />
                            ) : e.severity === "medium" ? (
                              <ShieldAlert className="h-4 w-4 text-amber-600" />
                            ) : (
                              <ShieldCheck className="h-4 w-4 text-emerald-600" />
                            )}
                            <span className="font-medium">{e.title}</span>
                          </div>
                          <div className="text-xs text-muted-foreground">{e.details}</div>
                        </TableCell>
                      )}
                      {visibleCols.severity && (
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className={`inline-block h-2.5 w-2.5 rounded-full ${sevColor[e.severity]}`} />
                            <span className="capitalize">{e.severity}</span>
                          </div>
                        </TableCell>
                      )}
                      {visibleCols.source && <TableCell className="uppercase">{e.source}</TableCell>}
                      {visibleCols.entity && <TableCell>{e.entity}</TableCell>}
                      {visibleCols.status && (
                        <TableCell>
                          <Badge variant={statusBadge[e.status].variant}>{statusBadge[e.status].label}</Badge>
                        </TableCell>
                      )}
                      {visibleCols.score && (
                        <TableCell className="min-w-[140px]">
                          <div className="flex items-center gap-2">
                            <Progress value={e.score} className="h-2" />
                            <span className="text-xs text-muted-foreground w-8 text-right">{e.score}</span>
                          </div>
                        </TableCell>
                      )}
                      {visibleCols.tags && (
                        <TableCell className="min-w-[180px]">
                          <div className="flex flex-wrap gap-1">
                            {e.tags.map((t) => (
                              <Badge key={t} variant="outline">
                                {t}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                      )}
                      {visibleCols.link && (
                        <TableCell>
                          {e.link ? (
                            <a
                              className="inline-flex items-center gap-1 text-primary underline underline-offset-4"
                              href={e.link}
                              target="_blank"
                              rel="noreferrer"
                              aria-label="Перейти к событию во внешней системе"
                            >
                              Открыть <ExternalLink className="h-3.5 w-3.5" />
                            </a>
                          ) : (
                            <span className="text-muted-foreground text-xs">—</span>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          <div className="mt-4 flex items-center justify-between">
            <div className="text-sm text-muted-foreground">
              Показаны {pagedInfo.start}–{pagedInfo.end} из {pagedInfo.total}
            </div>
            <div className="flex items-center gap-2">
              <Select value={String(limit)} onValueChange={(v) => { setLimit(Number(v)); setOffset(0); }}>
                <SelectTrigger className="w-[110px]" aria-label="Лимит на страницу">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[25, 50, 100, 200].map((n) => (
                    <SelectItem key={n} value={String(n)}>{n} на стр.</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setOffset(Math.max(0, offset - limit))}
                disabled={offset === 0}
              >
                Назад
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setOffset(offset + limit)}
                disabled={pagedInfo.end >= pagedInfo.total}
              >
                Вперед
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Footer controls */}
      <Card>
        <CardContent className="pt-6">
          <Tabs defaultValue="live" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="live" className="flex items-center gap-2">
                <PlayCircle className="h-4 w-4" /> Live
              </TabsTrigger>
              <TabsTrigger value="pause" className="flex items-center gap-2">
                <PauseCircle className="h-4 w-4" /> Пауза
              </TabsTrigger>
              <TabsTrigger value="status" className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4" /> Статус
              </TabsTrigger>
            </TabsList>
            <TabsContent value="live" className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm text-muted-foreground">
                  Автообновление активно каждые {Math.round(refreshMs / 1000)} сек.
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => setAutoRefresh(true)}>
                    Включить
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setAutoRefresh(false)}>
                    Выключить
                  </Button>
                </div>
              </div>
            </TabsContent>
            <TabsContent value="pause" className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm text-muted-foreground">Поток данных приостановлен вручную.</div>
                <Button size="sm" onClick={() => setAutoRefresh(false)}>
                  Поставить на паузу
                </Button>
              </div>
            </TabsContent>
            <TabsContent value="status" className="space-y-2">
              <div className="grid gap-2 md:grid-cols-3">
                <StatusTile
                  title="Подключения"
                  value="OK"
                  description="Все источники в сети"
                  icon={<ShieldCheck className="h-4 w-4" />}
                />
                <StatusTile
                  title="Очередь"
                  value="~1.2K msg"
                  description="Задержки в норме"
                  icon={<BarChart3 className="h-4 w-4" />}
                />
                <StatusTile
                  title="Ошибки"
                  value="0.1%"
                  description="Низкий уровень сбоев"
                  icon={<AlertCircle className="h-4 w-4" />}
                />
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

// ==============================
// Subcomponents
// ==============================

const ErrorBox: FC<{ error: Error; onRetry: () => void }> = ({ error, onRetry }) => {
  return (
    <div className="flex items-center justify-between rounded-md border border-destructive/40 bg-destructive/10 p-3">
      <div className="flex items-center gap-2">
        <AlertCircle className="h-4 w-4 text-destructive" />
        <div className="text-sm">
          <div className="font-medium">Ошибка загрузки</div>
          <div className="text-muted-foreground">{error.message}</div>
        </div>
      </div>
      <Button size="sm" variant="outline" onClick={onRetry}>
        Повторить
      </Button>
    </div>
  );
};

const StatusTile: FC<{ title: string; value: string; description: string; icon: React.ReactNode }> = ({
  title,
  value,
  description,
  icon,
}) => {
  return (
    <div className="rounded-2xl border p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">{title}</div>
        <div>{icon}</div>
      </div>
      <div className="mt-1 text-xl font-semibold">{value}</div>
      <div className="text-xs text-muted-foreground">{description}</div>
    </div>
  );
};

export default IntelDashboard;
