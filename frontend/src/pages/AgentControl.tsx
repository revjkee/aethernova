// frontend/src/pages/AgentControl.tsx
import * as React from "react";
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { z } from "zod";
import { motion } from "framer-motion";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
  RefreshCw,
  Play,
  Pause,
  Square,
  Plus,
  Download,
  Rocket,
  Settings2,
  Search,
  ChevronDown,
  ChevronUp,
  ChevronsLeft,
  ChevronLeft,
  ChevronRight,
  ChevronsRight,
  Zap,
  Activity,
  Info,
  TerminalSquare,
} from "lucide-react";
import {
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

/**
 * Типы и схемы
 */
export type AgentState = "idle" | "running" | "paused" | "stopped" | "error";
export type AgentKind = "planner" | "crawler" | "worker" | "guard" | "orchestrator";

const AgentSchema = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum(["planner", "crawler", "worker", "guard", "orchestrator"]),
  state: z.enum(["idle", "running", "paused", "stopped", "error"]),
  version: z.string().optional().default("1.0.0"),
  updatedAt: z.string().datetime(),
  createdAt: z.string().datetime(),
  runInfo: z.object({
    pid: z.number().int().optional().nullable(),
    host: z.string().optional().nullable(),
    requestId: z.string().optional().nullable(),
  }).optional().default({}),
  metrics: z.object({
    cpu: z.number().min(0).max(100).optional().default(0),
    mem: z.number().min(0).max(100).optional().default(0),
    rps: z.number().min(0).optional().default(0),
    latency_ms_p50: z.number().min(0).optional().default(0),
    latency_ms_p95: z.number().min(0).optional().default(0),
    queue_depth: z.number().min(0).optional().default(0),
  }).default({ cpu: 0, mem: 0, rps: 0, latency_ms_p50: 0, latency_ms_p95: 0, queue_depth: 0 }),
  tags: z.array(z.string()).optional().default([]),
});
export type Agent = z.infer<typeof AgentSchema>;

const AgentListSchema = z.object({
  items: z.array(AgentSchema),
  total: z.number().int(),
  page: z.number().int().min(1),
  pageSize: z.number().int().min(1),
});
type AgentList = z.infer<typeof AgentListSchema>;

const MetricPointSchema = z.object({
  t: z.number(), // unix ms
  cpu: z.number().optional().default(0),
  mem: z.number().optional().default(0),
  rps: z.number().optional().default(0),
  p95: z.number().optional().default(0),
});
type MetricPoint = z.infer<typeof MetricPointSchema>;

const LogEventSchema = z.object({
  t: z.string().datetime(),
  level: z.enum(["debug", "info", "warn", "error"]),
  message: z.string(),
  agentId: z.string().optional(),
  requestId: z.string().optional(),
  data: z.record(z.any()).optional(),
});
type LogEvent = z.infer<typeof LogEventSchema>;

/**
 * Утилиты
 */
const stateVariant: Record<AgentState, React.ComponentProps<typeof Badge>["variant"]> = {
  idle: "secondary",
  running: "default",
  paused: "outline",
  stopped: "secondary",
  error: "destructive",
};

function fmtDate(iso: string) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function dl(filename: string, content: string, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

/**
 * Конфиг API — используйте прокси в dev, а в prod относительные пути
 * Предполагаемые эндпоинты backend:
 * GET    /api/agents?page=&pageSize=&q=&state=&kind=
 * POST   /api/agents        body: { name, kind, params? }
 * POST   /api/agents/:id/start
 * POST   /api/agents/:id/pause
 * POST   /api/agents/:id/stop
 * POST   /api/agents/:id/scale body: { replicas }
 * GET    /api/agents/:id/metrics?window=10m
 * GET    /api/logs/stream (SSE) или /ws/logs (WebSocket)
 */

async function api<T>(input: RequestInfo, init?: RequestInit, signal?: AbortSignal): Promise<T> {
  const res = await fetch(input, { ...init, signal, headers: { "Content-Type": "application/json", ...(init?.headers || {}) } });
  const text = await res.text();
  if (!res.ok) {
    let detail = text;
    try {
      const j = JSON.parse(text);
      detail = j.detail || j.message || text;
    } catch { /* noop */ }
    throw new Error(`API ${res.status}: ${detail}`);
  }
  try { return JSON.parse(text) as T; } catch { return undefined as unknown as T; }
}

/**
 * Основная страница
 */
export default function AgentControl() {
  // фильтры/состояния
  const [q, setQ] = useState("");
  const [stateFilter, setStateFilter] = useState<AgentState | "any">("any");
  const [kindFilter, setKindFilter] = useState<AgentKind | "any">("any");
  const [pageSize, setPageSize] = useState(25);
  const [page, setPage] = useState(1);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [busy, setBusy] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // данные
  const [list, setList] = useState<AgentList>({ items: [], total: 0, page: 1, pageSize: 25 });
  const [selected, setSelected] = useState<Agent | null>(null);
  const [metrics, setMetrics] = useState<MetricPoint[]>([]);
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  // загрузка списка
  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      setError(null);
      const params = new URLSearchParams({
        page: String(page),
        pageSize: String(pageSize),
      });
      if (q.trim()) params.set("q", q.trim());
      if (stateFilter !== "any") params.set("state", stateFilter);
      if (kindFilter !== "any") params.set("kind", kindFilter);
      const raw = await api<unknown>(`/api/agents?${params.toString()}`, { method: "GET" }, ac.signal);
      const parsed = AgentListSchema.parse(raw);
      setList(parsed);
      if (!selected && parsed.items.length) setSelected(parsed.items[0]);
    } catch (e: any) {
      setError(e?.message || "Ошибка загрузки");
    }
  }, [q, stateFilter, kindFilter, page, pageSize, selected]);

  useEffect(() => {
    load();
  }, [load]);

  // автообновление
  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => load(), 5000);
    return () => clearInterval(id);
  }, [autoRefresh, load]);

  // метрики выбранного агента
  const loadMetrics = useCallback(async (agentId: string) => {
    try {
      const raw = await api<unknown>(`/api/agents/${agentId}/metrics?window=10m`, { method: "GET" });
      const arr = (Array.isArray(raw) ? raw : []) as unknown[];
      const data: MetricPoint[] = [];
      for (const r of arr) {
        const p = MetricPointSchema.safeParse(r);
        if (p.success) data.push(p.data);
      }
      setMetrics(data);
    } catch (e: any) {
      // метрики не критичны
    }
  }, []);

  useEffect(() => {
    if (selected) loadMetrics(selected.id);
  }, [selected, loadMetrics]);

  // SSE логи (fallback на polling)
  useEffect(() => {
    let closed = false;
    let ev: EventSource | null = null;
    try {
      ev = new EventSource("/api/logs/stream");
      ev.onmessage = (m) => {
        try {
          const parsed = LogEventSchema.safeParse(JSON.parse(m.data));
          if (parsed.success) {
            setLogs((prev) => {
              const next = [...prev, parsed.data];
              return next.slice(-1000);
            });
          }
        } catch { /* noop */ }
      };
      ev.onerror = () => { /* keep open */ };
    } catch {
      // fallback опрос
      const id = setInterval(async () => {
        if (closed) return;
        try {
          const raw = await api<unknown>("/api/logs?limit=200", { method: "GET" });
          const arr = Array.isArray(raw) ? raw : [];
          const parsed: LogEvent[] = [];
          for (const r of arr) {
            const p = LogEventSchema.safeParse(r);
            if (p.success) parsed.push(p.data);
          }
          setLogs(parsed.slice(-1000));
        } catch { /* noop */ }
      }, 5000);
      return () => { closed = true; clearInterval(id); };
    }
    return () => { closed = true; ev?.close(); };
  }, []);

  // действия
  const act = useCallback(async (id: string, endpoint: "start" | "pause" | "stop", body?: any) => {
    setBusy(true);
    try {
      await api(`/api/agents/${id}/${endpoint}`, { method: "POST", body: body ? JSON.stringify(body) : undefined });
      await load();
      if (selected?.id === id) await loadMetrics(id);
    } catch (e: any) {
      setError(e?.message || "Ошибка запроса");
    } finally {
      setBusy(false);
    }
  }, [load, selected, loadMetrics]);

  const scale = useCallback(async (id: string, replicas: number) => {
    setBusy(true);
    try {
      await api(`/api/agents/${id}/scale`, { method: "POST", body: JSON.stringify({ replicas }) });
      await load();
    } catch (e: any) {
      setError(e?.message || "Ошибка масштабирования");
    } finally {
      setBusy(false);
    }
  }, [load]);

  const createAgent = useCallback(async (payload: { name: string; kind: AgentKind; params?: any }) => {
    setBusy(true);
    try {
      await api("/api/agents", { method: "POST", body: JSON.stringify(payload) });
      setPage(1);
      await load();
    } catch (e: any) {
      setError(e?.message || "Ошибка создания агента");
    } finally {
      setBusy(false);
    }
  }, [load]);

  // производные
  const totalPages = Math.max(1, Math.ceil(list.total / list.pageSize));
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const visibleLogs = useMemo(() => {
    if (!selected) return logs.slice(-300);
    return logs.filter((l) => !l.agentId || l.agentId === selected.id).slice(-300);
  }, [logs, selected]);

  // локальные формы
  const [newName, setNewName] = useState("");
  const [newKind, setNewKind] = useState<AgentKind>("worker");
  const [newParams, setNewParams] = useState("");

  // экспорт
  const exportAgentsCSV = () => {
    const headers = ["id", "name", "kind", "state", "version", "createdAt", "updatedAt", "cpu", "mem", "rps", "p50", "p95", "queue"];
    const lines = [
      headers.join(","),
      ...list.items.map((a) => [
        a.id, a.name, a.kind, a.state, a.version, a.createdAt, a.updatedAt,
        a.metrics.cpu, a.metrics.mem, a.metrics.rps, a.metrics.latency_ms_p50, a.metrics.latency_ms_p95, a.metrics.queue_depth,
      ].map((v) => {
        const s = String(v ?? "");
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      }).join(",")),
    ];
    dl(`agents_${new Date().toISOString().replace(/[:.]/g, "-")}.csv`, lines.join("\n"), "text/csv;charset=utf-8");
  };

  return (
    <div className="p-4 md:p-6 space-y-6">
      <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Agent Control</h1>
            <p className="text-sm text-muted-foreground">
              Управление жизненным циклом ИИ-агентов, наблюдение за метриками и логами.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => load()} disabled={busy}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Обновить
            </Button>
            <Button variant="outline" size="sm" onClick={exportAgentsCSV}>
              <Download className="h-4 w-4 mr-2" />
              Экспорт CSV
            </Button>
          </div>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Левая колонка: фильтры + список */}
        <div className="lg:col-span-7 space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Фильтры и поиск</CardTitle>
              <CardDescription>Сужение выборки и автообновление списка</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                <div className="md:col-span-5">
                  <div className="relative">
                    <Input
                      value={q}
                      onChange={(e) => setQ(e.target.value)}
                      placeholder="Поиск по имени, тегам, версии…"
                      aria-label="Поиск"
                    />
                    <Search className="h-4 w-4 absolute right-2 top-2.5" />
                  </div>
                </div>
                <div className="md:col-span-3">
                  <Select value={stateFilter} onValueChange={(v) => { setStateFilter(v as any); setPage(1); }}>
                    <SelectTrigger aria-label="Состояние">
                      <SelectValue placeholder="Состояние" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="any">Любое</SelectItem>
                      <SelectItem value="running">running</SelectItem>
                      <SelectItem value="paused">paused</SelectItem>
                      <SelectItem value="idle">idle</SelectItem>
                      <SelectItem value="stopped">stopped</SelectItem>
                      <SelectItem value="error">error</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="md:col-span-3">
                  <Select value={kindFilter} onValueChange={(v) => { setKindFilter(v as any); setPage(1); }}>
                    <SelectTrigger aria-label="Тип агента">
                      <SelectValue placeholder="Тип агента" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="any">Любой</SelectItem>
                      <SelectItem value="planner">planner</SelectItem>
                      <SelectItem value="crawler">crawler</SelectItem>
                      <SelectItem value="worker">worker</SelectItem>
                      <SelectItem value="guard">guard</SelectItem>
                      <SelectItem value="orchestrator">orchestrator</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="md:col-span-1 flex items-center justify-end gap-2">
                  <div className="flex items-center gap-2">
                    <Switch id="autorefresh" checked={autoRefresh} onCheckedChange={setAutoRefresh} />
                    <label htmlFor="autorefresh" className="text-sm">Auto</label>
                  </div>
                </div>
              </div>
              <Separator />
              <div className="flex items-center justify-between gap-3">
                <div className="text-xs text-muted-foreground">
                  Всего: {list.total}. Страница {list.page} из {totalPages}.
                </div>
                <div className="flex items-center gap-1">
                  <Button variant="outline" size="icon" aria-label="В начало" disabled={page===1} onClick={()=>setPage(1)}>
                    <ChevronsLeft className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="icon" aria-label="Назад" disabled={page===1} onClick={()=>setPage((p)=>Math.max(1,p-1))}>
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <span className="text-sm px-2">Стр. {page}</span>
                  <Button variant="outline" size="icon" aria-label="Вперёд" disabled={page===totalPages} onClick={()=>setPage((p)=>Math.min(totalPages,p+1))}>
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="icon" aria-label="В конец" disabled={page===totalPages} onClick={()=>setPage(totalPages)}>
                    <ChevronsRight className="h-4 w-4" />
                  </Button>
                  <Select value={String(pageSize)} onValueChange={(v)=>{ setPageSize(Number(v)); setPage(1); }}>
                    <SelectTrigger className="w-[120px]" aria-label="Размер страницы">
                      <SelectValue placeholder="Размер" />
                    </SelectTrigger>
                    <SelectContent>
                      {[10,25,50,100].map(n=> <SelectItem key={n} value={String(n)}>{n}/стр</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Агенты</CardTitle>
              <CardDescription>Список активных и доступных инстансов</CardDescription>
            </CardHeader>
            <CardContent>
              {error && (
                <div className="mb-3 text-sm text-red-600 flex items-center gap-2">
                  <Info className="h-4 w-4" /> {error}
                </div>
              )}
              <ScrollArea className="w-full">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Имя</TableHead>
                      <TableHead>Тип</TableHead>
                      <TableHead>Состояние</TableHead>
                      <TableHead>CPU%</TableHead>
                      <TableHead>MEM%</TableHead>
                      <TableHead>RPS</TableHead>
                      <TableHead>P95</TableHead>
                      <TableHead>Обновлен</TableHead>
                      <TableHead className="w-[220px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {list.items.map((a) => (
                      <TableRow
                        key={a.id}
                        className={selected?.id===a.id ? "bg-muted/40" : ""}
                        onClick={()=>setSelected(a)}
                      >
                        <TableCell className="font-medium">{a.name}</TableCell>
                        <TableCell>{a.kind}</TableCell>
                        <TableCell>
                          <Badge variant={stateVariant[a.state]}>{a.state}</Badge>
                        </TableCell>
                        <TableCell>{a.metrics.cpu.toFixed(0)}</TableCell>
                        <TableCell>{a.metrics.mem.toFixed(0)}</TableCell>
                        <TableCell>{a.metrics.rps.toFixed(1)}</TableCell>
                        <TableCell>{a.metrics.latency_ms_p95.toFixed(0)} ms</TableCell>
                        <TableCell title={a.updatedAt}>{fmtDate(a.updatedAt)}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button size="icon" variant="ghost" disabled={busy || a.state==="running"} onClick={(e)=>{e.stopPropagation(); act(a.id,"start");}} aria-label="Start">
                              <Play className="h-4 w-4" />
                            </Button>
                            <Button size="icon" variant="ghost" disabled={busy || a.state!=="running"} onClick={(e)=>{e.stopPropagation(); act(a.id,"pause");}} aria-label="Pause">
                              <Pause className="h-4 w-4" />
                            </Button>
                            <Button size="icon" variant="ghost" disabled={busy || a.state==="stopped"} onClick={(e)=>{e.stopPropagation(); act(a.id,"stop");}} aria-label="Stop">
                              <Square className="h-4 w-4" />
                            </Button>
                            <ScalePopover onScale={(n)=>scale(a.id,n)} />
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!list.items.length && (
                      <TableRow>
                        <TableCell colSpan={9} className="text-center text-sm text-muted-foreground">Нет агентов</TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>

        {/* Правая колонка: детали выбранного агента */}
        <div className="lg:col-span-5 space-y-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Детали агента</CardTitle>
              <CardDescription>Состояние, действия и конфигурация</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {!selected ? (
                <div className="text-sm text-muted-foreground">Выберите агента из списка слева.</div>
              ) : (
                <>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-base font-medium">{selected.name}</div>
                      <div className="text-xs text-muted-foreground">
                        {selected.kind} • v{selected.version} • создан {fmtDate(selected.createdAt)}
                      </div>
                    </div>
                    <Badge variant={stateVariant[selected.state]}>{selected.state}</Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div className="rounded-md border p-3">
                      <div className="text-xs text-muted-foreground">CPU</div>
                      <div className="text-xl">{selected.metrics.cpu.toFixed(0)}%</div>
                    </div>
                    <div className="rounded-md border p-3">
                      <div className="text-xs text-muted-foreground">MEM</div>
                      <div className="text-xl">{selected.metrics.mem.toFixed(0)}%</div>
                    </div>
                    <div className="rounded-md border p-3">
                      <div className="text-xs text-muted-foreground">RPS</div>
                      <div className="text-xl">{selected.metrics.rps.toFixed(1)}</div>
                    </div>
                    <div className="rounded-md border p-3">
                      <div className="text-xs text-muted-foreground">P95</div>
                      <div className="text-xl">{selected.metrics.latency_ms_p95.toFixed(0)} ms</div>
                    </div>
                  </div>

                  <Tabs defaultValue="metrics">
                    <TabsList>
                      <TabsTrigger value="metrics"><Activity className="h-4 w-4 mr-1" />Метрики</TabsTrigger>
                      <TabsTrigger value="logs"><TerminalSquare className="h-4 w-4 mr-1" />Логи</TabsTrigger>
                      <TabsTrigger value="info"><Info className="h-4 w-4 mr-1" />Инфо</TabsTrigger>
                    </TabsList>
                    <TabsContent value="metrics" className="pt-3">
                      <div className="h-56 w-full rounded-md border p-2">
                        <ResponsiveContainer width="100%" height="100%">
                          <LineChart data={metrics}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="t" tickFormatter={(t)=> new Date(t).toLocaleTimeString()} minTickGap={24} />
                            <YAxis yAxisId="left" />
                            <YAxis yAxisId="right" orientation="right" />
                            <Tooltip labelFormatter={(t)=> new Date(Number(t)).toLocaleString()} />
                            <Legend />
                            <Line yAxisId="left" type="monotone" dataKey="cpu" name="CPU%" dot={false} />
                            <Line yAxisId="left" type="monotone" dataKey="mem" name="MEM%" dot={false} />
                            <Line yAxisId="right" type="monotone" dataKey="rps" name="RPS" dot={false} />
                            <Line yAxisId="right" type="monotone" dataKey="p95" name="P95 ms" dot={false} />
                          </LineChart>
                        </ResponsiveContainer>
                      </div>
                    </TabsContent>
                    <TabsContent value="logs" className="pt-3">
                      <div className="h-56 rounded-md border">
                        <ScrollArea className="h-56 p-2">
                          {visibleLogs.length === 0 ? (
                            <div className="text-sm text-muted-foreground px-2">Нет записей.</div>
                          ) : (
                            <ul className="space-y-1 text-xs font-mono">
                              {visibleLogs.map((l, i) => (
                                <li key={`${l.t}-${i}`} className="grid grid-cols-12 gap-2">
                                  <span className="col-span-3 text-muted-foreground">{new Date(l.t).toLocaleTimeString()}</span>
                                  <span className="col-span-2">
                                    <Badge variant={
                                      l.level==="error" ? "destructive" :
                                      l.level==="warn" ? "default" :
                                      l.level==="info" ? "secondary" : "outline"
                                    }>
                                      {l.level}
                                    </Badge>
                                  </span>
                                  <span className="col-span-7 truncate" title={l.message}>{l.message}</span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </ScrollArea>
                      </div>
                    </TabsContent>
                    <TabsContent value="info" className="pt-3">
                      <div className="rounded-md border p-3 text-xs">
                        <div className="grid grid-cols-2 gap-2">
                          <div className="text-muted-foreground">ID</div><div>{selected.id}</div>
                          <div className="text-muted-foreground">Host</div><div>{selected.runInfo?.host ?? "—"}</div>
                          <div className="text-muted-foreground">PID</div><div>{selected.runInfo?.pid ?? "—"}</div>
                          <div className="text-muted-foreground">ReqID</div><div>{selected.runInfo?.requestId ?? "—"}</div>
                          <div className="text-muted-foreground">Теги</div>
                          <div className="flex flex-wrap gap-1">
                            {(selected.tags ?? []).map((t)=> <Badge key={t} variant="outline">{t}</Badge>)}
                          </div>
                        </div>
                      </div>
                    </TabsContent>
                  </Tabs>

                  <div className="flex items-center justify-end gap-2">
                    <Button size="sm" disabled={busy || selected.state==="running"} onClick={()=>act(selected.id,"start")}>
                      <Play className="h-4 w-4 mr-2" />Запуск
                    </Button>
                    <Button size="sm" variant="outline" disabled={busy || selected.state!=="running"} onClick={()=>act(selected.id,"pause")}>
                      <Pause className="h-4 w-4 mr-2" />Пауза
                    </Button>
                    <Button size="sm" variant="destructive" disabled={busy || selected.state==="stopped"} onClick={()=>act(selected.id,"stop")}>
                      <Square className="h-4 w-4 mr-2" />Стоп
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Создание агента */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Создать агента</CardTitle>
              <CardDescription>Параметры запуска и конфигурация</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                <div className="md:col-span-5">
                  <Input placeholder="Имя агента" value={newName} onChange={(e)=>setNewName(e.target.value)} />
                </div>
                <div className="md:col-span-4">
                  <Select value={newKind} onValueChange={(v)=>setNewKind(v as AgentKind)}>
                    <SelectTrigger><SelectValue placeholder="Тип агента" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="worker">worker</SelectItem>
                      <SelectItem value="planner">planner</SelectItem>
                      <SelectItem value="crawler">crawler</SelectItem>
                      <SelectItem value="guard">guard</SelectItem>
                      <SelectItem value="orchestrator">orchestrator</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="md:col-span-3 flex items-center gap-2">
                  <Button size="sm" onClick={()=>createAgentSafe(createAgent, newName, newKind, newParams)} disabled={busy || !newName.trim()}>
                    <Plus className="h-4 w-4 mr-2" />Создать
                  </Button>
                </div>
                <div className="md:col-span-12">
                  <Textarea
                    placeholder='Доп.параметры JSON, например: {"replicas":2,"tags":["realtime"]}'
                    value={newParams}
                    onChange={(e)=>setNewParams(e.target.value)}
                    className="font-mono text-xs"
                    rows={4}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

/**
 * Хелперы UI
 */
function ScalePopover({ onScale }: { onScale: (replicas: number) => void }) {
  const [open, setOpen] = useState(false);
  const [n, setN] = useState(1);
  return (
    <div className="relative">
      <Button size="sm" variant="outline" onClick={()=>setOpen((o)=>!o)}>
        <Zap className="h-4 w-4 mr-2" />
        Scale
        {open ? <ChevronUp className="h-4 w-4 ml-1" /> : <ChevronDown className="h-4 w-4 ml-1" />}
      </Button>
      {open && (
        <div className="absolute right-0 z-50 mt-2 w-56 rounded-md border bg-background p-3 shadow-md">
          <div className="text-sm font-medium mb-2">Количество реплик</div>
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min={1}
              value={n}
              onChange={(e)=>setN(Math.max(1, Number(e.target.value)))}
              className="w-24"
            />
            <Button size="sm" onClick={()=>{ onScale(n); setOpen(false); }}>
              Применить
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

async function createAgentSafe(
  createAgent: (p: { name: string; kind: AgentKind; params?: any }) => Promise<void>,
  name: string,
  kind: AgentKind,
  paramsRaw: string,
) {
  let params: any | undefined = undefined;
  const raw = paramsRaw.trim();
  if (raw) {
    try { params = JSON.parse(raw); }
    catch { throw new Error("Параметры должны быть JSON"); }
  }
  await createAgent({ name: name.trim(), kind, params });
}
