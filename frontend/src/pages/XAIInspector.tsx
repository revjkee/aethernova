import React, { useCallback, useEffect, useMemo, useRef, useState, Suspense } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertCircle,
  BadgeAlert,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardCopy,
  Download,
  Filter,
  Layers,
  PauseCircle,
  PlayCircle,
  RefreshCcw,
  Search,
  Settings,
  Wifi,
  WifiOff
} from "lucide-react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid, LineChart, Line, Legend } from "recharts";

// shadcn/ui — предполагается, что используется в проекте
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip as UiTooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useToast } from "@/components/ui/use-toast";

/**
 * XAIInspector.tsx — промышленная страница инспекции XAI/моделей.
 *
 * Возможности:
 * - Панель фильтров: модель, период, уровень риска, поиск по тексту
 * - Live stream WebSocket (вкл/выкл), устойчивость к разрывам
 * - Метрики и графики (Recharts)
 * - Таблица инцидентов с пагинацией и выбором строки
 * - Инспектор деталей инцидента (JSON, фичи, трассировки)
 * - Экспорт в CSV, копирование JSON в буфер обмена
 * - Мягкая обработка ошибок, отмена запросов, idempotent refresh
 * - Клавиатурные шорткаты: R (refresh), L (live toggle), / (focus search)
 */

// =========================
// Типы данных
// =========================

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface XaIIncident {
  id: string;
  timestamp: string; // ISO
  model: string;
  requestId: string;
  userId?: string;
  risk: RiskLevel;
  latencyMs: number;
  tokens: number;
  category: string; // e.g. "bias", "safety", "hallucination"
  summary: string;
  features?: Record<string, number | string | boolean>;
  inputPreview?: string;
  outputPreview?: string;
  trace?: Array<{ span: string; durationMs: number; meta?: Record<string, string> }>;
  payload?: unknown; // сырой JSON
}

export interface MetricsPoint {
  ts: number; // epoch ms
  p95Latency: number;
  riskScore: number; // агрегатная метрика риска [0..100]
  incidents: number; // кол-во инцидентов
}

// =========================
// Утилиты
// =========================

const API_BASE = (import.meta as any)?.env?.VITE_XAI_API_BASE ?? "/api/xai";

function clsx(...v: Array<string | false | null | undefined>) {
  return v.filter(Boolean).join(" ");
}

function formatDate(iso: string) {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function downloadBlob(filename: string, data: string, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function incidentsToCsv(rows: XaIIncident[]): string {
  const header = [
    "id","timestamp","model","requestId","userId","risk","latencyMs","tokens","category","summary"
  ];
  const escape = (s: any) => `"${String(s ?? "").replace(/"/g, '""')}"`;
  const lines = rows.map(r => [
    r.id, r.timestamp, r.model, r.requestId, r.userId ?? "", r.risk, r.latencyMs, r.tokens, r.category, r.summary
  ].map(escape).join(","));
  return [header.join(","), ...lines].join("\n");
}

// Простая эвристика для подсветки риска
function riskBadgeColor(level: RiskLevel) {
  switch (level) {
    case "low": return "bg-emerald-100 text-emerald-700 border-emerald-200";
    case "medium": return "bg-amber-100 text-amber-800 border-amber-200";
    case "high": return "bg-orange-100 text-orange-800 border-orange-200";
    case "critical": return "bg-red-100 text-red-800 border-red-200";
  }
}

// =========================
// Надежный fetch-хук с отменой и повтором
// =========================

interface UseFetchOpts<T> { path: string; deps?: any[]; enabled?: boolean; map?: (x:any)=>T; }

function useFetch<T = any>({ path, deps = [], enabled = true, map }: UseFetchOpts<T>) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState<boolean>(enabled);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const exec = useCallback(async () => {
    if (!enabled) return;
    abortRef.current?.abort();
    const ctl = new AbortController();
    abortRef.current = ctl;
    setLoading(true); setError(null);
    try {
      const res = await fetch(`${API_BASE}${path}`, { signal: ctl.signal, headers: { "Accept": "application/json" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(map ? map(json) : json);
    } catch (e: any) {
      if (e?.name === "AbortError") return;
      setError(e?.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [path, enabled, map]);

  useEffect(() => { exec(); return () => abortRef.current?.abort(); }, deps); // eslint-disable-line

  return { data, loading, error, refresh: exec } as const;
}

// =========================
// Live WebSocket hook с автопереподключением
// =========================

function useLiveStream(enabled: boolean, onMessage: (inc: XaIIncident) => void) {
  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!enabled) { wsRef.current?.close(); wsRef.current = null; return; }

    const connect = () => {
      try {
        const url = (API_BASE.startsWith("http"))
          ? API_BASE.replace(/^http/, "ws") + "/live"
          : (location.protocol === "https:" ? "wss://" : "ws://") + location.host + API_BASE + "/live";
        const ws = new WebSocket(url);
        wsRef.current = ws;
        ws.onmessage = (evt) => {
          try { const obj = JSON.parse(evt.data); onMessage(obj as XaIIncident); } catch {}
        };
        ws.onclose = () => { if (enabled) timerRef.current = window.setTimeout(connect, 1500); };
        ws.onerror = () => { try { ws.close(); } catch {} };
      } catch {
        timerRef.current = window.setTimeout(connect, 2000);
      }
    };

    connect();
    return () => { if (timerRef.current) window.clearTimeout(timerRef.current); wsRef.current?.close(); };
  }, [enabled, onMessage]);
}

// =========================
// Основной компонент страницы
// =========================

const DEFAULT_RANGE = "24h" as const;

const rangeOptions: Array<{ value: string; label: string }> = [
  { value: "1h", label: "1 час" },
  { value: "6h", label: "6 часов" },
  { value: "12h", label: "12 часов" },
  { value: "24h", label: "24 часа" },
  { value: "7d", label: "7 дней" },
  { value: "30d", label: "30 дней" }
];

export default function XAIInspector() {
  const { toast } = useToast();
  const [model, setModel] = useState<string>("any");
  const [range, setRange] = useState<string>(DEFAULT_RANGE);
  const [risk, setRisk] = useState<RiskLevel | "any">("any");
  const [query, setQuery] = useState<string>("");
  const [live, setLive] = useState<boolean>(false);
  const [page, setPage] = useState<number>(1);
  const [selected, setSelected] = useState<XaIIncident | null>(null);

  const searchInputRef = useRef<HTMLInputElement | null>(null);

  // Шорткаты
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "r" || e.key === "R") { e.preventDefault(); metrics.refresh(); incidents.refresh(); }
      if (e.key === "l" || e.key === "L") { e.preventDefault(); setLive((v) => !v); }
      if (e.key === "/") { e.preventDefault(); searchInputRef.current?.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Модели (селектор)
  const models = useFetch<string[]>({ path: "/models", deps: [], enabled: true });

  // Метрики
  const metrics = useFetch<MetricsPoint[]>({
    path: `/metrics?range=${encodeURIComponent(range)}${model!=="any"?`&model=${encodeURIComponent(model)}`:""}`,
    deps: [range, model],
    enabled: true,
  });

  // Инциденты
  const incidents = useFetch<{ items: XaIIncident[]; total: number }>({
    path: `/incidents?page=${page}&q=${encodeURIComponent(query)}&range=${encodeURIComponent(range)}${model!=="any"?`&model=${encodeURIComponent(model)}`:""}${risk!=="any"?`&risk=${risk}`:""}`,
    deps: [page, query, range, model, risk],
  });

  // Live stream
  useLiveStream(live, (inc) => {
    // Мгновенно вставляем инцидент в начало списка
    incidents.refresh();
    toast({ description: `Новый инцидент: ${inc.summary?.slice(0, 80) ?? inc.id}` });
  });

  const currentMetrics = metrics.data ?? [];
  const currentItems = incidents.data?.items ?? [];
  const total = incidents.data?.total ?? 0;

  const exportCsv = useCallback(() => {
    const csv = incidentsToCsv(currentItems);
    downloadBlob(`xai-incidents-${Date.now()}.csv`, csv, "text/csv;charset=utf-8");
  }, [currentItems]);

  const copyJson = useCallback(() => {
    try {
      const text = JSON.stringify(currentItems, null, 2);
      navigator.clipboard.writeText(text);
      toast({ description: "JSON скопирован в буфер обмена" });
    } catch {
      toast({ description: "Не удалось скопировать JSON" });
    }
  }, [currentItems, toast]);

  const statusIcon = useMemo(() => live ? <Wifi className="h-4 w-4"/> : <WifiOff className="h-4 w-4"/>, [live]);

  const riskCounts = useMemo(() => {
    const acc = { low:0, medium:0, high:0, critical:0 } as Record<RiskLevel, number>;
    for (const r of currentItems) acc[r.risk]++;
    return acc;
  }, [currentItems]);

  return (
    <div className="p-4 md:p-6 space-y-4">
      <header className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <div>
          <h1 className="text-2xl md:text-3xl font-semibold tracking-tight">XAI Inspector</h1>
          <p className="text-sm text-muted-foreground">Диагностика рисков, трассировок и качества вывода моделей</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={() => { metrics.refresh(); incidents.refresh(); }}>
            <RefreshCcw className="h-4 w-4 mr-2"/>Обновить <span className="sr-only">R</span>
          </Button>
          <Button variant={live ? "destructive" : "default"} onClick={() => setLive(v=>!v)}>
            {live ? <PauseCircle className="h-4 w-4 mr-2"/> : <PlayCircle className="h-4 w-4 mr-2"/>}
            Live {statusIcon}
          </Button>
          <Button variant="outline" onClick={exportCsv}><Download className="h-4 w-4 mr-2"/>CSV</Button>
          <Button variant="outline" onClick={copyJson}><ClipboardCopy className="h-4 w-4 mr-2"/>JSON</Button>
        </div>
      </header>

      {/* Панель фильтров */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2"><Filter className="h-4 w-4"/>Фильтры</CardTitle>
          <CardDescription>Сфокусируйтесь на нужных инцидентах</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
            <div className="md:col-span-4">
              <Label htmlFor="search">Поиск</Label>
              <div className="relative">
                <Search className="h-4 w-4 absolute left-2 top-2.5 text-muted-foreground"/>
                <Input ref={searchInputRef} id="search" placeholder="requestId, summary, userId…" className="pl-8"
                  value={query} onChange={(e)=>{ setPage(1); setQuery(e.target.value); }} />
              </div>
            </div>
            <div className="md:col-span-3">
              <Label>Модель</Label>
              <Select value={model} onValueChange={(v)=>{ setPage(1); setModel(v); }}>
                <SelectTrigger>
                  <SelectValue placeholder="Выберите модель" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">Любая</SelectItem>
                  {(models.data ?? ["gpt-4o", "gpt-5", "llama-3.1"]).map(m => (
                    <SelectItem key={m} value={m}>{m}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="md:col-span-3">
              <Label>Период</Label>
              <Select value={range} onValueChange={(v)=>{ setPage(1); setRange(v); }}>
                <SelectTrigger>
                  <SelectValue placeholder="Период" />
                </SelectTrigger>
                <SelectContent>
                  {rangeOptions.map(r => <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="md:col-span-2">
              <Label>Риск</Label>
              <Select value={risk} onValueChange={(v)=>{ setPage(1); setRisk(v as any); }}>
                <SelectTrigger>
                  <SelectValue placeholder="Любой" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">Любой</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Метрики */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <MetricCard title="Инциденты" value={incidents.loading ? "…" : String(total)} subtitle="за период" icon={<BadgeAlert className="h-5 w-5"/>} />
        <MetricCard title="p95 Latency" value={metrics.loading ? "…" : `${Math.round((currentMetrics.at(-1)?.p95Latency ?? 0))} ms`} subtitle="последняя точка" icon={<BarChart3 className="h-5 w-5"/>} />
        <MetricCard title="Риск (agg)" value={metrics.loading ? "…" : `${Math.round((currentMetrics.at(-1)?.riskScore ?? 0))}`} subtitle="0..100" icon={<AlertCircle className="h-5 w-5"/>} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Динамика: инциденты и p95</CardTitle>
            <CardDescription>По выбранному периоду и модели</CardDescription>
          </CardHeader>
          <CardContent className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChartDual data={currentMetrics} />
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Распределение по рискам</CardTitle>
            <CardDescription>Текущая выборка таблицы</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(["critical","high","medium","low"] as RiskLevel[]).map((lvl) => (
                <div key={lvl} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={clsx("border px-2 py-0.5 rounded text-xs", riskBadgeColor(lvl))}>{lvl}</span>
                  </div>
                  <div className="text-sm tabular-nums">{riskCounts[lvl]}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Таблица + Инспектор */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Card className="xl:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Инциденты</CardTitle>
            <CardDescription>
              {incidents.loading ? "Загрузка…" : incidents.error ? `Ошибка: ${incidents.error}` : `${currentItems.length} из ${total}`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-lg border overflow-hidden">
              <TableIncidents
                rows={currentItems}
                onSelect={(r)=> setSelected(r)}
                selectedId={selected?.id}
              />
            </div>
            <div className="flex items-center justify-between mt-3">
              <div className="text-xs text-muted-foreground">Стр. {page}</div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={()=> setPage(p=> Math.max(1, p-1))}>Назад</Button>
                <Button variant="outline" size="sm" onClick={()=> setPage(p=> p+1)}>Вперёд</Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Инспектор</CardTitle>
            <CardDescription>{selected ? selected.id : "Выберите инцидент"}</CardDescription>
          </CardHeader>
          <CardContent>
            {selected ? <IncidentInspector item={selected}/> : (
              <div className="text-sm text-muted-foreground">Нет выбранного инцидента</div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// =========================
// Подкомпоненты
// =========================

function MetricCard({ title, subtitle, value, icon }: { title: string; subtitle?: string; value: string; icon?: React.ReactNode }) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold tabular-nums">{value}</div>
        {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
      </CardContent>
    </Card>
  );
}

function TableIncidents({ rows, onSelect, selectedId }: { rows: XaIIncident[]; onSelect: (r: XaIIncident)=>void; selectedId?: string | null }) {
  return (
    <div className="max-h-[420px] overflow-auto">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background z-10">
          <tr className="border-b text-muted-foreground">
            <th className="text-left px-3 py-2 w-10">#</th>
            <th className="text-left px-3 py-2">Время</th>
            <th className="text-left px-3 py-2">Модель</th>
            <th className="text-left px-3 py-2">Риск</th>
            <th className="text-left px-3 py-2">Категория</th>
            <th className="text-left px-3 py-2">Latency</th>
            <th className="text-left px-3 py-2">Токены</th>
            <th className="text-left px-3 py-2">Аннотация</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={r.id}
                className={clsx("border-b hover:bg-muted/40 cursor-pointer", selectedId===r.id && "bg-muted")}
                onClick={()=> onSelect(r)}>
              <td className="px-3 py-2 text-muted-foreground">{i+1}</td>
              <td className="px-3 py-2 whitespace-nowrap">{formatDate(r.timestamp)}</td>
              <td className="px-3 py-2">{r.model}</td>
              <td className="px-3 py-2"><span className={clsx("border px-2 py-0.5 rounded text-xs", riskBadgeColor(r.risk))}>{r.risk}</span></td>
              <td className="px-3 py-2">{r.category}</td>
              <td className="px-3 py-2 tabular-nums">{r.latencyMs} ms</td>
              <td className="px-3 py-2 tabular-nums">{r.tokens}</td>
              <td className="px-3 py-2 truncate max-w-[320px]">{r.summary}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr><td colSpan={8} className="text-center text-sm text-muted-foreground py-6">Нет данных</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function IncidentInspector({ item }: { item: XaIIncident }) {
  const [tab, setTab] = useState<string>("overview");
  const pretty = useMemo(() => {
    try { return JSON.stringify(item.payload ?? item, null, 2); } catch { return "{}"; }
  }, [item]);

  const copy = useCallback(() => {
    try { navigator.clipboard.writeText(pretty); } catch {}
  }, [pretty]);

  return (
    <Tabs value={tab} onValueChange={setTab}>
      <TabsList className="grid grid-cols-3">
        <TabsTrigger value="overview">Сводка</TabsTrigger>
        <TabsTrigger value="trace">Трасса</TabsTrigger>
        <TabsTrigger value="json">JSON</TabsTrigger>
      </TabsList>
      <TabsContent value="overview" className="space-y-3">
        <div className="grid grid-cols-2 gap-2 text-sm">
          <MetaRow k="ID" v={item.id} />
          <MetaRow k="Время" v={formatDate(item.timestamp)} />
          <MetaRow k="Модель" v={item.model} />
          <MetaRow k="Риск" v={item.risk} badge />
          <MetaRow k="Категория" v={item.category} />
          <MetaRow k="Latency" v={`${item.latencyMs} ms`} />
          <MetaRow k="Токены" v={String(item.tokens)} />
          {item.userId && <MetaRow k="User" v={item.userId} />}
        </div>
        {item.inputPreview && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">Вход</div>
            <ScrollArea className="max-h-24 border rounded p-2 text-sm bg-muted/30">
              {item.inputPreview}
            </ScrollArea>
          </div>
        )}
        {item.outputPreview && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">Выход</div>
            <ScrollArea className="max-h-24 border rounded p-2 text-sm bg-muted/30">
              {item.outputPreview}
            </ScrollArea>
          </div>
        )}
        {item.features && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">Фичи</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {Object.entries(item.features).map(([k,v]) => (
                <div key={k} className="flex items-center justify-between border rounded px-2 py-1">
                  <span className="text-muted-foreground">{k}</span>
                  <span className="tabular-nums">{String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </TabsContent>
      <TabsContent value="trace">
        <div className="space-y-2">
          {(item.trace ?? []).length === 0 && (
            <div className="text-sm text-muted-foreground">Нет трассировок</div>
          )}
          <div className="space-y-2">
            {(item.trace ?? []).map((t, i) => (
              <div key={i} className="flex items-center gap-2">
                <div className="w-40 text-xs text-muted-foreground truncate">{t.span}</div>
                <div className="flex-1 h-2 bg-muted rounded overflow-hidden">
                  <div className="h-full bg-primary" style={{ width: `${Math.min(100, t.durationMs/ (item.latencyMs||1) * 100)}%` }} />
                </div>
                <div className="w-20 text-right text-xs tabular-nums">{t.durationMs} ms</div>
              </div>
            ))}
          </div>
        </div>
      </TabsContent>
      <TabsContent value="json">
        <div className="flex items-center justify-between mb-2">
          <div className="text-xs text-muted-foreground">Сырые данные</div>
          <Button variant="outline" size="sm" onClick={copy}><ClipboardCopy className="h-4 w-4 mr-2"/>Копировать</Button>
        </div>
        <ScrollArea className="h-72 border rounded p-2 text-xs bg-muted/30">
          <pre className="whitespace-pre-wrap break-all">{pretty}</pre>
        </ScrollArea>
      </TabsContent>
    </Tabs>
  );
}

function MetaRow({ k, v, badge }: { k: string; v: string; badge?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="text-muted-foreground">{k}</div>
      {badge ? <span className={clsx("border px-2 py-0.5 rounded text-xs", riskBadgeColor(v as RiskLevel))}>{v}</span> : <div className="font-medium text-right truncate">{v}</div>}
    </div>
  );
}

function ComposedChartDual({ data }: { data: MetricsPoint[] }) {
  const formatted = useMemo(() => (data ?? []).map(d => ({
    ts: new Date(d.ts).toLocaleTimeString(),
    incidents: d.incidents,
    p95Latency: d.p95Latency,
    riskScore: d.riskScore,
  })), [data]);

  return (
    <LineChart data={formatted}>
      <CartesianGrid strokeDasharray="3 3" />
      <XAxis dataKey="ts" tick={{ fontSize: 12 }} />
      <YAxis yAxisId="left" tick={{ fontSize: 12 }} />
      <YAxis yAxisId="right" orientation="right" tick={{ fontSize: 12 }} />
      <Tooltip />
      <Legend />
      <Line yAxisId="left" type="monotone" dataKey="incidents" strokeWidth={2} dot={false} />
      <Line yAxisId="right" type="monotone" dataKey="p95Latency" strokeWidth={2} dot={false} />
    </LineChart>
  );
}
