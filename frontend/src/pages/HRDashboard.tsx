// frontend/src/pages/HRDashboard.tsx
import * as React from "react";
import { useState, useEffect, useMemo, useCallback } from "react";
import { z } from "zod";
import { motion } from "framer-motion";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Download, Upload, RefreshCw, Search, Users, BriefcaseBusiness, Clock4, Sparkles,
  ArrowUpRight, ArrowDownRight, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
  Check, X, Calendar, MoveRight, BarChart3, ListChecks, FilePlus2, Info, Filter, TrendingUp,
} from "lucide-react";
import {
  LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar,
} from "recharts";

/**
 * Типы и схемы
 */
const StageSchema = z.enum([
  "applied", "screening", "interview", "offer", "hired", "rejected",
]);
export type Stage = z.infer<typeof StageSchema>;

const VacancySchema = z.object({
  id: z.string(),
  title: z.string(),
  dept: z.string(),
  level: z.string().optional().default(""),
  openedAt: z.string().datetime(),
  headcount: z.number().int().min(1),
  filled: z.number().int().min(0).default(0),
});
export type Vacancy = z.infer<typeof VacancySchema>;

const CandidateSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
  phone: z.string().optional().default(""),
  positionId: z.string(),
  positionTitle: z.string(),
  stage: StageSchema,
  source: z.string().optional().default(""),
  experienceYears: z.number().min(0).max(60).optional().default(0),
  salaryExpect: z.number().min(0).optional().default(0),
  location: z.string().optional().default(""),
  tags: z.array(z.string()).optional().default([]),
  updatedAt: z.string().datetime(),
  createdAt: z.string().datetime(),
  notes: z.string().optional().default(""),
});
export type Candidate = z.infer<typeof CandidateSchema>;

const KpiSchema = z.object({
  totalCandidates: z.number().int().min(0),
  openVacancies: z.number().int().min(0),
  avgTimeToHireDays: z.number().min(0),
  offerAcceptanceRate: z.number().min(0).max(1),
  trendCandidates7d: z.number(), // +/- за 7 дней
});
type KPI = z.infer<typeof KpiSchema>;

const TimeseriesPointSchema = z.object({
  t: z.string().datetime(),
  candidates: z.number().min(0),
  hires: z.number().min(0),
  offers: z.number().min(0),
});
type TimeseriesPoint = z.infer<typeof TimeseriesPointSchema>;

const FunnelSchema = z.object({
  applied: z.number().min(0),
  screening: z.number().min(0),
  interview: z.number().min(0),
  offer: z.number().min(0),
  hired: z.number().min(0),
  rejected: z.number().min(0),
});
type Funnel = z.infer<typeof FunnelSchema>;

const CandidateListSchema = z.object({
  items: z.array(CandidateSchema),
  total: z.number().int().min(0),
  page: z.number().int().min(1),
  pageSize: z.number().int().min(1),
});
type CandidateList = z.infer<typeof CandidateListSchema>;

const VacancyListSchema = z.object({
  items: z.array(VacancySchema),
});
type VacancyList = z.infer<typeof VacancyListSchema>;

/**
 * Универсальный API с устойчивостью
 */
async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { headers: { "Content-Type": "application/json" }, ...init });
  const text = await res.text();
  if (!res.ok) {
    try {
      const j = JSON.parse(text);
      throw new Error(j.detail || j.message || `HTTP ${res.status}`);
    } catch {
      throw new Error(text || `HTTP ${res.status}`);
    }
  }
  try { return JSON.parse(text) as T; } catch { return undefined as unknown as T; }
}

/**
 * Вспомогательные функции
 */
function csvDownload(filename: string, rows: Record<string, any>[]) {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const esc = (v: any) => {
    const s = v == null ? "" : typeof v === "string" ? v : JSON.stringify(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => esc((r as any)[h])).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

const stageBadge: Record<Stage, React.ComponentProps<typeof Badge>["variant"]> = {
  applied: "secondary",
  screening: "outline",
  interview: "default",
  offer: "default",
  hired: "success" as any /* shadcn может не иметь 'success'; fallback ниже */,
  rejected: "destructive",
};

function fmtDate(iso: string) {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/**
 * Основная страница
 */
export default function HRDashboard() {
  const [tab, setTab] = useState<"overview" | "candidates" | "vacancies">("overview");

  // Фильтры и состояние
  const [q, setQ] = useState("");
  const [stageFilter, setStageFilter] = useState<Stage | "any">("any");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [onlyActive, setOnlyActive] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Данные
  const [kpi, setKpi] = useState<KPI | null>(null);
  const [series, setSeries] = useState<TimeseriesPoint[]>([]);
  const [funnel, setFunnel] = useState<Funnel | null>(null);
  const [cands, setCands] = useState<CandidateList>({ items: [], total: 0, page: 1, pageSize: 25 });
  const [vacs, setVacs] = useState<VacancyList>({ items: [] });
  const [selected, setSelected] = useState<Candidate | null>(null);

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Загрузка
  const loadOverview = useCallback(async () => {
    try {
      setError(null);
      const [k, s, f] = await Promise.all([
        api<unknown>("/api/hr/kpi"),
        api<unknown>("/api/hr/timeseries?window=30d"),
        api<unknown>("/api/hr/funnel"),
      ]);
      setKpi(KpiSchema.parse(k));
      setSeries((Array.isArray(s) ? s : []).map((x) => TimeseriesPointSchema.parse(x)));
      setFunnel(FunnelSchema.parse(f));
    } catch (e: any) {
      setError(e.message || "Ошибка загрузки Overview");
    }
  }, []);

  const loadCandidates = useCallback(async () => {
    try {
      setError(null);
      const params = new URLSearchParams({
        page: String(page),
        pageSize: String(pageSize),
      });
      if (q.trim()) params.set("q", q.trim());
      if (stageFilter !== "any") params.set("stage", stageFilter);
      const raw = await api<unknown>(`/api/hr/candidates?${params.toString()}`);
      const parsed = CandidateListSchema.parse(raw);
      setCands(parsed);
      if (!selected && parsed.items.length) setSelected(parsed.items[0]);
    } catch (e: any) {
      setError(e.message || "Ошибка загрузки кандидатов");
    }
  }, [q, stageFilter, page, pageSize, selected]);

  const loadVacancies = useCallback(async () => {
    try {
      setError(null);
      const raw = await api<unknown>("/api/hr/vacancies?active=" + String(onlyActive));
      const parsed = VacancyListSchema.parse(raw);
      setVacs(parsed);
    } catch (e: any) {
      setError(e.message || "Ошибка загрузки вакансий");
    }
  }, [onlyActive]);

  useEffect(() => {
    loadOverview();
    loadCandidates();
    loadVacancies();
  }, [loadOverview, loadCandidates, loadVacancies]);

  // Автообновление
  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => {
      if (tab === "overview") loadOverview();
      if (tab === "candidates") loadCandidates();
      if (tab === "vacancies") loadVacancies();
    }, 8000);
    return () => clearInterval(id);
  }, [autoRefresh, tab, loadOverview, loadCandidates, loadVacancies]);

  // Сортировка таблицы кандидатов
  type SortKey = "name" | "positionTitle" | "stage" | "updatedAt" | "experienceYears" | "salaryExpect";
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" } | null>({ key: "updatedAt", dir: "desc" });

  const sorted = useMemo(() => {
    const arr = [...cands.items];
    if (!sort) return arr;
    const { key, dir } = sort;
    const m = dir === "asc" ? 1 : -1;
    arr.sort((a, b) => {
      let A: number | string = "";
      let B: number | string = "";
      switch (key) {
        case "updatedAt":
          A = new Date(a.updatedAt).getTime(); B = new Date(b.updatedAt).getTime(); break;
        case "experienceYears":
          A = a.experienceYears ?? 0; B = b.experienceYears ?? 0; break;
        case "salaryExpect":
          A = a.salaryExpect ?? 0; B = b.salaryExpect ?? 0; break;
        default:
          A = (a as any)[key] ?? ""; B = (b as any)[key] ?? "";
      }
      if (A < B) return -1 * m;
      if (A > B) return 1 * m;
      return 0;
    });
    return arr;
  }, [cands.items, sort]);

  // Пагинация: серверная уже есть, но для UX сортировок держим текущую страницу
  const totalPages = Math.max(1, Math.ceil(cands.total / cands.pageSize));
  useEffect(() => { if (page > totalPages) setPage(totalPages); }, [page, totalPages]);

  // Действия ATS
  const moveStage = async (candId: string, to: Stage) => {
    setBusy(true);
    try {
      await api(`/api/hr/candidates/${candId}/move`, { method: "POST", body: JSON.stringify({ to }) });
      await loadCandidates();
      await loadOverview();
    } catch (e: any) {
      setError(e.message || "Ошибка смены этапа");
    } finally {
      setBusy(false);
    }
  };

  const reject = async (candId: string, reason: string) => {
    setBusy(true);
    try {
      await api(`/api/hr/candidates/${candId}/reject`, { method: "POST", body: JSON.stringify({ reason }) });
      await loadCandidates();
      await loadOverview();
    } catch (e: any) {
      setError(e.message || "Ошибка отклонения");
    } finally {
      setBusy(false);
    }
  };

  const schedule = async (candId: string, whenIso: string, title: string) => {
    setBusy(true);
    try {
      await api(`/api/hr/candidates/${candId}/schedule`, { method: "POST", body: JSON.stringify({ when: whenIso, title }) });
    } catch (e: any) {
      setError(e.message || "Ошибка планирования");
    } finally {
      setBusy(false);
    }
  };

  // Экспорт/импорт
  const exportCSV = () => {
    csvDownload(
      `candidates_${new Date().toISOString().replace(/[:.]/g, "-")}.csv`,
      sorted.map((c) => ({
        id: c.id, name: c.name, email: c.email, phone: c.phone,
        position: c.positionTitle, stage: c.stage, source: c.source,
        exp_years: c.experienceYears, salary_expect: c.salaryExpect,
        location: c.location, tags: (c.tags || []).join("|"),
        updatedAt: c.updatedAt, createdAt: c.createdAt,
      }))
    );
  };

  const importJson = async (json: string) => {
    try {
      const payload = JSON.parse(json);
      if (!Array.isArray(payload)) throw new Error("Ожидается массив объектов Candidate");
      // Опциональная локальная валидация
      payload.forEach((x) => CandidateSchema.parse(x));
      await api("/api/hr/candidates/import", { method: "POST", body: JSON.stringify(payload) });
      await loadCandidates();
      await loadOverview();
    } catch (e: any) {
      setError(e.message || "Ошибка импорта");
    }
  };

  return (
    <div className="p-4 md:p-6 space-y-6">
      <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">HR Dashboard</h1>
            <p className="text-sm text-muted-foreground">
              Наблюдение за воронкой найма, кандидатами и вакансиями. Реальные данные обновляются автоматически.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => { loadOverview(); loadCandidates(); loadVacancies(); }}>
              <RefreshCw className="h-4 w-4 mr-2" /> Обновить
            </Button>
            <div className="flex items-center gap-2">
              <Switch id="autorefresh" checked={autoRefresh} onCheckedChange={setAutoRefresh} />
              <label htmlFor="autorefresh" className="text-sm">Auto</label>
            </div>
          </div>
        </div>
      </motion.div>

      {error && (
        <div className="text-sm text-red-600 flex items-center gap-2">
          <Info className="h-4 w-4" /> {error}
        </div>
      )}

      {/* KPI */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <KpiCard
          icon={<Users className="h-5 w-5" aria-hidden />}
          title="Кандидаты"
          value={kpi?.totalCandidates ?? 0}
          hint="Всего в базе"
          trend={kpi?.trendCandidates7d ?? 0}
        />
        <KpiCard
          icon={<BriefcaseBusiness className="h-5 w-5" aria-hidden />}
          title="Открытые вакансии"
          value={kpi?.openVacancies ?? 0}
          hint="Активные позиции"
        />
        <KpiCard
          icon={<Clock4 className="h-5 w-5" aria-hidden />}
          title="Time-to-Hire"
          value={`${(kpi?.avgTimeToHireDays ?? 0).toFixed(1)} дн.`}
          hint="Среднее время"
        />
        <KpiCard
          icon={<Sparkles className="h-5 w-5" aria-hidden />}
          title="Offer Acceptance"
          value={`${Math.round((kpi?.offerAcceptanceRate ?? 0) * 100)}%`}
          hint="Доля принятых офферов"
        />
      </div>

      {/* Вкладки */}
      <Tabs value={tab} onValueChange={(v) => setTab(v as any)}>
        <TabsList>
          <TabsTrigger value="overview"><BarChart3 className="h-4 w-4 mr-1" />Overview</TabsTrigger>
          <TabsTrigger value="candidates"><ListChecks className="h-4 w-4 mr-1" />Кандидаты</TabsTrigger>
          <TabsTrigger value="vacancies"><BriefcaseBusiness className="h-4 w-4 mr-1" />Вакансии</TabsTrigger>
        </TabsList>

        {/* OVERVIEW */}
        <TabsContent value="overview" className="space-y-6 pt-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="lg:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Динамика за 30 дней</CardTitle>
                <CardDescription>Кандидаты, офферы и найм</CardDescription>
              </CardHeader>
              <CardContent className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={series}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="t" tickFormatter={(t) => new Date(t).toLocaleDateString()} minTickGap={24} />
                    <YAxis />
                    <Tooltip labelFormatter={(t) => new Date(String(t)).toLocaleString()} />
                    <Legend />
                    <Line type="monotone" dataKey="candidates" name="Кандидаты" dot={false} />
                    <Line type="monotone" dataKey="offers" name="Офферы" dot={false} />
                    <Line type="monotone" dataKey="hires" name="Наймы" dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Воронка найма</CardTitle>
                <CardDescription>Конверсия по этапам</CardDescription>
              </CardHeader>
              <CardContent className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={[
                      { stage: "applied", v: funnel?.applied ?? 0 },
                      { stage: "screening", v: funnel?.screening ?? 0 },
                      { stage: "interview", v: funnel?.interview ?? 0 },
                      { stage: "offer", v: funnel?.offer ?? 0 },
                      { stage: "hired", v: funnel?.hired ?? 0 },
                      { stage: "rejected", v: funnel?.rejected ?? 0 },
                    ]}
                    layout="vertical"
                    margin={{ left: 24 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis type="number" />
                    <YAxis dataKey="stage" type="category" />
                    <Tooltip />
                    <Bar dataKey="v" name="Кол-во" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* CANDIDATES */}
        <TabsContent value="candidates" className="space-y-6 pt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Фильтры</CardTitle>
              <CardDescription>Поиск, этапы, экспорт и импорт</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                <div className="md:col-span-5">
                  <div className="relative">
                    <Input
                      value={q}
                      onChange={(e) => setQ(e.target.value)}
                      placeholder="Поиск по имени, email, вакансии…"
                      aria-label="Поиск"
                    />
                    <Search className="h-4 w-4 absolute right-2 top-2.5" />
                  </div>
                </div>
                <div className="md:col-span-3">
                  <Select value={stageFilter} onValueChange={(v) => { setStageFilter(v as any); setPage(1); }}>
                    <SelectTrigger aria-label="Этап">
                      <SelectValue placeholder="Любой этап" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="any">Любой</SelectItem>
                      {StageSchema.options.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="md:col-span-4 flex items-center justify-end gap-2">
                  <Button variant="outline" size="sm" onClick={exportCSV}>
                    <Download className="h-4 w-4 mr-2" /> Экспорт CSV
                  </Button>
                  <ImportJson onImport={importJson} />
                </div>
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div className="text-xs text-muted-foreground">
                  Найдено: {cands.total}. Стр. {cands.page} из {totalPages}.
                </div>
                <div className="flex items-center gap-1">
                  <Button variant="outline" size="icon" disabled={page === 1} onClick={() => setPage(1)} aria-label="В начало">
                    <ChevronsLeft className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="icon" disabled={page === 1} onClick={() => setPage((p) => Math.max(1, p - 1))} aria-label="Назад">
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <span className="px-2 text-sm">Стр. {page}</span>
                  <Button variant="outline" size="icon" disabled={page === totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))} aria-label="Вперёд">
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="icon" disabled={page === totalPages} onClick={() => setPage(totalPages)} aria-label="В конец">
                    <ChevronsRight className="h-4 w-4" />
                  </Button>
                  <Select value={String(pageSize)} onValueChange={(v) => { setPageSize(Number(v)); setPage(1); }}>
                    <SelectTrigger className="w-[120px]" aria-label="Размер страницы">
                      <SelectValue placeholder="Размер" />
                    </SelectTrigger>
                    <SelectContent>
                      {[10, 25, 50, 100].map((n) => <SelectItem key={n} value={String(n)}>{n}/стр</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <Card className="lg:col-span-8">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg">Кандидаты</CardTitle>
                <CardDescription>Управление этапами и быстрые действия</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="w-full">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <SortableTh label="Имя" sort={sort} setSort={setSort} keyName="name" />
                        <SortableTh label="Вакансия" sort={sort} setSort={setSort} keyName="positionTitle" />
                        <TableHead>Этап</TableHead>
                        <SortableTh label="Опыт" sort={sort} setSort={setSort} keyName="experienceYears" />
                        <SortableTh label="Ожидания" sort={sort} setSort={setSort} keyName="salaryExpect" />
                        <SortableTh label="Обновлен" sort={sort} setSort={setSort} keyName="updatedAt" />
                        <TableHead className="w-[240px]" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sorted.map((c) => (
                        <TableRow
                          key={c.id}
                          className={selected?.id === c.id ? "bg-muted/40" : ""}
                          onClick={() => setSelected(c)}
                        >
                          <TableCell className="font-medium">{c.name}</TableCell>
                          <TableCell>{c.positionTitle}</TableCell>
                          <TableCell>
                            <Badge variant={stageBadge[c.stage] ?? "secondary"} className="capitalize">{c.stage}</Badge>
                          </TableCell>
                          <TableCell>{(c.experienceYears ?? 0).toFixed(1)}</TableCell>
                          <TableCell>{c.salaryExpect ? `${c.salaryExpect.toLocaleString()} ₽` : "—"}</TableCell>
                          <TableCell title={c.updatedAt}>{fmtDate(c.updatedAt)}</TableCell>
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-2">
                              <Button size="sm" variant="outline" disabled={busy || c.stage === "hired"} onClick={(e) => { e.stopPropagation(); moveStage(c.id, nextStage(c.stage)); }}>
                                <MoveRight className="h-4 w-4 mr-2" /> Дальше
                              </Button>
                              <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); schedule(c.id, new Date(Date.now() + 86400000).toISOString(), "Interview"); }}>
                                <Calendar className="h-4 w-4 mr-2" /> Интервью
                              </Button>
                              <Button size="sm" variant="destructive" onClick={(e) => { e.stopPropagation(); reject(c.id, "Недостаточный опыт"); }}>
                                <X className="h-4 w-4 mr-2" /> Отклонить
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                      {!sorted.length && (
                        <TableRow><TableCell colSpan={7} className="text-center text-sm text-muted-foreground">Нет данных</TableCell></TableRow>
                      )}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card className="lg:col-span-4">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg">Карточка кандидата</CardTitle>
                <CardDescription>Контакты, заметки и действия</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {!selected ? (
                  <div className="text-sm text-muted-foreground">Выберите кандидата слева.</div>
                ) : (
                  <>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-base font-medium">{selected.name}</div>
                        <div className="text-xs text-muted-foreground">{selected.email} • {selected.phone || "—"}</div>
                        <div className="text-xs text-muted-foreground">{selected.location || "—"}</div>
                      </div>
                      <Badge variant={stageBadge[selected.stage] ?? "secondary"} className="capitalize">
                        {selected.stage}
                      </Badge>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div className="rounded-md border p-2">
                        <div className="text-xs text-muted-foreground">Позиция</div>
                        <div>{selected.positionTitle}</div>
                      </div>
                      <div className="rounded-md border p-2">
                        <div className="text-xs text-muted-foreground">Ожидания</div>
                        <div>{selected.salaryExpect ? `${selected.salaryExpect.toLocaleString()} ₽` : "—"}</div>
                      </div>
                      <div className="rounded-md border p-2">
                        <div className="text-xs text-muted-foreground">Опыт</div>
                        <div>{(selected.experienceYears ?? 0).toFixed(1)} лет</div>
                      </div>
                      <div className="rounded-md border p-2">
                        <div className="text-xs text-muted-foreground">Обновлен</div>
                        <div>{fmtDate(selected.updatedAt)}</div>
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Теги</div>
                      <div className="flex flex-wrap gap-1">
                        {(selected.tags ?? []).map((t) => <Badge key={t} variant="outline">{t}</Badge>)}
                        {!(selected.tags ?? []).length && <span className="text-xs text-muted-foreground">Нет</span>}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Заметки</div>
                      <Textarea defaultValue={selected.notes ?? ""} className="text-xs" rows={4} placeholder="Добавить заметку…" />
                    </div>
                    <div className="flex items-center justify-end gap-2">
                      <Button size="sm" onClick={() => moveStage(selected.id, nextStage(selected.stage))}>
                        <MoveRight className="h-4 w-4 mr-2" /> Следующий этап
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => schedule(selected.id, new Date(Date.now() + 2 * 86400000).toISOString(), "Tech Interview")}>
                        <Calendar className="h-4 w-4 mr-2" /> Запланировать
                      </Button>
                      <Button size="sm" variant="destructive" onClick={() => reject(selected.id, "Культурное несоответствие")}>
                        <X className="h-4 w-4 mr-2" /> Отклонить
                      </Button>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* VACANCIES */}
        <TabsContent value="vacancies" className="space-y-6 pt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Вакансии</CardTitle>
              <CardDescription>Открытые позиции и статусы</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Checkbox id="active" checked={onlyActive} onCheckedChange={(v) => { setOnlyActive(Boolean(v)); }} />
                  <label htmlFor="active" className="text-sm">Только активные</label>
                </div>
                <Button variant="outline" size="sm" onClick={() => loadVacancies()}>
                  <RefreshCw className="h-4 w-4 mr-2" /> Обновить
                </Button>
              </div>
              <ScrollArea className="w-full h-[420px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Название</TableHead>
                      <TableHead>Отдел</TableHead>
                      <TableHead>Уровень</TableHead>
                      <TableHead>Открыта</TableHead>
                      <TableHead>HC</TableHead>
                      <TableHead>Закрыто</TableHead>
                      <TableHead className="w-[140px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {vacs.items.map((v) => (
                      <TableRow key={v.id}>
                        <TableCell className="font-medium">{v.title}</TableCell>
                        <TableCell>{v.dept}</TableCell>
                        <TableCell>{v.level || "—"}</TableCell>
                        <TableCell title={v.openedAt}>{fmtDate(v.openedAt)}</TableCell>
                        <TableCell>{v.headcount}</TableCell>
                        <TableCell>{v.filled}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button size="sm" variant="outline">
                              <FilePlus2 className="h-4 w-4 mr-2" /> Добавить кандидата
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!vacs.items.length && (
                      <TableRow><TableCell colSpan={7} className="text-center text-sm text-muted-foreground">Нет вакансий</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

/**
 * Компоненты
 */
function KpiCard({
  icon, title, value, hint, trend,
}: { icon: React.ReactNode; title: string; value: React.ReactNode; hint?: string; trend?: number; }) {
  const t = trend ?? 0;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          {icon} {title}
        </CardTitle>
        {hint && <CardDescription>{hint}</CardDescription>}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}</div>
        {trend != null && (
          <div className="mt-1 flex items-center gap-1 text-sm">
            {t >= 0 ? <ArrowUpRight className="h-4 w-4" /> : <ArrowDownRight className="h-4 w-4" />}
            <span className={t >= 0 ? "text-green-600" : "text-red-600"}>
              {t >= 0 ? "+" : ""}{t}
            </span>
            <span className="text-muted-foreground">за 7 дней</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SortableTh({
  label, sort, setSort, keyName,
}: {
  label: string;
  sort: { key: string; dir: "asc" | "desc" } | null;
  setSort: (s: any) => void;
  keyName: string;
}) {
  const active = sort?.key === keyName;
  return (
    <TableHead aria-sort={active ? (sort?.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button
        type="button"
        onClick={() => {
          if (!active) setSort({ key: keyName, dir: "asc" });
          else setSort({ key: keyName, dir: sort?.dir === "asc" ? "desc" : "asc" });
        }}
        className="inline-flex items-center gap-1 hover:underline focus:outline-none focus:ring-2 focus:ring-ring rounded-sm"
        aria-label={`Сортировать по: ${label}`}
      >
        {label}
        {active ? (
          sort?.dir === "asc" ? <TrendingUp className="h-4 w-4" /> : <TrendingUp className="h-4 w-4 rotate-180" />
        ) : <Filter className="h-4 w-4 opacity-40" />}
      </button>
    </TableHead>
  );
}

function ImportJson({ onImport }: { onImport: (json: string) => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);

  return (
    <div className="relative">
      <Button variant="outline" size="sm" onClick={() => setOpen((o) => !o)}>
        <Upload className="h-4 w-4 mr-2" /> Импорт JSON
      </Button>
      {open && (
        <div className="absolute right-0 z-50 mt-2 w-[420px] rounded-md border bg-background p-3 shadow-md">
          <div className="text-sm font-medium mb-2">Вставьте массив объектов Candidate</div>
          <Textarea
            value={value}
            onChange={(e) => setValue(e.target.value)}
            rows={8}
            className="font-mono text-xs"
            placeholder='[{"id":"...","name":"...","email":"user@example.com", ...}]'
          />
          <div className="flex items-center justify-end gap-2 mt-2">
            <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>Отмена</Button>
            <Button
              size="sm"
              onClick={async () => {
                setBusy(true);
                try { await onImport(value); setValue(""); setOpen(false); }
                catch (e) { /* ошибка уже показана вверху */ }
                finally { setBusy(false); }
              }}
              disabled={busy || !value.trim()}
            >
              <Check className="h-4 w-4 mr-2" /> Импортировать
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Локальная логика этапов
 */
function nextStage(s: Stage): Stage {
  switch (s) {
    case "applied": return "screening";
    case "screening": return "interview";
    case "interview": return "offer";
    case "offer": return "hired";
    case "hired": return "hired";
    case "rejected": return "rejected";
  }
}
