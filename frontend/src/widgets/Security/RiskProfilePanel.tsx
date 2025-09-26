// frontend/src/widgets/Security/RiskProfilePanel.tsx
import * as React from "react";
import { useMemo, useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Card, CardHeader, CardContent, CardFooter, CardTitle, CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Tabs, TabsList, TabsTrigger, TabsContent,
} from "@/components/ui/tabs";
import {
  Tooltip as UiTooltip, TooltipContent, TooltipProvider, TooltipTrigger,
} from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";
import {
  Table, TableHeader, TableRow, TableHead, TableBody, TableCell,
} from "@/components/ui/table";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator,
  DropdownMenuCheckboxItem, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  ShieldAlert, TrendingUp, Download, Filter, RefreshCcw, Search,
  Info, AlertTriangle, BarChart3, ChevronDown, Sparkles,
} from "lucide-react";
import {
  ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  BarChart as RBarChart, Bar, XAxis, YAxis, Tooltip as RTooltip, PieChart, Pie, Cell,
} from "recharts";
import clsx from "clsx";

/**
 * Типы и интерфейсы
 */
export type RiskStatus = "open" | "mitigated" | "accepted" | "in-progress";

export interface RiskItem {
  id: string;
  title: string;
  category: string;
  score: number;        // 0..10
  likelihood: number;   // 0..10
  impact: number;       // 0..10
  status: RiskStatus;
  owner?: string;
  tags?: string[];
  updatedAt: string;    // ISO
  trend?: "up" | "down" | "flat";
}

export interface RiskProfilePanelProps {
  items: RiskItem[];
  loading?: boolean;
  onRefresh?: () => void;
  onSelect?: (id: string) => void;
  onExportCsv?: (csv: string) => void;
  allowExport?: boolean;
  className?: string;
  initialView?: "overview" | "table";
  heightPx?: number; // высота зоны графиков
}

/**
 * Настройки уровня серьезности по порогам.
 * Значения можно переопределить через пропсы/окружение в будущем.
 */
const SEVERITY_THRESHOLDS = {
  low: 0,        // включительно
  medium: 4,     // >=4
  high: 7,       // >=7
  critical: 9,   // >=9
} as const;

/**
 * Утилиты
 */
function toSeverity(score: number): "Low" | "Medium" | "High" | "Critical" {
  if (score >= SEVERITY_THRESHOLDS.critical) return "Critical";
  if (score >= SEVERITY_THRESHOLDS.high) return "High";
  if (score >= SEVERITY_THRESHOLDS.medium) return "Medium";
  return "Low";
}

function fmtPercent(v: number) {
  const n = Math.max(0, Math.min(100, v));
  return `${n.toFixed(0)}%`;
}

function safeDateStr(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function downloadAs(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.setAttribute("download", filename);
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function toCsv(rows: RiskItem[]): string {
  const header = [
    "id", "title", "category", "score", "likelihood", "impact", "severity",
    "status", "owner", "tags", "updatedAt", "trend",
  ];
  const body = rows.map((r) => ([
    r.id,
    r.title.replace(/"/g, '""'),
    r.category.replace(/"/g, '""'),
    r.score,
    r.likelihood,
    r.impact,
    toSeverity(r.score),
    r.status,
    r.owner ?? "",
    (r.tags ?? []).join("|"),
    r.updatedAt,
    r.trend ?? "",
  ].map((v) => (typeof v === "string" ? `"${v}"` : String(v))).join(",")));
  return [header.join(","), ...body].join("\n");
}

/**
 * Основной компонент
 */
export default function RiskProfilePanel({
  items,
  loading = false,
  onRefresh,
  onSelect,
  onExportCsv,
  allowExport = true,
  className,
  initialView = "overview",
  heightPx = 320,
}: RiskProfilePanelProps) {
  // Локальные состояния UI
  const [query, setQuery] = useState("");
  const [activeView, setActiveView] = useState<"overview" | "table">(initialView);
  const [includeClosed, setIncludeClosed] = useState(false);
  const [selectedCategories, setSelectedCategories] = useState<Record<string, boolean>>({});
  const [sortBy, setSortBy] = useState<keyof RiskItem | "severity">("score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  // Категории
  const categories = useMemo(() => {
    const set = new Set(items.map((i) => i.category));
    return Array.from(set).sort();
  }, [items]);

  useEffect(() => {
    // Инициализация фильтра категорий: все включены
    if (categories.length) {
      setSelectedCategories((prev) => {
        if (Object.keys(prev).length) return prev;
        const next: Record<string, boolean> = {};
        categories.forEach((c) => { next[c] = true; });
        return next;
      });
    }
  }, [categories]);

  // Фильтрация
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter((i) => {
      if (!includeClosed && (i.status === "accepted" || i.status === "mitigated")) return false;
      if (Object.keys(selectedCategories).length && !selectedCategories[i.category]) return false;
      if (!q) return true;
      const hay = [
        i.title, i.category, i.owner ?? "", ...(i.tags ?? []),
        toSeverity(i.score), i.status,
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [items, includeClosed, selectedCategories, query]);

  // Сортировка
  const sorted = useMemo(() => {
    const list = [...filtered];
    list.sort((a, b) => {
      let av: number | string;
      let bv: number | string;
      if (sortBy === "severity") {
        const order = { Critical: 3, High: 2, Medium: 1, Low: 0 } as const;
        av = order[toSeverity(a.score)];
        bv = order[toSeverity(b.score)];
      } else {
        av = (a as any)[sortBy];
        bv = (b as any)[sortBy];
      }
      if (typeof av === "number" && typeof bv === "number") {
        return sortDir === "asc" ? av - bv : bv - av;
      }
      const cmp = String(av).localeCompare(String(bv));
      return sortDir === "asc" ? cmp : -cmp;
    });
    return list;
  }, [filtered, sortBy, sortDir]);

  // Метрики для overview
  const metrics = useMemo(() => {
    const total = filtered.length;
    const buckets = { Low: 0, Medium: 0, High: 0, Critical: 0 } as Record<string, number>;
    let sum = 0;
    let openCount = 0;
    filtered.forEach((i) => {
      const sev = toSeverity(i.score);
      buckets[sev] += 1;
      sum += i.score;
      if (i.status === "open" || i.status === "in-progress") openCount += 1;
    });
    const avg = total ? sum / total : 0;
    const openPct = total ? (openCount / total) * 100 : 0;
    return { total, buckets, avg, openPct };
  }, [filtered]);

  // Данные для графиков
  const radarData = useMemo(() => {
    const byCat = new Map<string, { category: string; score: number; count: number }>();
    filtered.forEach((i) => {
      const r = byCat.get(i.category) ?? { category: i.category, score: 0, count: 0 };
      r.score += i.score;
      r.count += 1;
      byCat.set(i.category, r);
    });
    return Array.from(byCat.values()).map((r) => ({
      category: r.category,
      avgScore: r.count ? r.score / r.count : 0,
    }));
  }, [filtered]);

  const barData = useMemo(() => ([
    { name: "Critical", value: metrics.buckets["Critical"] },
    { name: "High", value: metrics.buckets["High"] },
    { name: "Medium", value: metrics.buckets["Medium"] },
    { name: "Low", value: metrics.buckets["Low"] },
  ]), [metrics]);

  // Экспорт
  const handleExport = () => {
    const csv = toCsv(sorted);
    if (onExportCsv) onExportCsv(csv);
    else downloadAs(`risk-profile_${new Date().toISOString().slice(0,19)}.csv`, csv);
  };

  const toggleAllCategories = (checked: boolean) => {
    const next: Record<string, boolean> = {};
    categories.forEach((c) => { next[c] = checked; });
    setSelectedCategories(next);
  };

  /**
   * UI
   */
  return (
    <Card className={clsx("w-full", className)}>
      <CardHeader className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-6 w-6" aria-hidden />
            <CardTitle className="leading-none">Risk Profile</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <TooltipProvider>
              <UiTooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="icon" onClick={onRefresh} disabled={loading} aria-label="Refresh">
                    <RefreshCcw className={clsx("h-4 w-4", loading && "animate-spin")} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Обновить данные</TooltipContent>
              </UiTooltip>
            </TooltipProvider>
            {allowExport && (
              <Button variant="outline" onClick={handleExport}>
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </Button>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline">
                  <Filter className="h-4 w-4 mr-2" />
                  Фильтры
                  <ChevronDown className="h-4 w-4 ml-2" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-64">
                <DropdownMenuLabel>Категории</DropdownMenuLabel>
                <DropdownMenuItem onClick={() => toggleAllCategories(true)}>
                  Включить все
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => toggleAllCategories(false)}>
                  Отключить все
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                {categories.map((c) => (
                  <DropdownMenuCheckboxItem
                    key={c}
                    checked={!!selectedCategories[c]}
                    onCheckedChange={(v: boolean | 'mixed' | undefined) =>
                      setSelectedCategories((prev) => ({ ...prev, [c]: !!v }))
                    }
                  >
                    {c}
                  </DropdownMenuCheckboxItem>
                ))}
                <DropdownMenuSeparator />
                <DropdownMenuLabel>Прочее</DropdownMenuLabel>
                <DropdownMenuCheckboxItem
                  checked={includeClosed}
                  onCheckedChange={(v: boolean | 'mixed' | undefined) => setIncludeClosed(!!v)}
                >
                  Показывать закрытые/принятые
                </DropdownMenuCheckboxItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        <CardDescription className="flex items-center gap-2 text-sm">
          <Info className="h-4 w-4" aria-hidden />
          Панель профиля рисков: обзор, фильтры, графики и таблица.
        </CardDescription>

        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="h-4 w-4 absolute left-2 top-2.5 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setQuery(e.target.value)}
              placeholder="Поиск по названию, тегам, владельцу…"
              className="pl-8"
              aria-label="Поиск"
            />
          </div>

          <div className="flex items-center gap-2">
            <Label htmlFor="includeClosed" className="text-sm">Включать закрытые</Label>
            <Switch id="includeClosed" checked={includeClosed} onCheckedChange={setIncludeClosed} />
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
  <Tabs value={activeView} onValueChange={(v: string) => setActiveView(v as any)}>
          <TabsList>
            <TabsTrigger value="overview">Обзор</TabsTrigger>
            <TabsTrigger value="table">Таблица</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            {/* KPI Cards */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <KpiCard
                title="Всего рисков"
                value={String(metrics.total)}
                icon={<ShieldAlert className="h-5 w-5" />}
                desc="Количество после фильтров"
              />
              <KpiCard
                title="Средний балл"
                value={metrics.avg.toFixed(2)}
                icon={<BarChart3 className="h-5 w-5" />}
                desc="Среднее по выборке"
              />
              <KpiCard
                title="Открытых/в работе"
                value={`${Math.round(metrics.openPct)}%`}
                icon={<TrendingUp className="h-5 w-5" />}
                desc={`${fmtPercent(metrics.openPct)}`}
              />
              <KpiCard
                title="Критические"
                value={String(metrics.buckets["Critical"])}
                icon={<AlertTriangle className="h-5 w-5" />}
                desc="По текущим порогам"
                badge="Critical"
              />
            </div>

            {/* Charts */}
            <div className="grid gap-4 lg:grid-cols-3">
              <Card className="col-span-2">
                <CardHeader className="py-3">
                  <CardTitle className="text-base">Средний риск по категориям</CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  <div style={{ height: heightPx }} aria-label="Radar chart by category">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart data={radarData}>
                        <PolarGrid />
                        <PolarAngleAxis dataKey="category" />
                        <PolarRadiusAxis angle={30} domain={[0, 10]} />
                        <Radar dataKey="avgScore" strokeOpacity={0.8} fillOpacity={0.2} />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="py-3">
                  <CardTitle className="text-base">Распределение по серьезности</CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  <div style={{ height: heightPx }} aria-label="Bar chart by severity">
                    <ResponsiveContainer width="100%" height="100%">
                      <RBarChart data={barData}>
                        <XAxis dataKey="name" />
                        <YAxis allowDecimals={false} />
                        <RTooltip />
                        <Bar dataKey="value" />
                      </RBarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Top Risks */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="h-4 w-4" />
                  <h3 className="text-sm font-semibold">Приоритетные риски</h3>
                </div>
                <div className="flex items-center gap-2">
                  <Label htmlFor="sortBy" className="text-xs">Сортировка</Label>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button id="sortBy" size="sm" variant="outline">
                        {sortLabel(sortBy)} / {sortDir === "asc" ? "ASC" : "DESC"}
                        <ChevronDown className="h-4 w-4 ml-2" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      {["score","likelihood","impact","severity","updatedAt","category","title"].map((k) => (
                        <DropdownMenuItem
                          key={k}
                          onClick={() => setSortBy(k as any)}
                          className={clsx(sortBy === k && "font-semibold")}
                        >
                          {sortLabel(k as any)}
                        </DropdownMenuItem>
                      ))}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => setSortDir((d) => d === "asc" ? "desc" : "asc")}>
                        Переключить направление
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {sorted.slice(0, 6).map((r) => (
                  <motion.div
                    key={r.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25 }}
                  >
                    <RiskTile item={r} onSelect={onSelect} />
                  </motion.div>
                ))}
                {sorted.length === 0 && (
                  <div className="text-sm text-muted-foreground">Нет элементов по текущим фильтрам.</div>
                )}
              </div>
            </div>
          </TabsContent>

          <TabsContent value="table">
            <div className="rounded-xl border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[32px]" aria-label="Severity" />
                    <TableHead>Название</TableHead>
                    <TableHead>Категория</TableHead>
                    <TableHead className="text-right cursor-pointer" onClick={() => toggleSort("score", setSortBy, setSortDir, sortBy, sortDir)}>Score</TableHead>
                    <TableHead className="text-right cursor-pointer" onClick={() => toggleSort("likelihood", setSortBy, setSortDir, sortBy, sortDir)}>Likelihood</TableHead>
                    <TableHead className="text-right cursor-pointer" onClick={() => toggleSort("impact", setSortBy, setSortDir, sortBy, sortDir)}>Impact</TableHead>
                    <TableHead>Статус</TableHead>
                    <TableHead>Владелец</TableHead>
                    <TableHead>Теги</TableHead>
                    <TableHead className="text-right cursor-pointer" onClick={() => toggleSort("updatedAt", setSortBy, setSortDir, sortBy, sortDir)}>Обновлено</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sorted.map((r) => (
                    <TableRow key={r.id} className="hover:bg-muted/40">
                      <TableCell>
                        <SeverityBadge score={r.score} />
                      </TableCell>
                      <TableCell className="font-medium">
                        <button
                          onClick={() => onSelect?.(r.id)}
                          className="hover:underline focus:underline focus:outline-none"
                          aria-label={`Открыть риск ${r.title}`}
                        >
                          {r.title}
                        </button>
                        <div className="mt-2">
                          <Progress value={(r.score / 10) * 100} aria-label="Индикатор балла" />
                        </div>
                      </TableCell>
                      <TableCell>{r.category}</TableCell>
                      <TableCell className="text-right">{r.score.toFixed(2)}</TableCell>
                      <TableCell className="text-right">{r.likelihood.toFixed(2)}</TableCell>
                      <TableCell className="text-right">{r.impact.toFixed(2)}</TableCell>
                      <TableCell>
                        <StatusBadge status={r.status} />
                      </TableCell>
                      <TableCell>{r.owner ?? "—"}</TableCell>
                      <TableCell className="max-w-[240px] truncate" title={(r.tags ?? []).join(", ")}>
                        {(r.tags ?? []).slice(0, 4).map((t) => (
                          <Badge key={t} variant="secondary" className="mr-1">{t}</Badge>
                        ))}
                      </TableCell>
                      <TableCell className="text-right">{safeDateStr(r.updatedAt)}</TableCell>
                    </TableRow>
                  ))}
                  {sorted.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={10} className="text-center text-sm text-muted-foreground py-6">
                        Нет данных для отображения.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>

      <CardFooter className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Info className="h-3.5 w-3.5" />
          Пороговые уровни серьезности настраиваемы в коде.
        </div>
      </CardFooter>
    </Card>
  );
}

/**
 * Вспомогательные подкомпоненты
 */
function KpiCard({
  title, value, desc, icon, badge,
}: { title: string; value: string; desc?: string; icon?: React.ReactNode; badge?: "Critical" | "High" | "Medium" | "Low"; }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
          {icon}
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="flex items-baseline gap-2">
          <span className="text-2xl font-semibold">{value}</span>
          {badge && <SeverityPill level={badge} />}
        </motion.div>
        {desc && <p className="text-xs text-muted-foreground mt-1">{desc}</p>}
      </CardContent>
    </Card>
  );
}

function SeverityPill({ level }: { level: "Critical" | "High" | "Medium" | "Low" }) {
  const cls = {
    Critical: "bg-destructive text-destructive-foreground",
    High: "bg-orange-500 text-white",
    Medium: "bg-yellow-500 text-black",
    Low: "bg-emerald-500 text-white",
  }[level];
  return <span className={clsx("px-2 py-0.5 rounded-full text-[10px] font-semibold", cls)}>{level}</span>;
}

function SeverityBadge({ score }: { score: number }) {
  const sev = toSeverity(score);
  return <SeverityPill level={sev} />;
}

function StatusBadge({ status }: { status: RiskStatus }) {
  const map: Record<RiskStatus, { label: string; cls: string }> = {
    open: { label: 'Open', cls: 'bg-yellow-100 text-yellow-800' },
    mitigated: { label: 'Mitigated', cls: 'bg-green-100 text-green-800' },
    accepted: { label: 'Accepted', cls: 'bg-slate-100 text-slate-800' },
    'in-progress': { label: 'In Progress', cls: 'bg-blue-100 text-blue-800' },
  };
  const info = map[status] ?? { label: String(status), cls: 'bg-slate-100 text-slate-800' };

  return <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', info.cls)}>{info.label}</span>;
}

function sortLabel(k: keyof RiskItem | string) {
  const map: Record<string, string> = {
    score: 'Score', likelihood: 'Likelihood', impact: 'Impact', severity: 'Severity', updatedAt: 'Updated', category: 'Category', title: 'Title',
  };
  return map[String(k)] ?? String(k);
}

function toggleSort(
  key: keyof RiskItem | 'severity',
  setSortBy: React.Dispatch<React.SetStateAction<any>>,
  setSortDir: React.Dispatch<React.SetStateAction<'asc'|'desc'>>,
  currentBy: any,
  currentDir: 'asc'|'desc',
) {
  if (currentBy === key) {
    setSortDir(currentDir === 'asc' ? 'desc' : 'asc');
  } else {
    setSortBy(key as any);
    setSortDir('desc');
  }
}

function RiskTile({ item, onSelect }: { item: RiskItem; onSelect?: (id: string) => void }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold">{item.title}</div>
            <div className="text-xs text-muted-foreground">{item.category}</div>
          </div>
          <div className="text-right">
            <div className="text-lg font-semibold">{item.score.toFixed(2)}</div>
            <div className="text-xs text-muted-foreground">{toSeverity(item.score)}</div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="text-sm text-muted-foreground mb-2">{item.owner ?? '—'}</div>
        <div className="flex items-center gap-2">
          {(item.tags ?? []).slice(0, 3).map((t) => <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>)}
        </div>
      </CardContent>
      <CardFooter>
        <Button variant="ghost" size="sm" onClick={() => onSelect?.(item.id)}>Open</Button>
      </CardFooter>
    </Card>
  );
}
