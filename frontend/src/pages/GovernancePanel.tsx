// frontend/src/pages/GovernancePanel.tsx
import * as React from "react";
import { useEffect, useMemo, useState, useCallback } from "react";
import { z } from "zod";
import { motion } from "framer-motion";
import {
  Card, CardHeader, CardTitle, CardDescription, CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import {
  RefreshCw, Plus, Download, Search, Info, BarChart3, Users2, Gavel,
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, TrendingUp, Filter, Check, X, TimerReset, Play, ShieldCheck, AlertOctagon
} from "lucide-react";
import {
  LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, BarChart, Bar,
} from "recharts";

/**
 * Типы и схемы
 */
const GovStateSchema = z.enum([
  "Pending", "Active", "Succeeded", "Defeated", "Queued", "Executed", "Canceled",
]);
export type GovState = z.infer<typeof GovStateSchema>;

const ProposalSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string().default(""),
  proposer: z.string(),
  state: GovStateSchema,
  startTime: z.string().datetime(),
  endTime: z.string().datetime(),
  snapshot: z.string().optional().default(""),
  quorum: z.number().min(0),          // требуемый кворум голосов
  threshold: z.number().min(0),       // порог прохождения (например, % или вес)
  forVotes: z.number().min(0).default(0),
  againstVotes: z.number().min(0).default(0),
  abstainVotes: z.number().min(0).default(0),
  tags: z.array(z.string()).optional().default([]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type Proposal = z.infer<typeof ProposalSchema>;

const ProposalListSchema = z.object({
  items: z.array(ProposalSchema),
  total: z.number().int().min(0),
  page: z.number().int().min(1),
  pageSize: z.number().int().min(1),
});
type ProposalList = z.infer<typeof ProposalListSchema>;

const MyProfileSchema = z.object({
  address: z.string(),
  votingPower: z.number().min(0).default(0),
  delegatedTo: z.string().optional().default(""),
  role: z.enum(["admin", "member", "guest"]).default("member"),
});
type MyProfile = z.infer<typeof MyProfileSchema>;

const VoteSchema = z.object({
  proposalId: z.string(),
  voter: z.string(),
  choice: z.enum(["for", "against", "abstain"]),
  weight: z.number().min(0),
  txHash: z.string().optional(),
  createdAt: z.string().datetime(),
});
type Vote = z.infer<typeof VoteSchema>;

const SeriesPointSchema = z.object({
  t: z.string().datetime(),
  participation: z.number().min(0),
  passed: z.number().min(0),
  created: z.number().min(0),
});
type SeriesPoint = z.infer<typeof SeriesPointSchema>;

/**
 * API обёртка
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
 * Вспомогательные
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
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function fmtDate(iso: string) {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

const stateBadge: Record<GovState, React.ComponentProps<typeof Badge>["variant"]> = {
  Pending: "secondary",
  Active: "default",
  Succeeded: "success" as any,
  Defeated: "destructive",
  Queued: "outline",
  Executed: "secondary",
  Canceled: "destructive",
};

function percent(n: number, d: number) {
  return d <= 0 ? 0 : Math.max(0, Math.min(100, (n / d) * 100));
}

/**
 * Главная страница Governance
 *
 * Предполагаемые бэкенд маршруты:
 * GET  /api/gov/proposals?page=&pageSize=&q=&state=
 * POST /api/gov/proposals   body:{title,description,tags?,startTime?,endTime?}
 * POST /api/gov/proposals/:id/vote  body:{choice:"for"|"against"|"abstain", weight?}
 * POST /api/gov/proposals/:id/queue
 * POST /api/gov/proposals/:id/execute
 * POST /api/gov/proposals/:id/cancel
 * GET  /api/gov/series?window=90d
 * GET  /api/gov/votes?proposalId=
 * GET  /api/gov/profile
 * POST /api/gov/delegate body:{to}
 * GET  /api/gov/stream (SSE) — события: { type:"proposal|vote|state", payload:{...} }
 */
export default function GovernancePanel() {
  const [tab, setTab] = useState<"proposals" | "create" | "delegation" | "analytics">("proposals");

  // Фильтры/сортировка/пагинация
  const [q, setQ] = useState("");
  const [stateFilter, setStateFilter] = useState<GovState | "any">("any");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [sort, setSort] = useState<{ key: "endTime" | "startTime" | "updatedAt" | "title"; dir: "asc" | "desc" } | null>({ key: "endTime", dir: "desc" });
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Данные
  const [list, setList] = useState<ProposalList>({ items: [], total: 0, page: 1, pageSize: 25 });
  const [selected, setSelected] = useState<Proposal | null>(null);
  const [series, setSeries] = useState<SeriesPoint[]>([]);
  const [votes, setVotes] = useState<Vote[]>([]);
  const [me, setMe] = useState<MyProfile | null>(null);

  // Служебные
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadProfile = useCallback(async () => {
    try {
      const raw = await api<unknown>("/api/gov/profile");
      setMe(MyProfileSchema.parse(raw));
    } catch (e: any) {
      setError(e.message || "Ошибка профиля");
    }
  }, []);

  const loadProposals = useCallback(async () => {
    try {
      setError(null);
      const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
      if (q.trim()) params.set("q", q.trim());
      if (stateFilter !== "any") params.set("state", stateFilter);
      const raw = await api<unknown>(`/api/gov/proposals?${params.toString()}`);
      const parsed = ProposalListSchema.parse(raw);
      setList(parsed);
      if (!selected && parsed.items.length) setSelected(parsed.items[0]);
    } catch (e: any) {
      setError(e.message || "Ошибка загрузки предложений");
    }
  }, [q, stateFilter, page, pageSize, selected]);

  const loadSeries = useCallback(async () => {
    try {
      const raw = await api<unknown>("/api/gov/series?window=90d");
      const arr = (Array.isArray(raw) ? raw : []) as unknown[];
      setSeries(arr.map((x) => SeriesPointSchema.parse(x)));
    } catch { /* необязательно критично */ }
  }, []);

  const loadVotes = useCallback(async (proposalId: string) => {
    try {
      const raw = await api<unknown>(`/api/gov/votes?proposalId=${encodeURIComponent(proposalId)}`);
      const arr = Array.isArray(raw) ? raw : [];
      setVotes(arr.map((x) => VoteSchema.parse(x)));
    } catch { /* необязательно критично */ }
  }, []);

  useEffect(() => {
    loadProfile();
    loadProposals();
    loadSeries();
  }, [loadProfile, loadProposals, loadSeries]);

  // SSE-поток
  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource("/api/gov/stream");
      es.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data?.type === "proposal" || data?.type === "vote" || data?.type === "state") {
            loadProposals();
            if (selected) loadVotes(selected.id);
          }
        } catch { /* ignore */ }
      };
    } catch { /* нет SSE — ок */ }
    return () => { es?.close(); };
  }, [loadProposals, selected, loadVotes]);

  // Автообновление
  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => {
      loadProposals();
      if (selected) loadVotes(selected.id);
      loadSeries();
    }, 10000);
    return () => clearInterval(id);
  }, [autoRefresh, loadProposals, selected, loadVotes, loadSeries]);

  // Сортировка клиентская для UX
  const sorted = useMemo(() => {
    const arr = [...list.items];
    if (!sort) return arr;
    const { key, dir } = sort;
    const m = dir === "asc" ? 1 : -1;
    arr.sort((a, b) => {
      let A: number | string = "";
      let B: number | string = "";
      if (key === "endTime" || key === "startTime" || key === "updatedAt") {
        A = new Date((a as any)[key]).getTime();
        B = new Date((b as any)[key]).getTime();
      } else {
        A = (a as any)[key] ?? "";
        B = (b as any)[key] ?? "";
      }
      if (A < B) return -1 * m;
      if (A > B) return 1 * m;
      return 0;
    });
    return arr;
  }, [list.items, sort]);

  const totalPages = Math.max(1, Math.ceil(list.total / list.pageSize));
  useEffect(() => { if (page > totalPages) setPage(totalPages); }, [page, totalPages]);

  // Метрики выбранного
  const totalVotes = useMemo(() => {
    if (!selected) return 0;
    return (selected.forVotes ?? 0) + (selected.againstVotes ?? 0) + (selected.abstainVotes ?? 0);
  }, [selected]);
  const quorumPct = useMemo(() => percent(totalVotes, selected?.quorum ?? 0), [totalVotes, selected]);
  const passPct = useMemo(() => {
    if (!selected) return 0;
    const denom = Math.max(1, (selected.forVotes + selected.againstVotes));
    return percent(selected.forVotes, denom);
  }, [selected]);

  // Действия
  const vote = async (choice: "for" | "against" | "abstain", weight?: number) => {
    if (!selected) return;
    setBusy(true);
    try {
      await api(`/api/gov/proposals/${selected.id}/vote`, {
        method: "POST",
        body: JSON.stringify({ choice, weight }),
      });
      await loadProposals();
      await loadVotes(selected.id);
    } catch (e: any) {
      setError(e.message || "Ошибка голосования");
    } finally {
      setBusy(false);
    }
  };

  const queue = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      await api(`/api/gov/proposals/${selected.id}/queue`, { method: "POST" });
      await loadProposals();
    } catch (e: any) {
      setError(e.message || "Ошибка постановки в очередь");
    } finally {
      setBusy(false);
    }
  };

  const execute = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      await api(`/api/gov/proposals/${selected.id}/execute`, { method: "POST" });
      await loadProposals();
    } catch (e: any) {
      setError(e.message || "Ошибка исполнения");
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      await api(`/api/gov/proposals/${selected.id}/cancel`, { method: "POST" });
      await loadProposals();
    } catch (e: any) {
      setError(e.message || "Ошибка отмены");
    } finally {
      setBusy(false);
    }
  };

  // Создание предложения
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newTags, setNewTags] = useState("");
  const [startIso, setStartIso] = useState("");
  const [endIso, setEndIso] = useState("");

  const createProposal = async () => {
    setBusy(true);
    try {
      await api("/api/gov/proposals", {
        method: "POST",
        body: JSON.stringify({
          title: newTitle.trim(),
          description: newDesc,
          tags: newTags.split(",").map((x) => x.trim()).filter(Boolean),
          startTime: startIso || undefined,
          endTime: endIso || undefined,
        }),
      });
      setNewTitle(""); setNewDesc(""); setNewTags(""); setStartIso(""); setEndIso("");
      setTab("proposals");
      setPage(1);
      await loadProposals();
    } catch (e: any) {
      setError(e.message || "Ошибка создания предложения");
    } finally {
      setBusy(false);
    }
  };

  // Делегирование
  const [delegateTo, setDelegateTo] = useState("");
  const delegate = async () => {
    setBusy(true);
    try {
      await api("/api/gov/delegate", { method: "POST", body: JSON.stringify({ to: delegateTo.trim() }) });
      await loadProfile();
    } catch (e: any) {
      setError(e.message || "Ошибка делегирования");
    } finally {
      setBusy(false);
    }
  };

  // Экспорт
  const exportCSV = () => {
    csvDownload(
      `proposals_${new Date().toISOString().replace(/[:.]/g, "-")}.csv`,
      sorted.map((p) => ({
        id: p.id, title: p.title, proposer: p.proposer, state: p.state,
        startTime: p.startTime, endTime: p.endTime, quorum: p.quorum, threshold: p.threshold,
        forVotes: p.forVotes, againstVotes: p.againstVotes, abstainVotes: p.abstainVotes,
        tags: (p.tags ?? []).join("|"), snapshot: p.snapshot, updatedAt: p.updatedAt,
      }))
    );
  };

  return (
    <div className="p-4 md:p-6 space-y-6">
      <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Governance Panel</h1>
            <p className="text-sm text-muted-foreground">
              Управление предложениями, голосованием, делегированием и аналитикой протокола.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => { loadProposals(); loadSeries(); if (selected) loadVotes(selected.id); }}>
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

      <Tabs value={tab} onValueChange={(v) => setTab(v as any)}>
        <TabsList>
          <TabsTrigger value="proposals"><Gavel className="h-4 w-4 mr-1" />Предложения</TabsTrigger>
          <TabsTrigger value="create"><Plus className="h-4 w-4 mr-1" />Создать</TabsTrigger>
          <TabsTrigger value="delegation"><Users2 className="h-4 w-4 mr-1" />Делегирование</TabsTrigger>
          <TabsTrigger value="analytics"><BarChart3 className="h-4 w-4 mr-1" />Аналитика</TabsTrigger>
        </TabsList>

        {/* PROPOSALS */}
        <TabsContent value="proposals" className="space-y-6 pt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Фильтры</CardTitle>
              <CardDescription>Поиск, состояние, экспорт и размер страницы</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                <div className="md:col-span-5">
                  <div className="relative">
                    <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Поиск по заголовку, автору, тэгам…" aria-label="Поиск" />
                    <Search className="h-4 w-4 absolute right-2 top-2.5" />
                  </div>
                </div>
                <div className="md:col-span-3">
                  <Select value={stateFilter} onValueChange={(v) => { setStateFilter(v as any); setPage(1); }}>
                    <SelectTrigger aria-label="Состояние">
                      <SelectValue placeholder="Любое" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="any">Любое</SelectItem>
                      {GovStateSchema.options.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="md:col-span-4 flex items-center justify-end gap-2">
                  <Button variant="outline" size="sm" onClick={exportCSV}>
                    <Download className="h-4 w-4 mr-2" /> Экспорт CSV
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
                <CardTitle className="text-lg">Предложения</CardTitle>
                <CardDescription>Список и быстрые действия</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="w-full">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <SortableTh label="Заголовок" sort={sort} setSort={setSort} keyName="title" />
                        <TableHead>Автор</TableHead>
                        <SortableTh label="Начало" sort={sort} setSort={setSort} keyName="startTime" />
                        <SortableTh label="Окончание" sort={sort} setSort={setSort} keyName="endTime" />
                        <TableHead>Состояние</TableHead>
                        <TableHead className="w-[220px]" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sorted.map((p) => (
                        <TableRow
                          key={p.id}
                          className={selected?.id === p.id ? "bg-muted/40" : ""}
                          onClick={() => { setSelected(p); loadVotes(p.id); }}
                        >
                          <TableCell className="font-medium truncate max-w-[280px]" title={p.title}>{p.title}</TableCell>
                          <TableCell className="truncate max-w-[160px]" title={p.proposer}>{p.proposer}</TableCell>
                          <TableCell title={p.startTime}>{fmtDate(p.startTime)}</TableCell>
                          <TableCell title={p.endTime}>{fmtDate(p.endTime)}</TableCell>
                          <TableCell>
                            <Badge variant={stateBadge[p.state] ?? "secondary"}>{p.state}</Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-2">
                              <Button size="sm" variant="outline" disabled={p.state !== "Active" || busy} onClick={(e) => { e.stopPropagation(); setSelected(p); vote("for"); }}>
                                <Check className="h-4 w-4 mr-2" /> За
                              </Button>
                              <Button size="sm" variant="outline" disabled={p.state !== "Active" || busy} onClick={(e) => { e.stopPropagation(); setSelected(p); vote("against"); }}>
                                <X className="h-4 w-4 mr-2" /> Против
                              </Button>
                              <Button size="sm" variant="outline" disabled={p.state !== "Active" || busy} onClick={(e) => { e.stopPropagation(); setSelected(p); vote("abstain"); }}>
                                <TimerReset className="h-4 w-4 mr-2" /> Воздерж.
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                      {!sorted.length && (
                        <TableRow>
                          <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">Нет предложений</TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </ScrollArea>

                <div className="flex items-center justify-between pt-2">
                  <div className="text-xs text-muted-foreground">
                    Найдено: {list.total}. Стр. {list.page} из {totalPages}.
                  </div>
                  <div className="flex items-center gap-1">
                    <Button variant="outline" size="icon" disabled={page === 1} onClick={() => setPage(1)} aria-label="В начало"><ChevronsLeft className="h-4 w-4" /></Button>
                    <Button variant="outline" size="icon" disabled={page === 1} onClick={() => setPage((p) => Math.max(1, p - 1))} aria-label="Назад"><ChevronLeft className="h-4 w-4" /></Button>
                    <span className="px-2 text-sm">Стр. {page}</span>
                    <Button variant="outline" size="icon" disabled={page === totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))} aria-label="Вперёд"><ChevronRight className="h-4 w-4" /></Button>
                    <Button variant="outline" size="icon" disabled={page === totalPages} onClick={() => setPage(totalPages)} aria-label="В конец"><ChevronsRight className="h-4 w-4" /></Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="lg:col-span-4">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg">Детали предложения</CardTitle>
                <CardDescription>Кворум, порог и результаты</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {!selected ? (
                  <div className="text-sm text-muted-foreground">Выберите предложение слева.</div>
                ) : (
                  <>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-base font-medium">{selected.title}</div>
                        <div className="text-xs text-muted-foreground">
                          Автор: {selected.proposer} • Состояние: <span className="font-medium">{selected.state}</span>
                        </div>
                      </div>
                      <Badge variant={stateBadge[selected.state] ?? "secondary"}>{selected.state}</Badge>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div className="rounded-md border p-3">
                        <div className="text-xs text-muted-foreground">Кворум</div>
                        <div className="text-xl">{selected.quorum.toLocaleString()}</div>
                        <div className="text-xs">Достигнуто: {percent(totalVotes, selected.quorum).toFixed(1)}%</div>
                      </div>
                      <div className="rounded-md border p-3">
                        <div className="text-xs text-muted-foreground">Порог прохождения</div>
                        <div className="text-xl">{selected.threshold.toLocaleString()}</div>
                        <div className="text-xs">За: {passPct.toFixed(1)}%</div>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-sm">
                      <div className="rounded-md border p-3">
                        <div className="text-xs text-muted-foreground">За</div>
                        <div className="text-xl">{selected.forVotes.toLocaleString()}</div>
                      </div>
                      <div className="rounded-md border p-3">
                        <div className="text-xs text-muted-foreground">Против</div>
                        <div className="text-xl">{selected.againstVotes.toLocaleString()}</div>
                      </div>
                      <div className="rounded-md border p-3">
                        <div className="text-xs text-muted-foreground">Воздерж.</div>
                        <div className="text-xl">{selected.abstainVotes.toLocaleString()}</div>
                      </div>
                    </div>

                    <Separator />

                    <div className="space-y-2">
                      <div className="text-xs text-muted-foreground">Голосования (последние)</div>
                      <ScrollArea className="h-40 rounded-md border">
                        <div className="p-2 space-y-1 text-xs font-mono">
                          {votes.slice(-200).map((v, i) => (
                            <div key={`${v.proposalId}-${i}`} className="flex items-center gap-2">
                              <Badge variant={v.choice === "for" ? "default" : v.choice === "against" ? "destructive" : "outline"}>
                                {v.choice}
                              </Badge>
                              <span className="truncate">{v.voter}</span>
                              <span className="text-muted-foreground">•</span>
                              <span>{v.weight}</span>
                              <span className="text-muted-foreground">• {new Date(v.createdAt).toLocaleString()}</span>
                            </div>
                          ))}
                          {!votes.length && <div className="text-muted-foreground">Нет данных</div>}
                        </div>
                      </ScrollArea>
                    </div>

                    <div className="flex items-center justify-end gap-2">
                      <Button size="sm" disabled={selected.state !== "Active" || busy} onClick={() => vote("for")}>
                        <Check className="h-4 w-4 mr-2" /> Голосовать "За"
                      </Button>
                      <Button size="sm" variant="outline" disabled={selected.state !== "Active" || busy} onClick={() => vote("against")}>
                        <X className="h-4 w-4 mr-2" /> "Против"
                      </Button>
                      <Button size="sm" variant="outline" disabled={selected.state !== "Active" || busy} onClick={() => vote("abstain")}>
                        <TimerReset className="h-4 w-4 mr-2" /> Воздержаться
                      </Button>
                    </div>

                    <div className="flex items-center justify-end gap-2">
                      <Button size="sm" variant="outline" disabled={me?.role !== "admin" || selected.state !== "Succeeded" || busy} onClick={queue}>
                        <Play className="h-4 w-4 mr-2" /> Queue
                      </Button>
                      <Button size="sm" variant="outline" disabled={me?.role !== "admin" || selected.state !== "Queued" || busy} onClick={execute}>
                        <ShieldCheck className="h-4 w-4 mr-2" /> Execute
                      </Button>
                      <Button size="sm" variant="destructive" disabled={me?.role !== "admin" || busy} onClick={cancel}>
                        <AlertOctagon className="h-4 w-4 mr-2" /> Cancel
                      </Button>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* CREATE */}
        <TabsContent value="create" className="space-y-6 pt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Новое предложение</CardTitle>
              <CardDescription>Опишите изменение, сроки и метки</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                <div className="md:col-span-8">
                  <Input placeholder="Заголовок" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} />
                </div>
                <div className="md:col-span-4">
                  <Input placeholder="Теги через запятую" value={newTags} onChange={(e) => setNewTags(e.target.value)} />
                </div>
                <div className="md:col-span-6">
                  <label className="text-xs text-muted-foreground">Начало голосования</label>
                  <Input type="datetime-local" value={startIso} onChange={(e) => setStartIso(e.target.value)} />
                </div>
                <div className="md:col-span-6">
                  <label className="text-xs text-muted-foreground">Окончание голосования</label>
                  <Input type="datetime-local" value={endIso} onChange={(e) => setEndIso(e.target.value)} />
                </div>
                <div className="md:col-span-12">
                  <Textarea placeholder="Описание/рационал" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} rows={8} className="text-sm" />
                </div>
              </div>
              <div className="flex items-center justify-end gap-2">
                <Button size="sm" onClick={createProposal} disabled={busy || !newTitle.trim()}>
                  <Plus className="h-4 w-4 mr-2" /> Создать
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* DELEGATION */}
        <TabsContent value="delegation" className="space-y-6 pt-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg">Делегирование</CardTitle>
              <CardDescription>Передача голосующей силы другому адресу</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                <div className="md:col-span-6">
                  <Input placeholder="Адрес делегата" value={delegateTo} onChange={(e) => setDelegateTo(e.target.value)} />
                </div>
                <div className="md:col-span-6">
                  <Button size="sm" onClick={delegate} disabled={busy || !delegateTo.trim()}>Делегировать</Button>
                </div>
              </div>
              <Separator />
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="rounded-md border p-3">
                  <div className="text-xs text-muted-foreground">Ваш адрес</div>
                  <div className="text-sm">{me?.address ?? "—"}</div>
                </div>
                <div className="rounded-md border p-3">
                  <div className="text-xs text-muted-foreground">Voting Power</div>
                  <div className="text-xl">{me?.votingPower ?? 0}</div>
                </div>
                <div className="rounded-md border p-3">
                  <div className="text-xs text-muted-foreground">Делегировано на</div>
                  <div className="text-sm">{me?.delegatedTo || "—"}</div>
                </div>
                <div className="rounded-md border p-3">
                  <div className="text-xs text-muted-foreground">Роль</div>
                  <div className="text-sm">{me?.role ?? "—"}</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ANALYTICS */}
        <TabsContent value="analytics" className="space-y-6 pt-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="lg:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">30–90-дневная динамика</CardTitle>
                <CardDescription>Участие, созданные и принятые предложения</CardDescription>
              </CardHeader>
              <CardContent className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={series}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="t" tickFormatter={(t) => new Date(t).toLocaleDateString()} minTickGap={24} />
                    <YAxis />
                    <Tooltip labelFormatter={(t) => new Date(String(t)).toLocaleString()} />
                    <Legend />
                    <Line type="monotone" dataKey="participation" name="Участие" dot={false} />
                    <Line type="monotone" dataKey="created" name="Создано" dot={false} />
                    <Line type="monotone" dataKey="passed" name="Принято" dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Срез по состояниям</CardTitle>
                <CardDescription>Текущие предложения по статусам</CardDescription>
              </CardHeader>
              <CardContent className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={[
                      { state: "Pending", v: list.items.filter(x => x.state === "Pending").length },
                      { state: "Active", v: list.items.filter(x => x.state === "Active").length },
                      { state: "Succeeded", v: list.items.filter(x => x.state === "Succeeded").length },
                      { state: "Defeated", v: list.items.filter(x => x.state === "Defeated").length },
                      { state: "Queued", v: list.items.filter(x => x.state === "Queued").length },
                      { state: "Executed", v: list.items.filter(x => x.state === "Executed").length },
                      { state: "Canceled", v: list.items.filter(x => x.state === "Canceled").length },
                    ]}
                    layout="vertical"
                    margin={{ left: 24 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis type="number" />
                    <YAxis dataKey="state" type="category" />
                    <Tooltip />
                    <Bar dataKey="v" name="Кол-во" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

/**
 * Хелперы UI
 */
function SortableTh({
  label, sort, setSort, keyName,
}: {
  label: string;
  sort: { key: string; dir: "asc" | "desc" } | null;
  setSort: (s: any) => void;
  keyName: "endTime" | "startTime" | "updatedAt" | "title";
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
