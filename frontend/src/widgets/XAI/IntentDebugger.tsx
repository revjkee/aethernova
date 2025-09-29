// frontend/src/widgets/XAI/IntentDebugger.tsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
  SheetTrigger,
} from "@/components/ui/sheet";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Download,
  Upload,
  Search,
  Filter,
  Wand2,
  ArrowUpRight,
  Copy,
  Trash2,
  Info,
  Timer,
  Activity,
  Pause,
  Play,
  ListFilter,
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

// ----------------------------- Types -----------------------------------------

export type IntentRecord = {
  id: string;
  sessionId?: string;
  timestamp: string; // ISO
  intent: string;
  confidence: number; // 0..1
  agent?: string;
  channel?: string;
  userText?: string;
  context?: Record<string, unknown>;
  features?: string[];
  rationale?: string[]; // chain-of-thought summary/explainable steps (non-sensitive)
  trace?: Array<{
    step: string;
    detail?: string;
    latencyMs?: number;
  }>;
  tags?: string[];
};

export type IntentDebuggerProps = {
  data?: IntentRecord[];
  loadData?: () => Promise<IntentRecord[]>; // optional loader for live polling
  pollMs?: number; // default 0 (disabled)
  pageSize?: number; // default 20
  className?: string;
  // Optional hooks
  onError?: (err: unknown) => void;
};

type SortKey = "timestamp" | "confidence" | "intent" | "agent";

// ----------------------------- Utils -----------------------------------------

const clamp01 = (v: number) => Math.min(1, Math.max(0, v));

const formatDateTime = (iso: string) => {
  try {
    const d = new Date(iso);
    // Localized ISO-ish without seconds for compactness
    const dd = d.toLocaleDateString();
    const tt = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return `${dd} ${tt}`;
  } catch {
    return iso;
  }
};

const downloadBlob = (content: string, filename: string, type = "application/json") => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

const safeJson = (v: unknown) => {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return "/* Unable to stringify */";
  }
};

// ----------------------------- Component -------------------------------------

const DEFAULT_PAGE_SIZE = 20;

const emptyArray: IntentRecord[] = [];

const IntentDebugger: React.FC<IntentDebuggerProps> = ({
  data,
  loadData,
  pollMs = 0,
  pageSize = DEFAULT_PAGE_SIZE,
  className,
  onError,
}) => {
  // Local state
  const [rows, setRows] = useState<IntentRecord[]>(() => data ?? emptyArray);
  const [query, setQuery] = useState("");
  const [agent, setAgent] = useState<string>("all");
  const [channel, setChannel] = useState<string>("all");
  const [minConf, setMinConf] = useState<number>(0);
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [selected, setSelected] = useState<IntentRecord | null>(null);
  const [live, setLive] = useState<boolean>(pollMs > 0);
  const [page, setPage] = useState<number>(1);
  const [importOpen, setImportOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<number | null>(null);

  // Bootstrap from props.data
  useEffect(() => {
    if (data && data.length) setRows(data);
  }, [data]);

  // Live polling
  const doLoad = useCallback(async () => {
    if (!loadData) return;
    try {
      const next = await loadData();
      if (Array.isArray(next)) {
        setRows((prev) => {
          // merge by id, newer replaces older
          const map = new Map<string, IntentRecord>();
          for (const r of prev) map.set(r.id, r);
          for (const r of next) map.set(r.id, r);
          return Array.from(map.values());
        });
      }
    } catch (err) {
      onError?.(err);
    }
  }, [loadData, onError]);

  useEffect(() => {
    if (!live || !loadData || pollMs <= 0) return;
    let cancelled = false;

    const tick = async () => {
      if (cancelled) return;
      await doLoad();
      if (cancelled) return;
      pollRef.current = window.setTimeout(tick, pollMs);
    };

    tick();
    return () => {
      cancelled = true;
      if (pollRef.current) {
        window.clearTimeout(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [live, loadData, pollMs, doLoad]);

  // Derived facets
  const agents = useMemo(() => {
    const s = new Set(rows.map((r) => r.agent).filter(Boolean) as string[]);
    return Array.from(s).sort();
  }, [rows]);

  const channels = useMemo(() => {
    const s = new Set(rows.map((r) => r.channel).filter(Boolean) as string[]);
    return Array.from(s).sort();
  }, [rows]);

  // Filtering
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((r) => {
      if (agent !== "all" && r.agent !== agent) return false;
      if (channel !== "all" && r.channel !== channel) return false;
      if (r.confidence < minConf) return false;
      if (!q) return true;
      const hay = [
        r.intent,
        r.agent,
        r.channel,
        r.userText,
        ...(r.tags ?? []),
        ...(r.features ?? []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [rows, agent, channel, minConf, query]);

  // Sorting
  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let va: number | string = "";
      let vb: number | string = "";
      switch (sortKey) {
        case "timestamp":
          va = new Date(a.timestamp).getTime();
          vb = new Date(b.timestamp).getTime();
          break;
        case "confidence":
          va = a.confidence;
          vb = b.confidence;
          break;
        case "intent":
          va = a.intent;
          vb = b.intent;
          break;
        case "agent":
          va = a.agent ?? "";
          vb = b.agent ?? "";
          break;
      }
      if (va < vb) return sortDir === "asc" ? -1 : 1;
      if (va > vb) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return arr;
  }, [filtered, sortKey, sortDir]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const pageSafe = Math.min(Math.max(1, page), totalPages);
  const pageRows = useMemo(() => {
    const start = (pageSafe - 1) * pageSize;
    return sorted.slice(start, start + pageSize);
  }, [sorted, pageSafe, pageSize]);

  useEffect(() => {
    // reset to page 1 on filters
    setPage(1);
  }, [query, agent, channel, minConf]);

  // Aggregates for sparkline
  const spark = useMemo(() => {
    const byTs: Record<string, number[]> = {};
    for (const r of filtered) {
      const t = new Date(r.timestamp);
      // bucket to minute granularity
      const key = new Date(
        t.getFullYear(),
        t.getMonth(),
        t.getDate(),
        t.getHours(),
        t.getMinutes(),
        0,
        0
      ).toISOString();
      if (!byTs[key]) byTs[key] = [];
      byTs[key].push(r.confidence);
    }
    const pts = Object.entries(byTs)
      .map(([k, vals]) => ({
        ts: k,
        avg: vals.reduce((a, b) => a + b, 0) / vals.length,
      }))
      .sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
    return pts;
  }, [filtered]);

  // Handlers
  const onExport = useCallback(() => {
    downloadBlob(JSON.stringify(rows, null, 2), `intent_dump_${Date.now()}.json`);
  }, [rows]);

  const onImportFile = useCallback(
    async (file: File) => {
      const text = await file.text();
      try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
          // Basic validate for required fields
          const ok = parsed.filter(
            (r) => r && typeof r.id === "string" && typeof r.timestamp === "string" && typeof r.intent === "string"
          );
          setRows((prev) => {
            const map = new Map<string, IntentRecord>();
            for (const r of prev) map.set(r.id, r);
            for (const r of ok) map.set(r.id, r as IntentRecord);
            return Array.from(map.values());
          });
        }
      } catch (e) {
        onError?.(e);
      }
    },
    [onError]
  );

  const onCopySelected = useCallback(async () => {
    if (!selected) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(selected, null, 2));
    } catch (e) {
      onError?.(e);
    }
  }, [selected, onError]);

  const onClear = useCallback(() => {
    setQuery("");
    setAgent("all");
    setChannel("all");
    setMinConf(0);
    setSortKey("timestamp");
    setSortDir("desc");
  }, []);

  // -------------------------- Render -----------------------------------------
  return (
    <Card className={`w-full ${className ?? ""}`}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-2xl">XAI Intent Debugger</CardTitle>
          <div className="flex items-center gap-2">
            <Button
              variant={live ? "secondary" : "default"}
              size="sm"
              onClick={() => setLive((v) => !v)}
            >
              {live ? <Pause className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}
              Live
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                if (loadData) doLoad();
              }}
              disabled={!loadData}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <ListFilter className="mr-2 h-4 w-4" />
                  Actions
                  <ChevronDown className="ml-2 h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuLabel>Data</DropdownMenuLabel>
                <DropdownMenuItem onClick={onExport}>
                  <Download className="mr-2 h-4 w-4" />
                  Export JSON
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    setImportOpen(true);
                    fileInputRef.current?.click();
                  }}
                >
                  <Upload className="mr-2 h-4 w-4" />
                  Import JSON
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={onClear}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Reset filters
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <input
              ref={fileInputRef}
              className="hidden"
              type="file"
              accept="application/json"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) onImportFile(f);
                e.currentTarget.value = "";
              }}
            />
          </div>
        </div>
        <p className="text-muted-foreground mt-1 text-sm flex items-center">
          <Info className="h-4 w-4 mr-2" />
          Интерактивная отладка намерений, уверенности и трассировки XAI-агентов.
        </p>
      </CardHeader>
      <CardContent>
        {/* Filters */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 mb-4">
          <div className="lg:col-span-4">
            <Label htmlFor="search">Поиск</Label>
            <div className="relative">
              <Input
                id="search"
                placeholder="intent, агент, канал, тег, feature..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="pl-9"
              />
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            </div>
          </div>
          <div className="lg:col-span-2">
            <Label>Агент</Label>
            <Select value={agent} onValueChange={setAgent}>
              <SelectTrigger>
                <SelectValue placeholder="Agent" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все</SelectItem>
                {agents.map((a) => (
                  <SelectItem key={a} value={a}>
                    {a}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="lg:col-span-2">
            <Label>Канал</Label>
            <Select value={channel} onValueChange={setChannel}>
              <SelectTrigger>
                <SelectValue placeholder="Channel" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все</SelectItem>
                {channels.map((c) => (
                  <SelectItem key={c} value={c}>
                    {c}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="lg:col-span-2">
            <Label>Минимальная уверенность: {minConf.toFixed(2)}</Label>
            <div className="px-1 py-2">
              <Slider
                value={[minConf]}
                min={0}
                max={1}
                step={0.01}
                onValueChange={(v: number[]) => setMinConf(clamp01(v[0] ?? 0))}
              />
            </div>
          </div>
          <div className="lg:col-span-2">
            <Label>Сортировка</Label>
            <div className="flex gap-2">
              <Select value={sortKey} onValueChange={(v) => setSortKey(v as SortKey)}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Sort by" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="timestamp">Время</SelectItem>
                  <SelectItem value="confidence">Уверенность</SelectItem>
                  <SelectItem value="intent">Intent</SelectItem>
                  <SelectItem value="agent">Агент</SelectItem>
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
                title="Направление"
              >
                {sortDir === "asc" ? (
                  <ChevronUpIcon />
                ) : (
                  <ChevronDownIcon />
                )}
              </Button>
            </div>
          </div>
        </div>

        {/* Summary sparkline */}
        <div className="mb-4 rounded-xl border">
          <div className="px-4 py-2 flex items-center gap-2">
            <Activity className="h-4 w-4" />
            <span className="font-medium">Средняя уверенность во времени</span>
          </div>
          <div className="h-32 px-2 pb-2">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={spark}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="ts"
                  tickFormatter={(v) => new Date(v).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                />
                <YAxis domain={[0, 1]} />
                <Tooltip
                  formatter={(v: number) => v.toFixed(3)}
                  labelFormatter={(l) => formatDateTime(l as string)}
                />
                <Line type="monotone" dataKey="avg" dot={false} strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Table */}
        <div className="rounded-xl border">
          <div className="px-4 py-2 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4" />
              <span className="text-sm text-muted-foreground">
                Найдено: {filtered.length} • На странице: {pageRows.length}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Timer className="h-4 w-4" />
              <span className="text-sm text-muted-foreground">Стр. {pageSafe}/{totalPages}</span>
              <Button
                variant="outline"
                size="sm"
                disabled={pageSafe <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={pageSafe >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next
              </Button>
            </div>
          </div>

          <ScrollArea className="max-h-[48vh]">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-background">
                <tr className="text-left border-y">
                  <th className="px-4 py-2">Время</th>
                  <th className="px-4 py-2">Intent</th>
                  <th className="px-4 py-2">Увер.</th>
                  <th className="px-4 py-2">Агент</th>
                  <th className="px-4 py-2">Канал</th>
                  <th className="px-4 py-2">Теги</th>
                  <th className="px-4 py-2">Детали</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {pageRows.map((r) => (
                    <motion.tr
                      key={r.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="border-b hover:bg-muted/50 cursor-pointer"
                      onClick={() => setSelected(r)}
                    >
                      <td className="px-4 py-2 whitespace-nowrap">{formatDateTime(r.timestamp)}</td>
                      <td className="px-4 py-2">
                        <div className="flex items-center gap-2">
                          <Wand2 className="h-4 w-4" />
                          <span className="font-medium">{r.intent}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2">
                        <ConfidencePill value={r.confidence} />
                      </td>
                      <td className="px-4 py-2">{r.agent ?? "-"}</td>
                      <td className="px-4 py-2">{r.channel ?? "-"}</td>
                      <td className="px-4 py-2">
                        <div className="flex flex-wrap gap-1">
                          {(r.tags ?? []).slice(0, 4).map((t) => (
                            <Badge key={t} variant="secondary">
                              {t}
                            </Badge>
                          ))}
                          {(r.tags?.length ?? 0) > 4 ? (
                            <Badge variant="outline">+{(r.tags!.length - 4)}</Badge>
                          ) : null}
                        </div>
                      </td>
                      <td className="px-4 py-2">
                        <Button variant="ghost" size="sm" className="gap-1">
                          <ArrowUpRight className="h-4 w-4" />
                          Открыть
                        </Button>
                      </td>
                    </motion.tr>
                  ))}
                  {pageRows.length === 0 && (
                    <tr>
                      <td className="px-4 py-8 text-center text-muted-foreground" colSpan={7}>
                        Нет данных для отображения.
                      </td>
                    </tr>
                  )}
                </AnimatePresence>
              </tbody>
            </table>
          </ScrollArea>
        </div>

        {/* Detail sheet */}
        <Sheet open={!!selected} onOpenChange={(v: boolean) => !v && setSelected(null)}>
          <SheetContent side="right" className="w-full sm:max-w-2xl">
            <SheetHeader>
              <SheetTitle>Детали намерения</SheetTitle>
              <SheetDescription>
                Просмотр контекста, трассировки и динамики уверенности.
              </SheetDescription>
            </SheetHeader>
            <div className="mt-4 space-y-4">
              {selected && (
                <>
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-sm text-muted-foreground">{formatDateTime(selected.timestamp)}</div>
                      <div className="text-xl font-semibold">{selected.intent}</div>
                      <div className="mt-1">
                        <ConfidencePill value={selected.confidence} />
                      </div>
                      <div className="mt-2 flex gap-2">
                        {selected.agent && <Badge variant="outline">Agent: {selected.agent}</Badge>}
                        {selected.channel && <Badge variant="outline">Channel: {selected.channel}</Badge>}
                        {selected.sessionId && <Badge variant="secondary">Session: {selected.sessionId}</Badge>}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button variant="outline" size="sm" onClick={onCopySelected}>
                        <Copy className="mr-2 h-4 w-4" />
                        Copy JSON
                      </Button>
                    </div>
                  </div>

                  <Tabs defaultValue="rationale" className="w-full">
                    <TabsList className="grid w-full grid-cols-4">
                      <TabsTrigger value="rationale">Rationale</TabsTrigger>
                      <TabsTrigger value="trace">Trace</TabsTrigger>
                      <TabsTrigger value="json">JSON</TabsTrigger>
                      <TabsTrigger value="chart">Chart</TabsTrigger>
                    </TabsList>

                    <TabsContent value="rationale" className="mt-3">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">Обоснование</CardTitle>
                        </CardHeader>
                        <CardContent>
                          {selected.rationale && selected.rationale.length > 0 ? (
                            <ol className="list-decimal pl-5 space-y-1">
                              {selected.rationale.map((s, i) => (
                                <li key={i}>{s}</li>
                              ))}
                            </ol>
                          ) : (
                            <p className="text-muted-foreground text-sm">Нет данных.</p>
                          )}
                          {selected.features && selected.features.length > 0 && (
                            <div className="mt-3 flex flex-wrap gap-2">
                              {selected.features.map((f) => (
                                <Badge key={f} variant="secondary">{f}</Badge>
                              ))}
                            </div>
                          )}
                          {selected.userText && (
                            <div className="mt-3">
                              <Label className="text-xs text-muted-foreground">Пользовательский ввод</Label>
                              <p className="mt-1 rounded-md border p-2 text-sm whitespace-pre-wrap">
                                {selected.userText}
                              </p>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    </TabsContent>

                    <TabsContent value="trace" className="mt-3">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">Трассировка</CardTitle>
                        </CardHeader>
                        <CardContent>
                          {selected.trace && selected.trace.length > 0 ? (
                            <ul className="space-y-2">
                              {selected.trace.map((t, i) => (
                                <li key={i} className="rounded-md border p-2">
                                  <div className="flex items-center justify-between">
                                    <div className="font-medium">{t.step}</div>
                                    {typeof t.latencyMs === "number" && (
                                      <Badge variant="outline">{t.latencyMs} ms</Badge>
                                    )}
                                  </div>
                                  {t.detail && <p className="text-sm text-muted-foreground mt-1">{t.detail}</p>}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="text-muted-foreground text-sm">Нет данных.</p>
                          )}
                        </CardContent>
                      </Card>
                    </TabsContent>

                    <TabsContent value="json" className="mt-3">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">JSON</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="h-[38vh] rounded-md border p-2">
                            <pre className="text-xs leading-relaxed">
                              {safeJson(selected)}
                            </pre>
                          </ScrollArea>
                        </CardContent>
                      </Card>
                    </TabsContent>

                    <TabsContent value="chart" className="mt-3">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">Динамика уверенности (по intent)</CardTitle>
                        </CardHeader>
                        <CardContent className="h-56">
                          <ResponsiveContainer width="100%" height="100%">
                            <LineChart
                              data={
                                rows
                                  .filter((r) => r.intent === selected.intent)
                                  .sort(
                                    (a, b) =>
                                      new Date(a.timestamp).getTime() -
                                      new Date(b.timestamp).getTime()
                                  )
                                  .map((r) => ({
                                    ts: r.timestamp,
                                    conf: r.confidence,
                                  }))
                              }
                            >
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis
                                dataKey="ts"
                                tickFormatter={(v) =>
                                  new Date(v).toLocaleTimeString([], {
                                    hour: "2-digit",
                                    minute: "2-digit",
                                  })
                                }
                              />
                              <YAxis domain={[0, 1]} />
                              <Tooltip
                                formatter={(v: number) => v.toFixed(3)}
                                labelFormatter={(l) => formatDateTime(l as string)}
                              />
                              <Line type="monotone" dataKey="conf" dot={false} strokeWidth={2} />
                            </LineChart>
                          </ResponsiveContainer>
                        </CardContent>
                      </Card>
                    </TabsContent>
                  </Tabs>
                </>
              )}
            </div>
            <SheetFooter className="mt-4">
              <SheetTrigger asChild>
                <Dialog>
                  <DialogTriggerButton />
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Справка</DialogTitle>
                      <DialogDescription>
                        Рекомендации по использованию и формату данных.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-3 text-sm">
                      <p>
                        Компонент принимает массив записей <code>IntentRecord[]</code> через prop <code>data</code> или функцию <code>loadData</code> для live-обновления.
                      </p>
                      <p>
                        Минимально обязательные поля записи: <code>id</code>, <code>timestamp</code> (ISO), <code>intent</code>, <code>confidence</code>.
                      </p>
                      <p>
                        Необязательные поля: <code>agent</code>, <code>channel</code>, <code>userText</code>, <code>context</code>, <code>features</code>, <code>rationale</code>, <code>trace</code>, <code>tags</code>, <code>sessionId</code>.
                      </p>
                      <p>
                        Импорт/экспорт — JSON-массив таких записей. Повторяющиеся <code>id</code> перезаписываются.
                      </p>
                    </div>
                    <DialogFooter>
                      <DialogClose asChild>
                        <Button variant="secondary">Закрыть</Button>
                      </DialogClose>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              </SheetTrigger>
            </SheetFooter>
          </SheetContent>
        </Sheet>
      </CardContent>
    </Card>
  );
};

// -------------------------- Subcomponents ------------------------------------

const ChevronUpIcon: React.FC = () => (
  <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M18 15l-6-6-6 6" />
  </svg>
);

const ChevronDownIcon: React.FC = () => (
  <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M6 9l6 6 6-6" />
  </svg>
);

const ConfidencePill: React.FC<{ value: number }> = ({ value }) => {
  const pct = Math.round(clamp01(value) * 100);
  return (
    <span
      className="inline-flex items-center rounded-full border px-2 py-0.5 text-xs"
      title={`Уверенность: ${pct}%`}
    >
      <span className="mr-2 inline-block h-2 w-12 overflow-hidden rounded-full bg-muted">
        <span
          className="block h-2 rounded-full"
          style={{ width: `${pct}%` }}
        />
      </span>
      {value.toFixed(3)}
    </span>
  );
};

const DialogTriggerButton: React.FC = () => (
  <Button variant="ghost" size="sm">
    <Info className="mr-2 h-4 w-4" />
    Справка
  </Button>
);

// ------------------------------ Export ---------------------------------------

export default IntentDebugger;

/*
USAGE (for reference inside project):

import IntentDebugger, { IntentRecord } from "@/widgets/XAI/IntentDebugger";

<IntentDebugger
  data={initialData}
  loadData={async () => fetch("/api/xai/intents").then(r => r.json())}
  pollMs={5000}
  pageSize={25}
/>

Styling: relies on Tailwind + shadcn/ui. No external styles required.
*/
