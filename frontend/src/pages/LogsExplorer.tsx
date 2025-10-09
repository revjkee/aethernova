// frontend/src/pages/LogsExplorer.tsx
import * as React from "react";
import type { FC } from "react";
import { motion } from "framer-motion";
import {
  Play,
  Pause,
  Search,
  Filter,
  Download,
  Copy,
  AlertTriangle,
  Bug,
  Info,
  Trash2,
  Clock,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";

// ---- Типы данных ------------------------------------------------------------

type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal";

export type LogRecord = {
  id: string;               // стабильный ID (если нет — формируем на клиенте)
  ts: number;               // epoch ms
  level: LogLevel;
  service?: string;
  msg: string;
  meta?: Record<string, unknown>;
};

// ---- Утилиты форматирования -------------------------------------------------

const fmtFull = new Intl.DateTimeFormat(undefined, {
  year: "2-digit",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function formatTs(ts: number) {
  return fmtFull.format(ts);
}

function levelToColor(level: LogLevel): string {
  switch (level) {
    case "trace":
      return "text-muted-foreground";
    case "debug":
      return "text-blue-600 dark:text-blue-400";
    case "info":
      return "text-foreground";
    case "warn":
      return "text-amber-600 dark:text-amber-400";
    case "error":
      return "text-red-600 dark:text-red-400";
    case "fatal":
      return "text-fuchsia-600 dark:text-fuchsia-400";
    default:
      return "text-foreground";
  }
}

function serializeJSONL(records: LogRecord[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

function highlight(text: string, query: string, regex: boolean): React.ReactNode {
  if (!query) return text;
  try {
    if (regex) {
      const r = new RegExp(query, "gi");
      const parts: React.ReactNode[] = [];
      let lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = r.exec(text))) {
        const start = m.index;
        const end = start + (m[0]?.length ?? 0);
        if (start > lastIndex) parts.push(text.slice(lastIndex, start));
        parts.push(<mark key={`${start}-${end}`} className="bg-yellow-200 dark:bg-yellow-800">{text.slice(start, end)}</mark>);
        lastIndex = end;
        if (!r.global) break;
      }
      if (lastIndex < text.length) parts.push(text.slice(lastIndex));
      return parts;
    } else {
      const needle = query.toLowerCase();
      const idx = text.toLowerCase().indexOf(needle);
      if (idx === -1) return text;
      const end = idx + needle.length;
      return (
        <>
          {text.slice(0, idx)}
          <mark className="bg-yellow-200 dark:bg-yellow-800">{text.slice(idx, end)}</mark>
          {text.slice(end)}
        </>
      );
    }
  } catch {
    return text;
  }
}

// ---- Фильтрация -------------------------------------------------------------

type Filters = {
  query: string;
  regex: boolean;
  levels: Set<LogLevel>;
  service: string;
  from?: string; // ISO (datetime-local)
  to?: string;   // ISO (datetime-local)
  onlyErrors: boolean;
};

function applyFilters(records: LogRecord[], f: Filters): LogRecord[] {
  const q = f.query?.trim();
  const hasQ = !!q;
  let re: RegExp | null = null;
  if (hasQ && f.regex) {
    try {
      re = new RegExp(q, "i");
    } catch {
      // игнорируем некорректный RegExp
      re = null;
    }
  }
  const fromTs = f.from ? Date.parse(f.from) : undefined;
  const toTs = f.to ? Date.parse(f.to) : undefined;

  return records.filter((r) => {
    if (f.onlyErrors && !(r.level === "error" || r.level === "fatal" || r.level === "warn")) return false;
    if (f.levels.size && !f.levels.has(r.level)) return false;
    if (f.service && r.service && !r.service.toLowerCase().includes(f.service.toLowerCase())) return false;
    if (fromTs && r.ts < fromTs) return false;
    if (toTs && r.ts > toTs) return false;
    if (hasQ) {
      const corpus = `${r.msg}\n${r.service ?? ""}\n${JSON.stringify(r.meta ?? {})}`;
      if (f.regex) {
        if (re && !re.test(corpus)) return false;
      } else if (!corpus.toLowerCase().includes(q.toLowerCase())) return false;
    }
    return true;
  });
}

// ---- Виртуальный список без сторонних библиотек ----------------------------

type VirtualListProps<T> = {
  items: T[];
  rowHeight: number; // px
  overscan?: number;
  className?: string;
  renderRow: (item: T, index: number) => React.ReactNode;
};

const VirtualList = <T,>({ items, rowHeight, overscan = 8, className, renderRow }: VirtualListProps<T>) => {
  const wrapRef = React.useRef<HTMLDivElement | null>(null);
  const [height, setHeight] = React.useState<number>(480);
  const [scrollTop, setScrollTop] = React.useState<number>(0);

  React.useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const onScroll = () => setScrollTop(el.scrollTop);
    el.addEventListener("scroll", onScroll);
    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver((entries) => {
        for (const e of entries) {
          if (e.contentRect?.height) setHeight(e.contentRect.height);
        }
      });
      ro.observe(el);
    } else {
      setHeight(el.clientHeight || 480);
    }
    return () => {
      el.removeEventListener("scroll", onScroll);
      ro?.disconnect();
    };
  }, []);

  const total = items.length;
  const visibleCount = Math.ceil(height / rowHeight);
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const end = Math.min(total, start + visibleCount + overscan * 2);
  const offsetY = start * rowHeight;

  return (
    <div ref={wrapRef} className={["relative overflow-auto", className].filter(Boolean).join(" ")} style={{ willChange: "transform" }}>
      <div style={{ height: total * rowHeight, position: "relative" }}>
        <div style={{ position: "absolute", top: offsetY, left: 0, right: 0 }}>
          {items.slice(start, end).map((item, i) => (
            <div key={start + i} style={{ height: rowHeight }}>
              {renderRow(item, start + i)}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ---- Источник данных: SSE + polling (без внешних зависимостей) -------------

type UseLogsOptions = {
  pageSize?: number;
  sseUrl?: string;   // e.g. /api/logs/stream
  fetchUrl?: string; // e.g. /api/logs
};

function useLogs(opts: UseLogsOptions) {
  const pageSize = opts.pageSize ?? 500;
  const [logs, setLogs] = React.useState<LogRecord[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [tail, setTail] = React.useState<boolean>(true);
  const [pollingId, setPollingId] = React.useState<number | null>(null);
  const sseRef = React.useRef<EventSource | null>(null);

  const append = React.useCallback((incoming: LogRecord[]) => {
    if (!incoming?.length) return;
    setLogs((prev) => {
      const merged = [...prev, ...incoming];
      // ограничиваем память
      if (merged.length > 50_000) return merged.slice(merged.length - 50_000);
      return merged;
    });
  }, []);

  // Начальный поллинг последней страницы
  const fetchLatest = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const url = (opts.fetchUrl ?? "/api/logs") + `?limit=${pageSize}`;
      const res = await fetch(url, { headers: { Accept: "application/json" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as LogRecord[];
      setLogs(data);
    } catch (e: any) {
      setError(e?.message ?? "Fetch error");
    } finally {
      setLoading(false);
    }
  }, [opts.fetchUrl, pageSize]);

  // SSE (если доступно) с деградацией до polling
  const startTail = React.useCallback(() => {
    if (sseRef.current || !tail) return;
    if (typeof window === "undefined") return;
    let connected = false;

    if (opts.sseUrl && "EventSource" in window) {
      try {
        const es = new EventSource(opts.sseUrl);
        sseRef.current = es;
        es.onopen = () => { connected = true; };
        es.onmessage = (ev) => {
          try {
            const rec = JSON.parse(ev.data);
            const arr = Array.isArray(rec) ? rec : [rec];
            append(arr.map(coerceLog));
          } catch {
            // пропускаем
          }
        };
        es.onerror = () => {
          es.close();
          sseRef.current = null;
          if (!connected) startPolling();
        };
        return;
      } catch {
        // падаем в polling
      }
    }
    startPolling();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opts.sseUrl, tail, append]);

  const stopTail = React.useCallback(() => {
    sseRef.current?.close();
    sseRef.current = null;
    if (pollingId !== null) {
      window.clearInterval(pollingId);
      setPollingId(null);
    }
  }, [pollingId]);

  const startPolling = React.useCallback(() => {
    if (pollingId !== null) return;
    const id = window.setInterval(async () => {
      try {
        const lastTs = logs.length ? logs[logs.length - 1].ts : 0;
        const url = (opts.fetchUrl ?? "/api/logs") + `?sinceTs=${lastTs}`;
        const res = await fetch(url, { headers: { Accept: "application/json" } });
        if (!res.ok) return;
        const data = (await res.json()) as LogRecord[];
        if (data?.length) append(data.map(coerceLog));
      } catch {
        // без падения UI
      }
    }, 1500);
    setPollingId(id);
  }, [append, logs, opts.fetchUrl, pollingId]);

  React.useEffect(() => {
    fetchLatest();
  }, [fetchLatest]);

  React.useEffect(() => {
    if (tail) startTail();
    else stopTail();
    return () => stopTail();
  }, [tail, startTail, stopTail]);

  return { logs, setLogs, loading, error, tail, setTail, fetchLatest };
}

function coerceLog(x: any): LogRecord {
  const id = String(x?.id ?? `${x?.ts ?? Date.now()}-${Math.random().toString(36).slice(2)}`);
  const level: LogLevel = ["trace", "debug", "info", "warn", "error", "fatal"].includes(x?.level)
    ? x.level
    : "info";
  return {
    id,
    ts: typeof x?.ts === "number" ? x.ts : Date.parse(x?.ts ?? new Date().toISOString()),
    level,
    service: x?.service ?? undefined,
    msg: typeof x?.msg === "string" ? x.msg : JSON.stringify(x?.msg ?? "", null, 2),
    meta: typeof x?.meta === "object" ? x.meta : undefined,
  };
}

// ---- Строка таблицы ---------------------------------------------------------

const Row: FC<{
  rec: LogRecord;
  q: string;
  regex: boolean;
  onCopy: (rec: LogRecord) => void;
}> = ({ rec, q, regex, onCopy }) => {
  return (
    <div
      className="grid grid-cols-[168px_92px_160px_1fr_24px] items-center gap-3 px-3 text-xs font-mono leading-5 hover:bg-muted/50"
      role="row"
      aria-label="log-row"
    >
      <div className="truncate text-muted-foreground" title={new Date(rec.ts).toISOString()}>
        {formatTs(rec.ts)}
      </div>
      <div className={`truncate ${levelToColor(rec.level)}`}>{rec.level.toUpperCase()}</div>
      <div className="truncate text-muted-foreground" title={rec.service ?? ""}>
        {rec.service ?? "-"}
      </div>
      <div className="truncate">
        <span className="whitespace-pre-wrap break-words">
          {highlight(rec.msg, q, regex)}
        </span>
      </div>
      <div className="flex items-center justify-end">
        <TooltipProvider delayDuration={150}>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => onCopy(rec)} aria-label="Скопировать строку">
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Скопировать JSON</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>
    </div>
  );
};

// ---- Главная страница -------------------------------------------------------

const LogsExplorer: FC = () => {
  const { logs, setLogs, loading, error, tail, setTail, fetchLatest } = useLogs({
    pageSize: 500,
    sseUrl: "/api/logs/stream",
    fetchUrl: "/api/logs",
  });

  const [filters, setFilters] = React.useState<Filters>({
    query: "",
    regex: false,
    levels: new Set<LogLevel>(),
    service: "",
    from: undefined,
    to: undefined,
    onlyErrors: false,
  });

  const filtered = React.useMemo(() => applyFilters(logs, filters), [logs, filters]);

  const onCopyRow = React.useCallback((rec: LogRecord) => {
    const s = JSON.stringify(rec);
    void navigator.clipboard?.writeText(s);
  }, []);

  const copyAll = React.useCallback(() => {
    const s = serializeJSONL(filtered);
    void navigator.clipboard?.writeText(s);
  }, [filtered]);

  const downloadAll = React.useCallback(() => {
    const blob = new Blob([serializeJSONL(filtered)], { type: "application/x-ndjson;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const file = `logs_${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`;
    a.download = file;
    a.click();
    URL.revokeObjectURL(url);
  }, [filtered]);

  const clearAll = React.useCallback(() => {
    setLogs([]);
  }, [setLogs]);

  const toggleLevel = (lvl: LogLevel) => {
    setFilters((f) => {
      const next = new Set(f.levels);
      if (next.has(lvl)) next.delete(lvl);
      else next.add(lvl);
      return { ...f, levels: next };
    });
  };

  // Горячие клавиши: / — фокус поиска, Space — пауза/пуск
  const searchRef = React.useRef<HTMLInputElement | null>(null);
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.code === "Space" && (e.target as HTMLElement)?.tagName !== "INPUT") {
        e.preventDefault();
        setTail((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setTail]);

  return (
    <div className="min-h-screen w-full bg-background">
      {/* Шапка */}
      <header className="sticky top-0 z-30 border-b bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-14 items-center justify-between">
            <div className="flex items-center gap-2">
              <Bug className="h-5 w-5" />
              <span className="text-sm font-semibold tracking-tight">Logs Explorer</span>
              {tail ? <Badge>live</Badge> : <Badge variant="outline">paused</Badge>}
            </div>
            <div className="flex items-center gap-2">
              <TooltipProvider delayDuration={150}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon" aria-label="Перезагрузить" onClick={fetchLatest}>
                      <Clock className="h-4 w-4" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Загрузить последние</TooltipContent>
                </Tooltip>
              </TooltipProvider>
              <Button size="sm" variant={tail ? "outline" : "default"} onClick={() => setTail((v) => !v)}>
                {tail ? <><Pause className="mr-2 h-4 w-4" />Пауза</> : <><Play className="mr-2 h-4 w-4" />Пуск</>}
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Контент */}
      <main className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-4 space-y-4">
        {/* Панель фильтров */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">Фильтры</CardTitle>
                <CardDescription>Поиск, уровни, сервис, интервал времени</CardDescription>
              </div>
              <Badge variant="secondary" className="justify-self-end">{filtered.length} / {logs.length}</Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="flex items-center gap-2">
                <Search className="h-4 w-4 text-muted-foreground" />
                <Input
                  ref={searchRef}
                  placeholder="Поиск по сообщению, сервису, meta (/, фокус)"
                  value={filters.query}
                  onChange={(e) => setFilters((f) => ({ ...f, query: e.target.value }))}
                />
                <div className="flex items-center gap-2">
                  <Switch
                    id="regex"
                    checked={filters.regex}
                    onCheckedChange={(v) => setFilters((f) => ({ ...f, regex: v }))}
                  />
                  <Label htmlFor="regex" className="text-xs">RegExp</Label>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Сервис (contains)"
                  value={filters.service}
                  onChange={(e) => setFilters((f) => ({ ...f, service: e.target.value }))}
                />
                <div className="flex items-center gap-2">
                  <Switch
                    id="onlyErrors"
                    checked={filters.onlyErrors}
                    onCheckedChange={(v) => setFilters((f) => ({ ...f, onlyErrors: v }))}
                  />
                  <Label htmlFor="onlyErrors" className="text-xs">Только warn+</Label>
                </div>
              </div>

              <div className="grid w-full grid-cols-2 gap-2">
                <Input
                  type="datetime-local"
                  value={filters.from ?? ""}
                  onChange={(e) => setFilters((f) => ({ ...f, from: e.target.value || undefined }))}
                  aria-label="От"
                />
                <Input
                  type="datetime-local"
                  value={filters.to ?? ""}
                  onChange={(e) => setFilters((f) => ({ ...f, to: e.target.value || undefined }))}
                  aria-label="До"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {(["trace", "debug", "info", "warn", "error", "fatal"] as LogLevel[]).map((lvl) => {
                const active = filters.levels.has(lvl);
                return (
                  <Button
                    key={lvl}
                    size="sm"
                    variant={active ? "default" : "outline"}
                    onClick={() => toggleLevel(lvl)}
                  >
                    {lvl.toUpperCase()}
                  </Button>
                );
              })}
              <Separator orientation="vertical" className="mx-2 hidden md:block" />
              <div className="ml-auto flex items-center gap-2">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button variant="outline" size="sm" onClick={copyAll}>
                        <Copy className="mr-2 h-4 w-4" /> Копировать JSONL
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Скопировать отфильтрованные</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <Button variant="outline" size="sm" onClick={downloadAll}>
                  <Download className="mr-2 h-4 w-4" /> Скачать
                </Button>
                <Button variant="ghost" size="sm" onClick={clearAll}>
                  <Trash2 className="mr-2 h-4 w-4" /> Очистить
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Ошибки загрузки */}
        {error ? (
          <Card className="border-red-500/40">
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2 text-red-600">
                <AlertTriangle className="h-4 w-4" /> Ошибка загрузки
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-sm">{error}</div>
            </CardContent>
          </Card>
        ) : null}

        {/* Таблица */}
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CardTitle className="text-base">Логи</CardTitle>
                {loading ? <Badge variant="secondary">загрузка…</Badge> : null}
              </div>
              <div className="text-xs text-muted-foreground flex items-center gap-2">
                <Info className="h-3.5 w-3.5" />
                Управление: Space — пауза/пуск, / — поиск. Колонки: время, уровень, сервис, сообщение.
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div role="table" aria-label="logs-table" className="w-full">
              {/* Заголовки */}
              <div className="grid grid-cols-[168px_92px_160px_1fr_24px] items-center gap-3 border-b px-3 py-2 text-[11px] uppercase tracking-wide text-muted-foreground">
                <div>Время</div>
                <div>Уровень</div>
                <div>Сервис</div>
                <div>Сообщение</div>
                <div />
              </div>

              {/* Тело: виртуализация */}
              <VirtualList
                items={filtered}
                rowHeight={28}
                className="h-[60vh]"
                renderRow={(rec) => (
                  <Row rec={rec} q={filters.query} regex={filters.regex} onCopy={onCopyRow} />
                )}
              />
            </div>
          </CardContent>
        </Card>

        {/* Примечания */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          className="text-xs text-muted-foreground"
        >
          Для интеграции подключите эндпоинты:
          <ul className="list-disc pl-4 mt-1">
            <li>GET /api/logs?limit=N&sinceTs=epoch_ms — постраничная выдача JSON массива LogRecord</li>
            <li>SSE /api/logs/stream — event: message, data: LogRecord | LogRecord[]</li>
          </ul>
        </motion.div>
      </main>
    </div>
  );
};

export default LogsExplorer;
