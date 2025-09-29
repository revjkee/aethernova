// frontend/src/widgets/Agents/AgentLogsViewer.tsx
// Industrial-grade Agent Logs Viewer
// - Virtualized log list
// - Live stream via WebSocket or SSE
// - Filtering (level, agent, text, time range)
// - Pause/Resume, Follow Tail, Clear, Export (JSON/NDJSON)
// - Copy-to-clipboard for a log line
// - Resilient reconnect with backoff
// - Safe JSON parsing + structured view toggle

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  memo,
  PropsWithChildren,
} from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Play,
  Pause,
  Download,
  Trash2,
  Search,
  RefreshCw,
  AlertTriangle,
  TerminalSquare,
  Link as LinkIcon,
  Link2Off,
  ListFilter,
  Copy,
  Check,
} from "lucide-react";

// ---------- Types ----------
export type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal";
export type TransportKind = "ws" | "sse" | "none";

export interface AgentLog {
  id: string;                 // stable id (e.g., hash or backend id)
  ts: string;                 // ISO timestamp
  level: LogLevel;
  agent: string;              // agent name or id
  source?: string;            // module/source file
  message: string;            // human-readable message
  context?: Record<string, unknown>; // arbitrary structured payload
}

export interface AgentLogsViewerProps {
  // Live sources (optional). Provide one of them for streaming.
  wsUrl?: string;             // ws(s)://... endpoint producing NDJSON lines
  sseUrl?: string;            // http(s)://... SSE endpoint with data: <json>
  // Initial fetch (optional) to back-fill history.
  fetchInitial?: (limit: number) => Promise<AgentLog[]>;
  initialLimit?: number;      // how many initial records to load
  // Buffer settings
  maxBuffer?: number;         // max records to keep in memory
  // Render options
  height?: number;            // fixed height for the viewer
  compact?: boolean;          // denser rows
}

// ---------- Utilities ----------
const LEVEL_ORDER: Record<LogLevel, number> = {
  fatal: 50,
  error: 40,
  warn: 30,
  info: 20,
  debug: 10,
  trace: 0,
};

const LEVEL_BADGE: Record<LogLevel, string> = {
  fatal: "bg-red-600 text-white",
  error: "bg-red-500 text-white",
  warn: "bg-amber-500 text-black",
  info: "bg-blue-500 text-white",
  debug: "bg-slate-500 text-white",
  trace: "bg-gray-400 text-black",
};

function clsx(...parts: Array<string | false | undefined | null>) {
  return parts.filter(Boolean).join(" ");
}

function parseMaybe<T = unknown>(s: string): T | undefined {
  try {
    return JSON.parse(s) as T;
  } catch {
    return undefined;
  }
}

function backoff(attempt: number, base = 500, max = 8000) {
  const val = Math.min(max, base * 2 ** attempt);
  return val + Math.floor(Math.random() * (val / 4));
}

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function toISO(ts: string | number | Date): string {
  try {
    return new Date(ts).toISOString();
  } catch {
    return String(ts);
  }
}

// ---------- Virtualization (lightweight) ----------
/**
 * Simple vertical virtualization without external deps.
 * Works well for log lines with similar heights.
 */
function useVirtualList<T>(items: T[], rowHeight: number, containerRef: React.RefObject<HTMLElement>) {
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(0);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onScroll = () => setScrollTop(el.scrollTop);
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    el.addEventListener("scroll", onScroll, { passive: true });
    ro.observe(el);
    setHeight(el.clientHeight);
    return () => {
      el.removeEventListener("scroll", onScroll);
      ro.disconnect();
    };
  }, [containerRef]);

  const total = items.length * rowHeight;
  const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - 10);
  const endIndex = Math.min(items.length, Math.ceil((scrollTop + height) / rowHeight) + 10);
  const offsetY = startIndex * rowHeight;

  return { total, startIndex, endIndex, offsetY, height };
}

// ---------- Row component ----------
const LogRow = memo(function LogRow({
  log,
  compact,
  onCopy,
}: {
  log: AgentLog;
  compact?: boolean;
  onCopy: (text: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  const onCopyClick = useCallback(() => {
    const payload = JSON.stringify(log, null, 2);
    navigator.clipboard.writeText(payload).then(() => {
      setCopied(true);
      const t = setTimeout(() => setCopied(false), 1200);
      return () => clearTimeout(t);
    });
  }, [log]);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1200);
    return () => clearTimeout(t);
  }, [copied]);

  return (
    <div
      className={clsx(
        "grid w-full items-start gap-2 border-b border-border px-3",
        compact ? "py-1.5" : "py-2.5",
        "grid-cols-[auto_1fr_auto]"
      )}
      role="listitem"
      aria-label="log-row"
    >
      <div className="flex items-center gap-2">
        <Badge className={clsx("font-mono text-[10px]", LEVEL_BADGE[log.level])}>{log.level}</Badge>
        <Badge variant="outline" className="font-mono text-[10px]">{log.agent}</Badge>
      </div>
      <div className="min-w-0">
        <div className={clsx("text-xs text-muted-foreground font-mono", compact ? "" : "mb-0.5")}>
          {toISO(log.ts)} {log.source ? `• ${log.source}` : ""}
        </div>
        <div className={clsx("whitespace-pre-wrap break-words", compact ? "text-xs" : "text-sm")}>
          {log.message}
        </div>
        {log.context && Object.keys(log.context).length > 0 && (
          <pre className={clsx("mt-1 rounded bg-muted p-2 overflow-x-auto", compact ? "text-[11px]" : "text-xs")}>
            {JSON.stringify(log.context, null, 2)}
          </pre>
        )}
      </div>
      <div className="flex items-start">
        <Button variant="ghost" size="icon" aria-label="copy" onClick={onCopyClick}>
          {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
        </Button>
      </div>
    </div>
  );
});

// ---------- Main component ----------
export default function AgentLogsViewer({
  wsUrl,
  sseUrl,
  fetchInitial,
  initialLimit = 500,
  maxBuffer = 5000,
  height = 520,
  compact,
}: AgentLogsViewerProps) {
  // State
  const [connected, setConnected] = useState<boolean>(false);
  const [transport, setTransport] = useState<TransportKind>("none");
  const [paused, setPaused] = useState<boolean>(false);
  const [follow, setFollow] = useState<boolean>(true);

  const [query, setQuery] = useState<string>("");
  const [level, setLevel] = useState<LogLevel | "all">("all");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [fromTs, setFromTs] = useState<string>("");
  const [toTs, setToTs] = useState<string>("");

  const [logs, setLogs] = useState<AgentLog[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);
  const rowHeight = compact ? 56 : 72;
  const virtual = useVirtualList(logs, rowHeight, containerRef);

  // Agents memo
  const agents = useMemo(() => {
    const set = new Set<string>();
    logs.forEach((l) => set.add(l.agent));
    return ["all", ...Array.from(set).sort()];
  }, [logs]);

  // Derived filtered logs
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const from = fromTs ? Date.parse(fromTs) : undefined;
    const to = toTs ? Date.parse(toTs) : undefined;
    return logs.filter((l) => {
      if (level !== "all" && l.level !== level) return false;
      if (agentFilter !== "all" && l.agent !== agentFilter) return false;
      const t = Date.parse(l.ts);
      if (from && t < from) return false;
      if (to && t > to) return false;
      if (q) {
        const hay = `${l.message} ${l.agent} ${l.source ?? ""} ${JSON.stringify(l.context ?? {})}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [logs, level, agentFilter, query, fromTs, toTs]);

  // Virtualization uses filtered list
  const vVirtual = useVirtualList(filtered, rowHeight, containerRef);

  // Auto-follow to bottom
  useEffect(() => {
    if (!follow) return;
    const el = containerRef.current;
    if (!el) return;
    // Schedule after paint
    requestAnimationFrame(() => {
      el.scrollTop = el.scrollHeight;
    });
  }, [filtered.length, follow]);

  // Initial fetch
  useEffect(() => {
    let unmounted = false;
    if (!fetchInitial) return;
    (async () => {
      try {
        const data = await fetchInitial(initialLimit);
        if (unmounted) return;
        setLogs((prev) => trimBuffer(mergeDedup(prev, data), maxBuffer));
      } catch {
        // Silent: data source is optional.
      }
    })();
    return () => {
      unmounted = true;
    };
  }, [fetchInitial, initialLimit, maxBuffer]);

  // Live stream
  useEffect(() => {
    let stop = false;
    let attempt = 0;
    let ws: WebSocket | null = null;
    let es: EventSource | null = null;

    const handleLine = (raw: string) => {
      const parsed = parseMaybe<AgentLog>(raw);
      if (!parsed) return;
      if (!parsed.id) {
        // enforce stable id to prevent reordering issues
        parsed.id = `${parsed.agent ?? "agent"}:${parsed.ts ?? Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
      }
      if (!parsed.ts) parsed.ts = new Date().toISOString();
      if (!parsed.level) parsed.level = "info";
      setLogs((prev) => {
        const next = mergeDedup(prev, [parsed]);
        return trimBuffer(next, maxBuffer);
      });
    };

    const connectWS = () => {
      if (!wsUrl) return;
      setTransport("ws");
      ws = new WebSocket(wsUrl);
      ws.onopen = () => {
        setConnected(true);
        attempt = 0;
      };
      ws.onclose = () => {
        setConnected(false);
        if (!stop) {
          attempt++;
          setTimeout(connectWS, backoff(attempt));
        }
      };
      ws.onerror = () => {
        ws?.close();
      };
      ws.onmessage = (ev) => {
        if (paused) return;
        const data = ev.data;
        if (typeof data === "string") {
          // Accept either a JSON object or NDJSON lines
          if (data.includes("\n")) {
            data.split("\n").forEach((line) => line.trim() && handleLine(line));
          } else {
            handleLine(data);
          }
        }
      };
    };

    const connectSSE = () => {
      if (!sseUrl) return;
      setTransport("sse");
      es = new EventSource(sseUrl);
      es.onopen = () => {
        setConnected(true);
        attempt = 0;
      };
      es.onerror = () => {
        setConnected(false);
        es?.close();
        if (!stop) {
          attempt++;
          setTimeout(connectSSE, backoff(attempt));
        }
      };
      es.onmessage = (ev) => {
        if (paused) return;
        if (ev.data) handleLine(ev.data);
      };
    };

    if (wsUrl) connectWS();
    else if (sseUrl) connectSSE();

    return () => {
      stop = true;
      setConnected(false);
      ws?.close();
      es?.close();
      setTransport("none");
    };
  }, [wsUrl, sseUrl, paused, maxBuffer]);

  // Actions
  const onClear = useCallback(() => setLogs([]), []);
  const onPauseToggle = useCallback(() => setPaused((p) => !p), []);
  const onFollowToggle = useCallback(() => setFollow((f) => !f), []);
  const onCopy = useCallback((text: string) => {
    navigator.clipboard.writeText(text).catch(() => undefined);
  }, []);
  const onExportJSON = useCallback(() => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: "application/json" });
    downloadBlob(`agent-logs-${Date.now()}.json`, blob);
  }, [filtered]);

  const onExportNDJSON = useCallback(() => {
    const lines = filtered.map((l) => JSON.stringify(l)).join("\n");
    const blob = new Blob([lines], { type: "application/x-ndjson" });
    downloadBlob(`agent-logs-${Date.now()}.ndjson`, blob);
  }, [filtered]);

  // Helpers
  function mergeDedup(base: AgentLog[], incoming: AgentLog[]): AgentLog[] {
    if (incoming.length === 0) return base;
    const map = new Map<string, AgentLog>();
    for (const l of base) map.set(l.id, l);
    for (const l of incoming) map.set(l.id, l);
    // keep order by timestamp asc, then by id
    const arr = Array.from(map.values());
    arr.sort((a, b) => {
      const ta = Date.parse(a.ts);
      const tb = Date.parse(b.ts);
      if (ta !== tb) return ta - tb;
      return a.id.localeCompare(b.id);
    });
    return arr;
  }

  function trimBuffer(arr: AgentLog[], max: number): AgentLog[] {
    if (arr.length <= max) return arr;
    return arr.slice(arr.length - max);
  }

  // UI
  const [minLevel, setMinLevel] = useState<LogLevel | "all">("all");
  const applyMinLevel = useCallback((min: LogLevel | "all") => {
    setMinLevel(min);
    if (min === "all") {
      setLevel("all");
      return;
    }
    // auto-apply level filter to minimum and above
    setLevel("all");
  }, []);

  const minLevelPredicate = useCallback(
    (l: AgentLog) => {
      if (minLevel === "all") return true;
      return LEVEL_ORDER[l.level] >= LEVEL_ORDER[minLevel];
    },
    [minLevel]
  );

  const finalFiltered = useMemo(() => filtered.filter(minLevelPredicate), [filtered, minLevelPredicate]);

  // Rendered slice for virtualization (filtered list)
  const start = vVirtual.startIndex;
  const end = vVirtual.endIndex;
  const slice = finalFiltered.slice(start, end);

  return (
    <Card className="w-full">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-3">
          <CardTitle className="flex items-center gap-2">
            <TerminalSquare className="h-5 w-5" />
            Agent Logs
          </CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant={connected ? "default" : "secondary"} className="font-mono">
              {transport === "ws" ? (connected ? "WS connected" : "WS") : transport === "sse" ? (connected ? "SSE connected" : "SSE") : "offline"}
            </Badge>
            <div className="flex items-center gap-2">
              <Label htmlFor="follow" className="text-sm">Follow</Label>
              <Switch id="follow" checked={follow} onCheckedChange={onFollowToggle} />
            </div>
            <Button variant="outline" size="icon" onClick={onPauseToggle} aria-label="pause-resume">
              {paused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
            </Button>
            <Button variant="outline" size="icon" onClick={onClear} aria-label="clear">
              <Trash2 className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="icon" onClick={onExportJSON} aria-label="export-json" title="Export JSON">
              <Download className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="icon" onClick={onExportNDJSON} aria-label="export-ndjson" title="Export NDJSON">
              <Download className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-12">
          <div className="md:col-span-4">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 z-10 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="Search message, agent, source, context"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="search"
              />
            </div>
          </div>
          <div className="md:col-span-2">
            <Label className="sr-only">Level</Label>
            <Select value={level} onValueChange={(v) => setLevel(v as any)}>
              <SelectTrigger>
                <SelectValue placeholder="Level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Level: all</SelectItem>
                <SelectItem value="trace">trace</SelectItem>
                <SelectItem value="debug">debug</SelectItem>
                <SelectItem value="info">info</SelectItem>
                <SelectItem value="warn">warn</SelectItem>
                <SelectItem value="error">error</SelectItem>
                <SelectItem value="fatal">fatal</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="md:col-span-2">
            <Label className="sr-only">Min Level</Label>
            <Select value={minLevel} onValueChange={(v) => applyMinLevel(v as any)}>
              <SelectTrigger>
                <SelectValue placeholder="Min level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Min: all</SelectItem>
                <SelectItem value="trace">trace+</SelectItem>
                <SelectItem value="debug">debug+</SelectItem>
                <SelectItem value="info">info+</SelectItem>
                <SelectItem value="warn">warn+</SelectItem>
                <SelectItem value="error">error+</SelectItem>
                <SelectItem value="fatal">fatal+</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="md:col-span-2">
            <Label className="sr-only">Agent</Label>
            <Select value={agentFilter} onValueChange={(v) => setAgentFilter(v)}>
              <SelectTrigger>
                <SelectValue placeholder="Agent" />
              </SelectTrigger>
              <SelectContent>
                {agents.map((a) => (
                  <SelectItem key={a} value={a}>
                    Agent: {a}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="md:col-span-1">
            <Input
              type="datetime-local"
              value={fromTs}
              onChange={(e) => setFromTs(e.target.value)}
              aria-label="from"
              title="From"
            />
          </div>
          <div className="md:col-span-1">
            <Input
              type="datetime-local"
              value={toTs}
              onChange={(e) => setToTs(e.target.value)}
              aria-label="to"
              title="To"
            />
          </div>
        </div>
      </CardHeader>

      <CardContent>
        <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
          <ListFilter className="h-4 w-4" />
          Showing {finalFiltered.length.toLocaleString()} of {logs.length.toLocaleString()} logs
        </div>

        <div
          ref={containerRef}
          className="relative w-full rounded border bg-background"
          style={{ height }}
          role="list"
          aria-label="logs-container"
        >
          <div style={{ height: vVirtual.total, position: "relative" }}>
            <div style={{ transform: `translateY(${vVirtual.offsetY}px)` }}>
              {slice.length === 0 ? (
                <EmptyState connected={connected} transport={transport} />
              ) : (
                slice.map((log) => (
                  <LogRow key={log.id} log={log} compact={compact} onCopy={onCopy} />
                ))
              )}
            </div>
          </div>
        </div>

        <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            {connected ? <LinkIcon className="h-4 w-4" /> : <Link2Off className="h-4 w-4" />}
            Buffer {logs.length.toLocaleString()}/{maxBuffer.toLocaleString()}
          </div>
          <div className="flex items-center gap-2">
            {paused ? "Paused" : "Live"} • {follow ? "Following tail" : "Static view"}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------- Empty state ----------
function EmptyState({ connected, transport }: { connected: boolean; transport: TransportKind }) {
  return (
    <div className="flex h-[160px] items-center justify-center">
      <div className="text-center text-sm text-muted-foreground">
        <AlertTriangle className="mx-auto mb-2 h-5 w-5" />
        {connected
          ? "Нет записей, подходящих под фильтры."
          : transport === "none"
          ? "Источник не подключен. Укажите wsUrl или sseUrl."
          : "Ожидание данных от источника..."}
      </div>
    </div>
  );
}
