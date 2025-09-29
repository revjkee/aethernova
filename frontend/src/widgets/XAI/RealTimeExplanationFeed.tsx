import React, {useCallback, useEffect, useMemo, useReducer, useRef, useState} from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import {
  Activity,
  AlertCircle,
  CirclePause,
  CirclePlay,
  Filter,
  Link as LinkIcon,
  MousePointerClick,
  Network,
  RotateCcw,
  Search,
  ServerCrash,
  Settings2,
  Signal,
  Sparkles,
  Trash2,
} from "lucide-react";

/**
 * RealTimeExplanationFeed
 * Industrial-grade, accessible, XAI-focused streaming feed with SSE/WebSocket intake, robust typing, filters,
 * debounced search, auto-scroll, retention limits, and subtle XAI-metrics surfacing (confidence, latency, attributions, trace id).
 */

// ---------- Types ----------

export type AttributionVector = Record<string, number>; // feature -> importance

export type ExplanationLevel = "info" | "insight" | "warning" | "critical";

export interface ExplanationChunk {
  id: string;
  model?: string;
  source?: string; // e.g., component/module name
  timestamp: string; // ISO
  text: string;
  level: ExplanationLevel;
  confidence?: number; // 0..1
  latency_ms?: number;
  trace_id?: string;
  tags?: string[];
  attributions?: AttributionVector;
  reference_url?: string;
}

export interface StreamMessage {
  type: "explanation" | "heartbeat" | "control";
  payload?: ExplanationChunk;
}

export interface RealTimeExplanationFeedProps {
  /** Optional Server-Sent Events endpoint. If supplied, SSE is preferred. */
  sseUrl?: string;
  /** Optional WebSocket endpoint as fallback or primary if no sseUrl given. */
  wsUrl?: string;
  /** Max number of messages to retain in memory (for perf). */
  retention?: number;
  /** Initial filter for levels. */
  levels?: ExplanationLevel[];
  /** Initial tags filter (inclusive OR). */
  includeTags?: string[];
  /** Called when connection state changes. */
  onConnectionChange?: (state: ConnectionState) => void;
  /** Whether to start paused. */
  startPaused?: boolean;
  /** Provide external id for testability (DOM). */
  id?: string;
}

// ---------- Connection & State ----------

type ConnectionState = "disconnected" | "connecting" | "connected" | "error" | "paused";

interface FeedState {
  items: ExplanationChunk[];
  connected: ConnectionState;
  levelFilter: Set<ExplanationLevel>;
  tagFilter: Set<string>;
  query: string;
  autoScroll: boolean;
}

type FeedAction =
  | { type: "connected" }
  | { type: "connecting" }
  | { type: "paused" }
  | { type: "error" }
  | { type: "disconnected" }
  | { type: "push"; item: ExplanationChunk; retention: number }
  | { type: "clear" }
  | { type: "toggleLevel"; level: ExplanationLevel }
  | { type: "toggleTag"; tag: string }
  | { type: "query"; value: string }
  | { type: "autoscroll"; value: boolean };

const initialState = (levels?: ExplanationLevel[], tags?: string[]): FeedState => ({
  items: [],
  connected: "disconnected",
  levelFilter: new Set(levels && levels.length ? levels : ["info", "insight", "warning", "critical"]),
  tagFilter: new Set(tags ?? []),
  query: "",
  autoScroll: true,
});

function feedReducer(state: FeedState, action: FeedAction): FeedState {
  switch (action.type) {
    case "connecting":
      return { ...state, connected: "connecting" };
    case "connected":
      return { ...state, connected: "connected" };
    case "paused":
      return { ...state, connected: "paused" };
    case "error":
      return { ...state, connected: "error" };
    case "disconnected":
      return { ...state, connected: "disconnected" };
    case "push": {
      const next = [action.item, ...state.items];
      if (next.length > action.retention) next.length = action.retention;
      return { ...state, items: next };
    }
    case "clear":
      return { ...state, items: [] };
    case "toggleLevel": {
      const next = new Set(state.levelFilter);
      if (next.has(action.level)) next.delete(action.level); else next.add(action.level);
      return { ...state, levelFilter: next };
    }
    case "toggleTag": {
      const next = new Set(state.tagFilter);
      if (next.has(action.tag)) next.delete(action.tag); else next.add(action.tag);
      return { ...state, tagFilter: next };
    }
    case "query":
      return { ...state, query: action.value };
    case "autoscroll":
      return { ...state, autoScroll: action.value };
    default:
      return state;
  }
}

// ---------- Utilities ----------

const cn = (...classes: (string | undefined | false)[]) => classes.filter(Boolean).join(" ");

function formatTimeAgo(iso: string): string {
  const d = new Date(iso).getTime();
  const diff = Date.now() - d;
  if (diff < 1000) return "now";
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function levelTheme(level: ExplanationLevel): { badge: string; dot: string; label: string } {
  switch (level) {
    case "info":
      return { badge: "bg-secondary text-secondary-foreground", dot: "bg-muted", label: "Info" };
    case "insight":
      return { badge: "bg-blue-500/15 text-blue-600 dark:text-blue-400", dot: "bg-blue-500", label: "Insight" };
    case "warning":
      return { badge: "bg-amber-500/15 text-amber-600 dark:text-amber-400", dot: "bg-amber-500", label: "Warning" };
    case "critical":
      return { badge: "bg-red-500/15 text-red-600 dark:text-red-400", dot: "bg-red-500", label: "Critical" };
  }
}

function clamp01(n?: number): number | undefined {
  if (n == null) return undefined;
  return Math.max(0, Math.min(1, n));
}

function miniAttributionBars(attrs?: AttributionVector): { key: string; value: number }[] {
  if (!attrs) return [];
  const entries = Object.entries(attrs).map(([k, v]) => ({ key: k, value: v }));
  // normalize to 0..1
  const max = Math.max(0.00001, ...entries.map(e => Math.abs(e.value)));
  return entries
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 8)
    .map(e => ({ key: e.key, value: Math.abs(e.value) / max }));
}

// ---------- Component ----------

export const RealTimeExplanationFeed: React.FC<RealTimeExplanationFeedProps> = ({
  sseUrl,
  wsUrl,
  retention = 500,
  levels,
  includeTags,
  onConnectionChange,
  startPaused,
  id,
}) => {
  const [state, dispatch] = useReducer(feedReducer, initialState(levels, includeTags));
  const [paused, setPaused] = useState<boolean>(!!startPaused);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<number>(0);

  // Derived filters
  const filtered = useMemo(() => {
    const q = state.query.trim().toLowerCase();
    const hasTags = state.tagFilter.size > 0;
    return state.items.filter(item => {
      if (!state.levelFilter.has(item.level)) return false;
      if (hasTags && !(item.tags || []).some(t => state.tagFilter.has(t))) return false;
      if (!q) return true;
      return (
        item.text.toLowerCase().includes(q) ||
        (item.model?.toLowerCase().includes(q) ?? false) ||
        (item.source?.toLowerCase().includes(q) ?? false) ||
        (item.tags?.some(t => t.toLowerCase().includes(q)) ?? false) ||
        (item.trace_id?.toLowerCase().includes(q) ?? false)
      );
    });
  }, [state.items, state.levelFilter, state.tagFilter, state.query]);

  // Auto-scroll when new items if enabled and not paused
  useEffect(() => {
    if (!state.autoScroll || paused) return;
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [filtered.length, state.autoScroll, paused]);

  // Connection state notification
  useEffect(() => {
    onConnectionChange?.(state.connected);
  }, [state.connected, onConnectionChange]);

  const closeStreams = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (paused) return; // will connect on unpause
    dispatch({ type: "connecting" });
    closeStreams();

    const onItem = (item: ExplanationChunk) => {
      dispatch({ type: "push", item, retention });
    };

    const onError = () => {
      dispatch({ type: "error" });
      // simple backoff
      retryRef.current = Math.min(30_000, (retryRef.current || 1000) * 2);
      setTimeout(() => connect(), retryRef.current);
    };

    const onOpen = () => {
      retryRef.current = 0;
      dispatch({ type: "connected" });
    };

    if (sseUrl) {
      try {
        const es = new EventSource(sseUrl);
        esRef.current = es;
        es.onopen = onOpen;
        es.onerror = onError;
        es.onmessage = (ev) => {
          try {
            const msg: StreamMessage = JSON.parse(ev.data);
            if (msg.type === "explanation" && msg.payload) onItem(msg.payload);
          } catch { /* ignore malformed */ }
        };
        return;
      } catch {
        // fallthrough to WS
      }
    }

    if (wsUrl) {
      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;
        ws.onopen = onOpen;
        ws.onerror = onError;
        ws.onclose = () => dispatch({ type: "disconnected" });
        ws.onmessage = (ev) => {
          try {
            const msg: StreamMessage = JSON.parse(ev.data);
            if (msg.type === "explanation" && msg.payload) onItem(msg.payload);
          } catch { /* ignore malformed */ }
        };
        return;
      } catch {
        dispatch({ type: "error" });
      }
    }
  }, [sseUrl, wsUrl, retention, paused, closeStreams]);

  // Lifecycle connect/disconnect
  useEffect(() => {
    if (!paused) connect();
    return () => closeStreams();
  }, [connect, paused, closeStreams]);

  // Pause/Resume
  const handlePauseToggle = useCallback((next: boolean) => {
    setPaused(next);
    if (next) {
      dispatch({ type: "paused" });
      closeStreams();
    } else {
      dispatch({ type: "connecting" });
      connect();
    }
  }, [connect, closeStreams]);

  const uniqueTags = useMemo(() => {
    const set = new Set<string>();
    state.items.forEach(i => (i.tags || []).forEach(t => set.add(t)));
    return Array.from(set).sort();
  }, [state.items]);

  // ---------- Render helpers ----------

  const HeaderControls = (
    <div className="flex w-full items-center gap-2 flex-wrap">
      <TooltipProvider>
        <div className="flex items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant={paused ? "default" : "secondary"}
                size="sm"
                onClick={() => handlePauseToggle(!paused)}
                aria-pressed={paused}
              >
                {paused ? <CirclePlay className="mr-2 h-4 w-4" /> : <CirclePause className="mr-2 h-4 w-4" />}
                {paused ? "Resume" : "Pause"}
              </Button>
            </TooltipTrigger>
            <TooltipContent>Приостановить/возобновить поток</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="sm" onClick={() => dispatch({ type: "clear" })}>
                <Trash2 className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Очистить ленту</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="sm" onClick={() => connect()}>
                <RotateCcw className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Переподключиться</TooltipContent>
          </Tooltip>
        </div>

        <Separator orientation="vertical" className="h-6" />

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              className="pl-8 w-64"
              placeholder="Поиск: текст, модель, тег, trace id"
              value={state.query}
              onChange={(e) => dispatch({ type: "query", value: e.target.value })}
            />
          </div>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Filter className="mr-2 h-4 w-4" /> Фильтры
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuLabel className="flex items-center gap-2"><Settings2 className="h-4 w-4" /> Уровни</DropdownMenuLabel>
              <DropdownMenuCheckboxItem
                checked={state.levelFilter.has("info")}
                onCheckedChange={() => dispatch({ type: "toggleLevel", level: "info" })}
              >Info</DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem
                checked={state.levelFilter.has("insight")}
                onCheckedChange={() => dispatch({ type: "toggleLevel", level: "insight" })}
              >Insight</DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem
                checked={state.levelFilter.has("warning")}
                onCheckedChange={() => dispatch({ type: "toggleLevel", level: "warning" })}
              >Warning</DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem
                checked={state.levelFilter.has("critical")}
                onCheckedChange={() => dispatch({ type: "toggleLevel", level: "critical" })}
              >Critical</DropdownMenuCheckboxItem>
              <DropdownMenuSeparator />
              <DropdownMenuLabel className="flex items-center gap-2"><Sparkles className="h-4 w-4" /> Теги</DropdownMenuLabel>
              {uniqueTags.length === 0 ? (
                <div className="px-2 py-1 text-sm text-muted-foreground">Нет тегов</div>
              ) : (
                uniqueTags.map(tag => (
                  <DropdownMenuCheckboxItem
                    key={tag}
                    checked={state.tagFilter.has(tag)}
                    onCheckedChange={() => dispatch({ type: "toggleTag", tag })}
                  >{tag}</DropdownMenuCheckboxItem>
                ))
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          <div className="flex items-center gap-2 px-2">
            <span className="text-sm text-muted-foreground">Auto-scroll</span>
            <Switch checked={state.autoScroll} onCheckedChange={(v) => dispatch({ type: "autoscroll", value: v })} />
          </div>
        </div>

        <div className="ml-auto flex items-center gap-3 text-sm text-muted-foreground">
          <div className="flex items-center gap-1">
            <Network className="h-4 w-4" />
            <span>{state.connected}</span>
          </div>
          <Separator orientation="vertical" className="h-6" />
          <div className="flex items-center gap-1">
            <Activity className="h-4 w-4" />
            <span>{filtered.length} / {state.items.length}</span>
          </div>
        </div>
      </TooltipProvider>
    </div>
  );

  return (
    <Card id={id} className="w-full border-border/60 shadow-sm">
      <CardHeader className="space-y-2">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-xl">
            <MousePointerClick className="h-5 w-5" /> Real-time XAI Feed
          </CardTitle>
          <div className="flex items-center gap-2">
            {state.connected === "error" && (
              <Badge variant="destructive" className="flex items-center gap-1"><ServerCrash className="h-3 w-3" /> Ошибка</Badge>
            )}
            {state.connected === "connected" && (
              <Badge className="bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 flex items-center gap-1"><Signal className="h-3 w-3" /> Live</Badge>
            )}
            {state.connected === "paused" && (
              <Badge className="bg-zinc-500/15 text-zinc-600 dark:text-zinc-300">Paused</Badge>
            )}
          </div>
        </div>
        {HeaderControls}
      </CardHeader>

      <CardContent className="pt-0">
        <ScrollArea className="h-[560px] pr-3">
          <div className="flex flex-col gap-2">
            <AnimatePresence initial={false}>
              {filtered.map((item) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 6 }}
                  transition={{ type: "spring", stiffness: 380, damping: 28, mass: 0.5 }}
                >
                  <FeedRow item={item} />
                </motion.div>
              ))}
            </AnimatePresence>
            <div ref={bottomRef} />
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

// ---------- Row Component ----------

interface FeedRowProps { item: ExplanationChunk }

const FeedRow: React.FC<FeedRowProps> = ({ item }) => {
  const theme = levelTheme(item.level);
  const bars = miniAttributionBars(item.attributions);
  const conf = clamp01(item.confidence);

  return (
    <div
      className={cn(
        "rounded-2xl border p-3 md:p-4 shadow-sm",
        "border-border/60 bg-background/60 hover:bg-muted/40 transition-colors",
      )}
      role="article"
      aria-label={`explanation ${item.level}`}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className={cn("h-2 w-2 rounded-full", theme.dot)} />
        <Badge className={cn("capitalize", theme.badge)}>{theme.label}</Badge>
        {item.model && <Badge variant="secondary" className="capitalize">{item.model}</Badge>}
        {item.source && <Badge variant="outline">{item.source}</Badge>}
        {(item.tags || []).slice(0, 4).map(t => (
          <Badge key={t} variant="outline" className="text-xs">#{t}</Badge>
        ))}
        <div className="ml-auto flex items-center gap-3 text-xs text-muted-foreground">
          {typeof item.latency_ms === "number" && (
            <span className="flex items-center gap-1"><Activity className="h-3 w-3" /> {item.latency_ms} ms</span>
          )}
          <span>{formatTimeAgo(item.timestamp)}</span>
        </div>
      </div>

      <div className="mt-2 text-sm leading-relaxed">
        {item.text}
      </div>

      <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Confidence</span>
          <div className="flex-1"><Progress value={(conf ?? 0) * 100} aria-label="confidence" /></div>
          {conf != null && <span className="text-xs tabular-nums">{Math.round(conf * 100)}%</span>}
        </div>
        <div className="md:col-span-2">
          {bars.length > 0 ? (
            <div>
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>Top attributions</span>
                {item.trace_id && (
                  <span className="flex items-center gap-1"><LinkIcon className="h-3 w-3" /> trace: {item.trace_id}</span>
                )}
              </div>
              <div className="mt-1 grid grid-cols-8 gap-2">
                {bars.map(b => (
                  <TooltipProvider key={b.key}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div className="flex flex-col items-center gap-1">
                          <div className="h-12 w-full rounded bg-primary/15">
                            <div className="w-full rounded-b bg-primary" style={{ height: `${Math.max(6, Math.floor(b.value * 100))}%` }} />
                          </div>
                          <span className="truncate text-[10px] text-muted-foreground w-full" title={b.key}>{b.key}</span>
                        </div>
                      </TooltipTrigger>
                      <TooltipContent>
                        <span>{b.key}: {(b.value * 100).toFixed(0)}%</span>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-xs text-muted-foreground flex items-center gap-1"><AlertCircle className="h-3 w-3" /> Нет данных атрибуции</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RealTimeExplanationFeed;
