/*
 * Path: frontend/src/widgets/Security/AIIncidentTimeline.tsx
 * Industrial-grade incident timeline for AI/security events.
 * Tech: React + TypeScript, Tailwind, shadcn/ui, framer-motion, lucide-react, optional Recharts sparkline.
 * No runtime external deps beyond the above UI libs. Safe to tree-shake.
 */

'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { FC } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  Brain,
  Filter,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldAlert,
  Wifi,
  WifiOff,
  ChevronDown,
  ExternalLink,
} from 'lucide-react';

// shadcn/ui
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuCheckboxItem, DropdownMenuLabel } from '@/components/ui/dropdown-menu';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';

// Recharts is optional. We guard dynamic import to avoid hard dependency.
let Recharts: any = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  Recharts = require('recharts');
} catch (_) {
  Recharts = null;
}

/**
 * Types
 */
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IncidentKind = 'model' | 'data' | 'security' | 'governance' | 'infra';

export interface IncidentRecord {
  id: string;
  ts: string; // ISO date
  title: string;
  summary?: string;
  severity: IncidentSeverity;
  kind: IncidentKind;
  source?: string; // system/source id
  tags?: string[];
  link?: string; // deep-link to details
  meta?: Record<string, unknown>;
}

export interface FetchBatch {
  items: IncidentRecord[];
  nextCursor?: string | null; // for pagination if needed
}

export type DataSource =
  | string // GET url returning FetchBatch or IncidentRecord[]
  | ((params: { cursor?: string | null; since?: string | null }) => Promise<FetchBatch | IncidentRecord[]>);

export interface AIIncidentTimelineProps {
  dataSource: DataSource;
  height?: number; // px, default 560
  live?: boolean; // enable SSE if dataSource is URL ("/api/incidents/stream")
  liveStreamUrl?: string; // optional SSE url; if not provided and live=true, attempts `${dataSource}/stream`
  defaultSeverities?: IncidentSeverity[];
  defaultKinds?: IncidentKind[];
  timeFrom?: string | null; // ISO lower bound
  onSelect?: (incident: IncidentRecord) => void;
  className?: string;
}

/**
 * Utilities
 */
const SEVERITY_ORDER: Record<IncidentSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const severityColor: Record<IncidentSeverity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-amber-500 text-black',
  low: 'bg-emerald-600 text-white',
  info: 'bg-slate-600 text-white',
};

const kindIcon: Record<IncidentKind, React.ReactNode> = {
  model: <Brain className="h-3.5 w-3.5" />,
  data: <ShieldCheck className="h-3.5 w-3.5" />, // reuse icon
  security: <ShieldAlert className="h-3.5 w-3.5" />,
  governance: <AlertTriangle className="h-3.5 w-3.5" />,
  infra: <Wifi className="h-3.5 w-3.5" />,
};

function cn(...classes: Array<string | undefined | false | null>) {
  return classes.filter(Boolean).join(' ');
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(d);
  } catch {
    return ts;
  }
}

/**
 * Simple in-place virtualization (windowed list) without external deps.
 * Works best for uniform-ish item heights. We keep it robust with overscan.
 */
function useVirtual<T>(items: T[], rowHeight = 80, viewportHeight = 560, overscan = 6) {
  const [scrollTop, setScrollTop] = useState(0);
  const total = items.length * rowHeight;
  const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const endIndex = Math.min(items.length - 1, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan);

  const visible = items.slice(startIndex, endIndex + 1);
  const offsetTop = startIndex * rowHeight;

  const onScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop((e.currentTarget as HTMLDivElement).scrollTop);
  }, []);

  return { visible, offsetTop, total, onScroll };
}

/**
 * Data fetching helpers
 */
async function fetchIncidents(ds: DataSource, params: { cursor?: string | null; since?: string | null }): Promise<FetchBatch> {
  if (typeof ds === 'string') {
    const url = new URL(ds, window.location.origin);
    if (params.cursor) url.searchParams.set('cursor', String(params.cursor));
    if (params.since) url.searchParams.set('since', String(params.since));
    const r = await fetch(url.toString(), { headers: { 'Accept': 'application/json' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const json = await r.json();
    if (Array.isArray(json)) return { items: json };
    return json as FetchBatch;
  }
  const res = await ds(params);
  return Array.isArray(res) ? { items: res } : res;
}

/**
 * Main component
 */
export const AIIncidentTimeline: FC<AIIncidentTimelineProps> = ({
  dataSource,
  height = 560,
  live = false,
  liveStreamUrl,
  defaultSeverities = ['critical', 'high', 'medium', 'low', 'info'],
  defaultKinds = ['model', 'data', 'security', 'governance', 'infra'],
  timeFrom = null,
  onSelect,
  className,
}) => {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [q, setQ] = useState('');
  const [severities, setSeverities] = useState<IncidentSeverity[]>(defaultSeverities);
  const [kinds, setKinds] = useState<IncidentKind[]>(defaultKinds);
  const [online, setOnline] = useState(true);

  // Debounce search input
  const [qDebounced, setQDebounced] = useState(q);
  useEffect(() => {
    const h = setTimeout(() => setQDebounced(q.trim().toLowerCase()), 250);
    return () => clearTimeout(h);
  }, [q]);

  const viewportRef = useRef<HTMLDivElement | null>(null);

  const filtered = useMemo(() => {
    const sinceTs = timeFrom ? Date.parse(timeFrom) : null;
    return incidents.filter((i) => {
      if (!severities.includes(i.severity)) return false;
      if (!kinds.includes(i.kind)) return false;
      if (sinceTs && Date.parse(i.ts) < sinceTs) return false;
      if (!qDebounced) return true;
      const hay = `${i.title} ${i.summary ?? ''} ${i.tags?.join(' ') ?? ''} ${i.kind} ${i.severity}`.toLowerCase();
      return hay.includes(qDebounced);
    });
  }, [incidents, severities, kinds, qDebounced, timeFrom]);

  const rowHeight = 92; // tuned for timeline item
  const { visible, offsetTop, total, onScroll } = useVirtual(filtered, rowHeight, height);

  // Initial fetch
  const loadInitial = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchIncidents(dataSource, { cursor: null, since: timeFrom });
      const items = [...res.items].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
      setIncidents(items);
      setCursor(res.nextCursor ?? null);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [dataSource, timeFrom]);

  useEffect(() => {
    void loadInitial();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataSource, timeFrom]);

  // Pagination on scroll bottom
  const handleScroll = useCallback(async (e: React.UIEvent<HTMLDivElement>) => {
    onScroll(e);
    const el = e.currentTarget;
    if (!cursor || loading) return;
    const nearBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 200;
    if (nearBottom) {
      setLoading(true);
      try {
        const res = await fetchIncidents(dataSource, { cursor, since: timeFrom });
        const merged = [...incidents, ...res.items];
        merged.sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
        // de-dup by id
        const uniq = Array.from(new Map(merged.map((x) => [x.id, x])).values());
        setIncidents(uniq);
        setCursor(res.nextCursor ?? null);
      } catch (e: any) {
        setError(e?.message ?? 'Failed to load more');
      } finally {
        setLoading(false);
      }
    }
  }, [cursor, dataSource, incidents, loading, onScroll, timeFrom]);

  // Live updates via SSE (if URL)
  useEffect(() => {
    if (!live) return;
    if (typeof window === 'undefined') return;

    const url = (() => {
      if (liveStreamUrl) return liveStreamUrl;
      if (typeof dataSource === 'string') return `${dataSource.replace(/\/$/, '')}/stream`;
      return null;
    })();

    if (!url) return;

    let es: EventSource | null = null;
    try {
      es = new EventSource(url);
      setOnline(true);
      es.onmessage = (ev) => {
        try {
          const item: IncidentRecord | IncidentRecord[] = JSON.parse(ev.data);
          const arr = Array.isArray(item) ? item : [item];
          if (!arr.length) return;
          setIncidents((prev) => {
            const merged = [...arr, ...prev];
            merged.sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
            return Array.from(new Map(merged.map((x) => [x.id, x])).values());
          });
        } catch {}
      };
      es.onerror = () => setOnline(false);
    } catch {
      setOnline(false);
    }
    return () => {
      try { es?.close(); } catch {}
    };
  }, [live, liveStreamUrl, dataSource]);

  // Sparkline data (last 24 buckets)
  const sparkline = useMemo(() => {
    const buckets = new Map<string, number>();
    const now = Date.now();
    const stepMs = 60 * 60 * 1000; // 1h
    for (let i = 23; i >= 0; i--) {
      const t = new Date(now - i * stepMs);
      const key = t.toISOString().slice(0, 13) + ':00';
      buckets.set(key, 0);
    }
    for (const it of incidents) {
      const key = new Date(it.ts).toISOString().slice(0, 13) + ':00';
      if (buckets.has(key)) buckets.set(key, (buckets.get(key) || 0) + 1);
    }
    return Array.from(buckets.entries()).map(([k, v]) => ({ t: k, v }));
  }, [incidents]);

  // UI helpers
  const toggleSeverity = (s: IncidentSeverity) => {
    setSeverities((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));
  };
  const toggleKind = (k: IncidentKind) => {
    setKinds((prev) => (prev.includes(k) ? prev.filter((x) => x !== k) : [...prev, k]));
  };

  const resetFilters = () => {
    setSeverities(defaultSeverities);
    setKinds(defaultKinds);
    setQ('');
  };

  // Render
  return (
    <Card className={cn('w-full', className)} aria-label="AI Incident Timeline">
      <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <Brain className="h-5 w-5" />
          <CardTitle className="text-xl">AI Incident Timeline</CardTitle>
          <Badge variant="outline" className="ml-2">{incidents.length} events</Badge>
          <Separator orientation="vertical" className="mx-2 h-6" />
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className={cn('flex items-center gap-1 text-xs', online ? 'text-emerald-600' : 'text-red-600')}>
                  {online ? <Wifi className="h-4 w-4" /> : <WifiOff className="h-4 w-4" />}
                  <span>{online ? 'live' : 'offline'}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>Потоковые обновления SSE {online ? 'активны' : 'недоступны'}</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Поиск по заголовку, тегам, описанию"
              className="pl-8 w-64"
              aria-label="Поиск инцидентов"
            />
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          </div>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2"><Filter className="h-4 w-4" />Фильтры<ChevronDown className="h-4 w-4" /></Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel>Уровень</DropdownMenuLabel>
              {(['critical','high','medium','low','info'] as IncidentSeverity[]).map((s) => (
                <DropdownMenuCheckboxItem key={s} checked={severities.includes(s)} onCheckedChange={() => toggleSeverity(s)}>
                  <span className={cn('inline-block h-2 w-2 rounded-full mr-2',
                    s==='critical' && 'bg-red-600', s==='high' && 'bg-orange-600', s==='medium' && 'bg-amber-500', s==='low' && 'bg-emerald-600', s==='info' && 'bg-slate-600'
                  )} /> {s}
                </DropdownMenuCheckboxItem>
              ))}
              <Separator className="my-2" />
              <DropdownMenuLabel>Тип</DropdownMenuLabel>
              {(['model','data','security','governance','infra'] as IncidentKind[]).map((k) => (
                <DropdownMenuCheckboxItem key={k} checked={kinds.includes(k)} onCheckedChange={() => toggleKind(k)}>
                  <span className="mr-2 inline-flex items-center">{kindIcon[k as IncidentKind]}</span> {k}
                </DropdownMenuCheckboxItem>
              ))}
              <Separator className="my-2" />
              <div className="px-2 py-1.5 flex justify-between items-center">
                <Button variant="ghost" size="sm" onClick={resetFilters}>Сбросить</Button>
                <Button variant="outline" size="icon" onClick={() => void loadInitial()} aria-label="Обновить">
                  <RefreshCw className="h-4 w-4" />
                </Button>
              </div>
            </DropdownMenuContent>
          </DropdownMenu>

          <div className="flex items-center gap-2 pl-2">
            <Switch id="live" checked={live} disabled className="cursor-not-allowed opacity-60" />
            <Label htmlFor="live" className="text-xs">Live</Label>
          </div>
        </div>
      </CardHeader>

      {/* Optional sparkline */}
      {Recharts ? (
        <div className="px-4 pb-2">
          <div className="text-xs text-muted-foreground mb-1">Инциденты за 24ч</div>
          <Recharts.ResponsiveContainer width="100%" height={48}>
            <Recharts.AreaChart data={sparkline} margin={{ left: 0, right: 0, top: 4, bottom: 0 }}>
              <Recharts.Area type="monotone" dataKey="v" fillOpacity={0.2} />
              <Recharts.YAxis hide domain={[0, 'dataMax + 2']} />
              <Recharts.XAxis hide dataKey="t" />
              <Recharts.Tooltip formatter={(v: number) => [`${v}`, 'events']} labelFormatter={(l: string) => l} />
            </Recharts.AreaChart>
          </Recharts.ResponsiveContainer>
        </div>
      ) : null}

      <CardContent className="pt-0">
        <div
          ref={viewportRef}
          style={{ height }}
          className="relative overflow-auto rounded-xl border bg-background"
          onScroll={handleScroll}
          role="list"
          aria-label="Список инцидентов"
        >
          <div style={{ height: total }} className="relative">
            <div style={{ transform: `translateY(${offsetTop}px)` }}>
              <AnimatePresence initial={false}>
                {visible.map((it) => (
                  <motion.div
                    key={it.id}
                    layout
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.12 }}
                    role="listitem"
                    aria-label={`Инцидент ${it.title}`}
                  >
                    <TimelineItem record={it} onSelect={onSelect} />
                    <Separator />
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </div>
          {loading && (
            <div className="absolute bottom-2 left-1/2 -translate-x-1/2 rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">
              Загрузка…
            </div>
          )}
          {error && (
            <div className="absolute bottom-2 left-2 right-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          {filtered.length === 0 && !loading && !error && (
            <div className="absolute inset-0 grid place-items-center text-sm text-muted-foreground">
              Нет данных по текущим фильтрам
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

/**
 * Timeline row component
 */
const TimelineItem: FC<{ record: IncidentRecord; onSelect?: (i: IncidentRecord) => void }> = ({ record, onSelect }) => {
  const sClr = severityColor[record.severity];
  const icon = kindIcon[record.kind];

  return (
    <div className="flex items-start gap-3 px-4 py-3">
      <div className="mt-1">
        <div className={cn('h-2.5 w-2.5 rounded-full',
          record.severity === 'critical' && 'bg-red-600',
          record.severity === 'high' && 'bg-orange-600',
          record.severity === 'medium' && 'bg-amber-500',
          record.severity === 'low' && 'bg-emerald-600',
          record.severity === 'info' && 'bg-slate-600',
        )} />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onSelect?.(record)}
            className="truncate text-left font-medium hover:underline"
          >
            {record.title}
          </button>
          <Badge className={cn('capitalize', sClr)}>{record.severity}</Badge>
          <Badge variant="outline" className="capitalize gap-1">{icon}{record.kind}</Badge>
          {record.tags?.slice(0, 3).map((t) => (
            <Badge key={t} variant="secondary" className="capitalize">{t}</Badge>
          ))}
        </div>
        {record.summary ? (
          <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{record.summary}</p>
        ) : null}
        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span>{formatTime(record.ts)}</span>
          {record.source && (
            <span className="rounded bg-muted px-1.5 py-0.5">{record.source}</span>
          )}
          {record.link && (
            <a
              className="inline-flex items-center gap-1 underline-offset-2 hover:underline"
              href={record.link}
              target="_blank"
              rel="noreferrer noopener"
              aria-label="Открыть детали"
            >
              Подробнее <ExternalLink className="h-3.5 w-3.5" />
            </a>
          )}
        </div>
      </div>
    </div>
  );
};

export default AIIncidentTimeline;
