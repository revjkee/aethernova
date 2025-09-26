// frontend/src/widgets/Governance/ProposalTimeline.tsx
import * as React from "react";
import { memo, useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import {
  CalendarDays,
  CheckCircle2,
  ChevronsDown,
  ChevronsUp,
  CircleSlash2,
  CircleCheckBig,
  Clock4,
  Dot,
  FileCheck2,
  FileEdit,
  FilePlus2,
  Gavel,
  Hash,
  Info,
  LineChart,
  ListFilter,
  Loader2,
  PartyPopper,
  Search,
  ShieldCheck,
  TriangleAlert,
  XCircle,
} from "lucide-react";

type VoteSupport = "for" | "against" | "abstain";
export type ProposalEventType =
  | "CREATED"
  | "UPDATED"
  | "VOTING_START"
  | "VOTE"
  | "QUORUM"
  | "SUCCEEDED"
  | "EXECUTED"
  | "DEFEATED"
  | "CANCELED";

export interface ProposalEvent {
  id: string;
  type: ProposalEventType;
  timestamp: string | number | Date; // ISO, epoch, or Date
  actor?: string; // e.g., 0x..., ENS, username
  txHash?: string;
  details?: string; // free text
  support?: VoteSupport; // for vote events
  weight?: number; // voting power for a vote
  quorum?: { current: number; required: number }; // for QUORUM events
  metadata?: Record<string, unknown>;
}

export interface ProposalTimelineProps {
  events: ProposalEvent[];
  loading?: boolean;
  error?: string | null;
  compact?: boolean;
  groupByDay?: boolean;
  showLegend?: boolean;
  timezone?: string; // IANA tz, e.g. "Europe/Riga"
  txExplorerBaseUrl?: string; // e.g., "https://etherscan.io/tx/"
  initialFilters?: Partial<Record<ProposalEventType, boolean>>;
  onSelectEvent?: (evt: ProposalEvent) => void;
  // Optional search over text fields (actor/details)
  enableSearch?: boolean;
  // Accessibility: custom aria-labels
  ariaLabel?: string;
}

/** ---------- Utilities ---------- */

// Safely build className strings.
function cn(...v: Array<string | false | null | undefined>) {
  return v.filter(Boolean).join(" ");
}

const EVENT_LABELS: Record<ProposalEventType, string> = {
  CREATED: "Created",
  UPDATED: "Updated",
  VOTING_START: "Voting started",
  VOTE: "Vote cast",
  QUORUM: "Quorum reached",
  SUCCEEDED: "Succeeded",
  EXECUTED: "Executed",
  DEFEATED: "Defeated",
  CANCELED: "Canceled",
};

const TYPE_ICON: Record<ProposalEventType, React.ReactNode> = {
  CREATED: <FilePlus2 className="h-4 w-4" aria-hidden />,
  UPDATED: <FileEdit className="h-4 w-4" aria-hidden />,
  VOTING_START: <Gavel className="h-4 w-4" aria-hidden />,
  VOTE: <CheckCircle2 className="h-4 w-4" aria-hidden />,
  QUORUM: <ShieldCheck className="h-4 w-4" aria-hidden />,
  SUCCEEDED: <CircleCheckBig className="h-4 w-4" aria-hidden />,
  EXECUTED: <PartyPopper className="h-4 w-4" aria-hidden />,
  DEFEATED: <XCircle className="h-4 w-4" aria-hidden />,
  CANCELED: <CircleSlash2 className="h-4 w-4" aria-hidden />,
};

const TYPE_BADGE_VARIANT: Record<ProposalEventType, "default" | "secondary" | "outline" | "destructive"> = {
  CREATED: "secondary",
  UPDATED: "secondary",
  VOTING_START: "default",
  VOTE: "outline",
  QUORUM: "default",
  SUCCEEDED: "default",
  EXECUTED: "default",
  DEFEATED: "destructive",
  CANCELED: "destructive",
};

function isValidDate(d: Date) {
  return d instanceof Date && !Number.isNaN(d.getTime());
}

function toDate(input: string | number | Date): Date {
  const d = input instanceof Date ? input : new Date(input);
  return isValidDate(d) ? d : new Date(0);
}

function formatDate(d: Date, tz?: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: tz,
  }).format(d);
}

function formatDay(d: Date, tz?: string) {
  return new Intl.DateTimeFormat(undefined, {
    weekday: "short",
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: tz,
  }).format(d);
}

function relativeTime(from: Date, now: Date) {
  const diff = Math.max(0, now.getTime() - from.getTime());
  const sec = Math.floor(diff / 1000);
  const min = Math.floor(sec / 60);
  const hrs = Math.floor(min / 60);
  const days = Math.floor(hrs / 24);
  if (sec < 60) return `${sec}s ago`;
  if (min < 60) return `${min}m ago`;
  if (hrs < 24) return `${hrs}h ago`;
  return `${days}d ago`;
}

function defaultFilters(): Record<ProposalEventType, boolean> {
  return {
    CREATED: true,
    UPDATED: true,
    VOTING_START: true,
    VOTE: true,
    QUORUM: true,
    SUCCEEDED: true,
    EXECUTED: true,
    DEFEATED: true,
    CANCELED: true,
  };
}

function uniqueId(prefix = "id") {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
}

/** ---------- Row (memoized) ---------- */

const TimelineRow = memo(function TimelineRow({
  evt,
  tz,
  compact,
  txExplorerBaseUrl,
  onSelect,
  now,
  tabIndex,
}: {
  evt: ProposalEvent;
  tz?: string;
  compact?: boolean;
  txExplorerBaseUrl?: string;
  onSelect?: (e: ProposalEvent) => void;
  now: Date;
  tabIndex: number;
}) {
  const d = toDate(evt.timestamp);
  const timeFull = formatDate(d, tz);
  const rel = relativeTime(d, now);

  const isVote = evt.type === "VOTE";
  const isQuorum = evt.type === "QUORUM";
  const label = EVENT_LABELS[evt.type];
  const icon = TYPE_ICON[evt.type];

  const handleClick = () => onSelect?.(evt);

  return (
    <motion.li
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      className="group relative pl-6"
      role="listitem"
      aria-label={`${label} at ${timeFull}`}
      tabIndex={-1}
    >
      {/* Connector & dot */}
      <span className="absolute left-0 top-2 h-full w-px bg-border" aria-hidden />
      <span className={cn(
        "absolute left-[-5px] top-2 h-2.5 w-2.5 rounded-full ring-2 ring-background",
        evt.type === "DEFEATED" || evt.type === "CANCELED" ? "bg-red-500" :
        evt.type === "SUCCEEDED" || evt.type === "EXECUTED" ? "bg-green-500" :
        evt.type === "QUORUM" ? "bg-emerald-500" :
        evt.type === "VOTE" ? "bg-blue-500" :
        evt.type === "VOTING_START" ? "bg-yellow-500" :
        "bg-muted-foreground"
      )} aria-hidden />

      <button
        type="button"
        onClick={handleClick}
        className={cn(
          "w-full text-left rounded-xl border bg-card transition-shadow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          "hover:shadow-md",
          compact ? "px-3 py-2" : "px-4 py-3"
        )}
        tabIndex={tabIndex}
        aria-describedby={`evt-${evt.id}-time`}
      >
        <div className={cn("flex items-start gap-3")}>
          <div className="mt-0.5">{icon}</div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant={TYPE_BADGE_VARIANT[evt.type]}>{label}</Badge>
              {evt.actor && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge variant="outline" className="font-mono" title={evt.actor}>
                        {shortAddr(evt.actor)}
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent>
                      <div className="text-xs">Actor</div>
                      <div className="font-mono text-xs">{evt.actor}</div>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
              {evt.txHash && txExplorerBaseUrl && (
                <a
                  className="inline-flex items-center gap-1 text-xs underline-offset-2 hover:underline"
                  href={`${txExplorerBaseUrl}${evt.txHash}`}
                  target="_blank"
                  rel="noreferrer"
                  aria-label="Open transaction in explorer"
                >
                  <Hash className="h-3 w-3" />
                  <span className="font-mono">{shortHash(evt.txHash)}</span>
                </a>
              )}
            </div>

            {evt.details && (
              <p className={cn("text-sm text-muted-foreground mt-1", compact && "line-clamp-2")}>
                {evt.details}
              </p>
            )}

            {isVote && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                <Badge variant={voteVariant(evt.support)} className="uppercase">
                  {evt.support ?? "N/A"}
                </Badge>
                {typeof evt.weight === "number" && (
                  <span className="text-muted-foreground">Weight: {formatNumber(evt.weight)}</span>
                )}
              </div>
            )}

            {isQuorum && evt.quorum && (
              <div className="mt-2">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-muted-foreground">Quorum progress</span>
                  <span className="font-mono">
                    {formatNumber(evt.quorum.current)} / {formatNumber(evt.quorum.required)}
                  </span>
                </div>
                <Progress value={quorumPercent(evt.quorum)} aria-label="Quorum progress" />
              </div>
            )}

            <div id={`evt-${evt.id}-time`} className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
              <Clock4 className="h-3.5 w-3.5" />
              <span>{timeFull}</span>
              <Dot className="h-3 w-3" />
              <span aria-label="relative time">{rel}</span>
            </div>
          </div>
        </div>
      </button>
    </motion.li>
  );
});

function shortAddr(s: string) {
  return s.length > 12 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s;
}
function shortHash(s: string) {
  return s.length > 14 ? `${s.slice(0, 8)}…${s.slice(-6)}` : s;
}
function voteVariant(s?: VoteSupport): "default" | "secondary" | "outline" | "destructive" {
  if (s === "for") return "default";
  if (s === "against") return "destructive";
  return "secondary";
}
function quorumPercent(q: { current: number; required: number }) {
  if (q.required <= 0) return 0;
  return Math.max(0, Math.min(100, (q.current / q.required) * 100));
}
function formatNumber(n: number) {
  try {
    return new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(n);
  } catch {
    return String(n);
  }
}

/** ---------- Legend ---------- */

function Legend({ tz }: { tz?: string }) {
  const items: Array<{ t: ProposalEventType; icon: React.ReactNode }> = ([
    "CREATED",
    "UPDATED",
    "VOTING_START",
    "VOTE",
    "QUORUM",
    "SUCCEEDED",
    "EXECUTED",
    "DEFEATED",
    "CANCELED",
  ] as ProposalEventType[]).map((t) => ({ t, icon: TYPE_ICON[t] }));

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <CalendarDays className="h-3.5 w-3.5 text-muted-foreground" />
      <span className="text-muted-foreground">Times shown in {tz ?? "local time"}</span>
      <Separator orientation="vertical" className="h-4" />
      {items.map(({ t, icon }) => (
        <span key={t} className="inline-flex items-center gap-1">
          {icon}
          <span className="text-muted-foreground">{EVENT_LABELS[t]}</span>
        </span>
      ))}
    </div>
  );
}

/** ---------- Filters ---------- */

function FilterPanel({
  state,
  onToggleAll,
  onToggleType,
  enableSearch,
  search,
  onSearch,
}: {
  state: Record<ProposalEventType, boolean>;
  onToggleAll: (v: boolean) => void;
  onToggleType: (t: ProposalEventType, v: boolean) => void;
  enableSearch?: boolean;
  search: string;
  onSearch: (v: string) => void;
}) {
  const allOn = Object.values(state).every(Boolean);
  const someOn = Object.values(state).some(Boolean);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ListFilter className="h-4 w-4" />
          <span className="text-sm font-medium">Filters</span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => onToggleAll(!allOn)}
            aria-pressed={allOn}
          >
            {allOn ? (
              <>
                <ChevronsDown className="h-4 w-4 mr-1" />
                Hide all
              </>
            ) : (
              <>
                <ChevronsUp className="h-4 w-4 mr-1" />
                Show all
              </>
            )}
          </Button>
        </div>
      </div>

      {enableSearch && (
        <div className="relative">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            className="pl-8"
            placeholder="Search by actor or details…"
            value={search}
            onChange={(e) => onSearch(e.target.value)}
            aria-label="Search events"
          />
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
        {(Object.keys(EVENT_LABELS) as ProposalEventType[]).map((t) => (
          <label key={t} className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={state[t]}
              onCheckedChange={(v) => onToggleType(t, Boolean(v))}
              aria-label={`Toggle ${EVENT_LABELS[t]}`}
            />
            <span className="inline-flex items-center gap-1">
              {TYPE_ICON[t]}
              {EVENT_LABELS[t]}
            </span>
          </label>
        ))}
      </div>

      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Info className="h-3.5 w-3.5" />
        Toggle event types to refine the timeline.
      </div>
    </div>
  );
}

/** ---------- Grouping ---------- */

function groupByDay(events: ProposalEvent[], tz?: string) {
  const map = new Map<string, ProposalEvent[]>();
  for (const e of events) {
    const d = toDate(e.timestamp);
    const key = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(d); // yyyy-mm-dd (almost)
    const normalized = key.replaceAll("/", "-");
    const arr = map.get(normalized) ?? [];
    arr.push(e);
    map.set(normalized, arr);
  }
  // Sort keys descending (newest group first)
  const keys = Array.from(map.keys()).sort((a, b) => (a < b ? 1 : -1));
  return keys.map((k) => ({
    key: k,
    label: formatDay(new Date(k), tz),
    events: (map.get(k) ?? []).sort(
      (a, b) => toDate(a.timestamp).getTime() - toDate(b.timestamp).getTime()
    ),
  }));
}

/** ---------- Main Component ---------- */

export default function ProposalTimeline({
  events,
  loading,
  error,
  compact,
  groupByDay: byDay = true,
  showLegend = true,
  timezone,
  txExplorerBaseUrl,
  initialFilters,
  onSelectEvent,
  enableSearch = true,
  ariaLabel = "Proposal timeline",
}: ProposalTimelineProps) {
  const [filters, setFilters] = useState<Record<ProposalEventType, boolean>>({
    ...defaultFilters(),
    ...(initialFilters || {}),
  });
  const [search, setSearch] = useState("");
  const nowRef = useRef(new Date());

  // Normalize & sort all events ascending by timestamp for stable grouping.
  const normalized = useMemo(() => {
    return [...events]
      .map((e) => ({ ...e, timestamp: toDate(e.timestamp) }))
      .sort((a, b) => toDate(a.timestamp).getTime() - toDate(b.timestamp).getTime());
  }, [events]);

  // Filter by type and search.
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return normalized.filter((e) => {
      if (!filters[e.type]) return false;
      if (!q) return true;
      const inActor = (e.actor ?? "").toLowerCase().includes(q);
      const inDetails = (e.details ?? "").toLowerCase().includes(q);
      const inType = EVENT_LABELS[e.type].toLowerCase().includes(q);
      return inActor || inDetails || inType;
    });
  }, [normalized, filters, search]);

  const grouped = useMemo(() => {
    return byDay ? groupByDay(filtered, timezone) : [{ key: "all", label: "All events", events: filtered }];
  }, [filtered, byDay, timezone]);

  // Keyboard navigation support
  const containerRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    function onKey(e: KeyboardEvent) {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      const focusables = Array.from(el.querySelectorAll<HTMLButtonElement>("button[role!='switch']"));
      const idx = focusables.findIndex((n) => n === document.activeElement);
      if (e.key === "ArrowDown") {
        const next = focusables[Math.min(focusables.length - 1, idx + 1)];
        next?.focus();
        e.preventDefault();
      } else {
        const prev = focusables[Math.max(0, idx - 1)];
        prev?.focus();
        e.preventDefault();
      }
    }
    el.addEventListener("keydown", onKey);
    return () => el.removeEventListener("keydown", onKey);
  }, [grouped]);

  // Handlers
  const toggleAll = (v: boolean) => {
    const f = defaultFilters();
    Object.keys(f).forEach((k) => (f[k as ProposalEventType] = v));
    setFilters(f);
  };
  const toggleType = (t: ProposalEventType, v: boolean) => {
    setFilters((s) => ({ ...s, [t]: v }));
  };

  // Derived states
  const emptyState = !loading && !error && filtered.length === 0;
  const now = nowRef.current;

  return (
    <Card aria-label={ariaLabel}>
      <CardHeader className="gap-2">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <LineChart className="h-5 w-5" />
              Proposal Timeline
            </CardTitle>
            <CardDescription>
              Chronological on-chain and governance events for the selected proposal.
            </CardDescription>
          </div>
          {showLegend && (
            <div className="hidden md:block">
              <Legend tz={timezone} />
            </div>
          )}
        </div>
        <div className="md:hidden">
          {showLegend && <Legend tz={timezone} />}
        </div>
      </CardHeader>

      <CardContent ref={containerRef}>
        <div className="mb-4">
          <FilterPanel
            state={filters}
            onToggleAll={toggleAll}
            onToggleType={toggleType}
            enableSearch={enableSearch}
            search={search}
            onSearch={setSearch}
          />
        </div>

        {loading && (
          <LoadingState compact={compact} />
        )}

        {!loading && error && (
          <ErrorState message={error} />
        )}

        {!loading && !error && (
          <>
            {emptyState ? (
              <EmptyState />
            ) : (
              <ScrollArea className={cn("max-h-[60vh] pr-2", compact ? "" : "md:max-h-[70vh]")}>
                <ul className="space-y-6" role="list" aria-live="polite">
                  <AnimatePresence initial={false}>
                    {grouped.map((g) => (
                      <motion.li
                        key={g.key}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -8 }}
                        className="space-y-3"
                        role="listitem"
                        aria-label={`Group ${g.label}`}
                      >
                        <div className="sticky top-0 z-10 bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60 rounded-md border px-2 py-1.5 inline-flex items-center gap-2 text-xs">
                          <CalendarDays className="h-3.5 w-3.5" />
                          <span className="font-medium">{g.label}</span>
                        </div>
                        <ul className="space-y-3" role="list">
                          {g.events.map((evt, i) => (
                            <TimelineRow
                              key={evt.id}
                              evt={evt}
                              tz={timezone}
                              compact={compact}
                              txExplorerBaseUrl={txExplorerBaseUrl}
                              onSelect={onSelectEvent}
                              now={now}
                              tabIndex={i === 0 ? 0 : -1}
                            />
                          ))}
                        </ul>
                      </motion.li>
                    ))}
                  </AnimatePresence>
                </ul>
              </ScrollArea>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

/** ---------- States ---------- */

function LoadingState({ compact }: { compact?: boolean }) {
  return (
    <div className="flex flex-col gap-3" role="status" aria-live="polite">
      {[...Array(4)].map((_, i) => (
        <div key={i} className={cn("animate-pulse rounded-xl border bg-card", compact ? "h-16" : "h-20")} />
      ))}
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading timeline…
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-start gap-3 rounded-xl border p-4">
      <FileCheck2 className="h-5 w-5 text-muted-foreground" />
      <div className="text-sm text-muted-foreground">
        No events match the current filters.
      </div>
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-xl border p-4">
      <TriangleAlert className="h-5 w-5 text-red-500" />
      <div className="text-sm">
        <span className="font-medium">Error:</span>{" "}
        <span className="text-muted-foreground">{message}</span>
      </div>
    </div>
  );
}
