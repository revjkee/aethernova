// frontend/src/features/ethics/components/EthicsLogTable.tsx
import * as React from "react";
import { useMemo, useState, useCallback, useEffect, useRef } from "react";
import { z } from "zod";
import {
  Card,
  CardHeader,
  CardContent,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Checkbox } from "@/components/ui/checkbox";
import {
  AlertCircle,
  ShieldAlert,
  ShieldCheck,
  Shield,
  Info,
  ChevronDown,
  ChevronUp,
  Filter,
  Download,
  RefreshCw,
  ChevronsLeft,
  ChevronLeft,
  ChevronRight,
  ChevronsRight,
  SortAsc,
  SortDesc,
} from "lucide-react";

// -----------------------------
// Types & validation
// -----------------------------
export type EthicsSeverity = "low" | "medium" | "high" | "critical";
export type EthicsOutcome = "allow" | "block" | "review" | "deny";

export interface EthicsLogEntry {
  id: string;                     // stable id (uuid/ksuid)
  timestamp: string;              // ISO 8601
  actor: string;                  // user/agent/service
  entity: string;                 // resource/model/subject
  action: string;                 // operation type
  ruleId?: string;
  ruleName?: string;
  severity: EthicsSeverity;
  outcome: EthicsOutcome;
  rationale?: string;             // human-readable explanation
  tags?: string[];                // free-form tags
  requestId?: string;
  metadata?: Record<string, unknown>; // structured details
}

export const EthicsLogSchema = z.object({
  id: z.string().min(1),
  timestamp: z.string().datetime(),
  actor: z.string().min(1),
  entity: z.string().min(1),
  action: z.string().min(1),
  ruleId: z.string().optional(),
  ruleName: z.string().optional(),
  severity: z.enum(["low", "medium", "high", "critical"]),
  outcome: z.enum(["allow", "block", "review", "deny"]),
  rationale: z.string().optional(),
  tags: z.array(z.string()).optional(),
  requestId: z.string().optional(),
  metadata: z.record(z.any()).optional(),
});

export type SortKey = keyof Pick<
  EthicsLogEntry,
  "timestamp" | "actor" | "entity" | "action" | "severity" | "outcome"
>;
type SortState = { key: SortKey; dir: "asc" | "desc" } | null;

// -----------------------------
// Utilities
// -----------------------------
const severityOrder: Record<EthicsSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};
const outcomeOrder: Record<EthicsOutcome, number> = {
  allow: 0,
  review: 1,
  deny: 2,
  block: 3,
};

function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    // ISO short with time
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

function downloadCSV(filename: string, rows: EthicsLogEntry[]) {
  const headers = [
    "id","timestamp","actor","entity","action","ruleId","ruleName",
    "severity","outcome","rationale","tags","requestId","metadata",
  ];
  const escape = (val: unknown) => {
    if (val == null) return "";
    const s =
      typeof val === "string"
        ? val
        : Array.isArray(val)
        ? val.join("|")
        : typeof val === "object"
        ? JSON.stringify(val)
        : String(val);
    // CSV escaping
    if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const lines = [
    headers.join(","),
    ...rows.map((r) =>
      [
        r.id,
        r.timestamp,
        r.actor,
        r.entity,
        r.action,
        r.ruleId ?? "",
        r.ruleName ?? "",
        r.severity,
        r.outcome,
        r.rationale ?? "",
        (r.tags ?? []).join("|"),
        r.requestId ?? "",
        r.metadata ? JSON.stringify(r.metadata) : "",
      ]
        .map(escape)
        .join(",")
    ),
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Stable stringify for metadata preview
function pretty(obj: unknown): string {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

function classNames(...xs: Array<string | false | null | undefined>) {
  return xs.filter(Boolean).join(" ");
}

// -----------------------------
// Props
// -----------------------------
export interface EthicsLogTableProps {
  data: EthicsLogEntry[];
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  title?: string;
  description?: string;
  pageSizeOptions?: number[]; // default [10, 25, 50, 100]
  initialPageSize?: number;
  enableCsvExport?: boolean;
  ariaLabel?: string; // for screen readers
}

// -----------------------------
// Component
// -----------------------------
export function EthicsLogTable({
  data,
  isLoading = false,
  error = null,
  onRetry,
  title = "Ethics Log",
  description = "Записи аудита и решений этического движка",
  pageSizeOptions = [10, 25, 50, 100],
  initialPageSize = 25,
  enableCsvExport = true,
  ariaLabel = "Таблица журналов этики",
}: EthicsLogTableProps) {
  // Optional runtime validation in dev
  useEffect(() => {
    if (process.env.NODE_ENV !== "production") {
      for (const r of data) {
        const res = EthicsLogSchema.safeParse(r);
        if (!res.success) {
          // eslint-disable-next-line no-console
          console.warn("EthicsLogTable: invalid row", r, res.error.flatten());
        }
      }
    }
  }, [data]);

  // Filters
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<EthicsSeverity[]>([]);
  const [from, setFrom] = useState<string>("");
  const [to, setTo] = useState<string>("");

  // Columns visibility
  const [showColumns, setShowColumns] = useState<Record<string, boolean>>({
    rule: true,
    tags: true,
    requestId: true,
  });

  // Sorting
  const [sort, setSort] = useState<SortState>({ key: "timestamp", dir: "desc" });
  const toggleSort = useCallback((key: SortKey) => {
    setSort((prev) => {
      if (!prev || prev.key !== key) return { key, dir: "asc" };
      return { key, dir: prev.dir === "asc" ? "desc" : "asc" };
    });
  }, []);

  // Pagination
  const [pageSize, setPageSize] = useState<number>(initialPageSize);
  const [page, setPage] = useState<number>(1);

  // Expanded rows
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const toggleRow = useCallback((id: string) => {
    setExpanded((e) => ({ ...e, [id]: !e[id] }));
  }, []);

  // Keyboard navigation
  const rowRefs = useRef<Map<string, HTMLTableRowElement | null>>(new Map());
  const idByIndex = useMemo(() => filteredSorted.map((r) => r.id), []); // placeholder, will update after filteredSorted defined

  // Derived: filter
  const filtered = useMemo(() => {
    const qn = q.trim().toLowerCase();
    const fn = from ? new Date(from).getTime() : Number.NEGATIVE_INFINITY;
    const tn = to ? new Date(to).getTime() : Number.POSITIVE_INFINITY;
    return data.filter((r) => {
      const t = new Date(r.timestamp).getTime();
      if (Number.isNaN(t) || t < fn || t > tn) return false;

      if (sev.length && !sev.includes(r.severity)) return false;

      if (qn.length) {
        const hay = [
          r.id,
          r.actor,
          r.entity,
          r.action,
          r.ruleId,
          r.ruleName,
          r.rationale,
          r.requestId,
          ...(r.tags ?? []),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(qn)) return false;
      }
      return true;
    });
  }, [data, q, sev, from, to]);

  // Derived: sort
  const filteredSorted = useMemo(() => {
    if (!sort) return filtered;
    const { key, dir } = sort;
    const m = dir === "asc" ? 1 : -1;
    const arr = [...filtered];
    arr.sort((a, b) => {
      let va: number | string = "";
      let vb: number | string = "";
      switch (key) {
        case "timestamp":
          va = new Date(a.timestamp).getTime();
          vb = new Date(b.timestamp).getTime();
          break;
        case "severity":
          va = severityOrder[a.severity];
          vb = severityOrder[b.severity];
          break;
        case "outcome":
          va = outcomeOrder[a.outcome];
          vb = outcomeOrder[b.outcome];
          break;
        default:
          va = (a[key] as string) ?? "";
          vb = (b[key] as string) ?? "";
      }
      if (va < vb) return -1 * m;
      if (va > vb) return 1 * m;
      // tie-break by time desc for stability
      const ta = new Date(a.timestamp).getTime();
      const tb = new Date(b.timestamp).getTime();
      return tb - ta;
    });
    return arr;
  }, [filtered, sort]);

  // Derived: paginate
  const total = filteredSorted.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [totalPages, page]);

  const pageData = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredSorted.slice(start, start + pageSize);
  }, [filteredSorted, page, pageSize]);

  // Update nav refs map based on current page
  useEffect(() => {
    rowRefs.current = new Map();
  }, [pageData]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTableRowElement>, idx: number, id: string) => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const next =
          e.key === "ArrowDown"
            ? Math.min(pageData.length - 1, idx + 1)
            : Math.max(0, idx - 1);
        const nextId = pageData[next]?.id;
        if (nextId) {
          const el = rowRefs.current.get(nextId);
          el?.focus();
        }
      } else if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleRow(id);
      }
    },
    [pageData, toggleRow]
  );

  const clearFilters = () => {
    setQ("");
    setSev([]);
    setFrom("");
    setTo("");
  };

  const exportCsv = () => {
    downloadCSV(
      `ethics_log_${new Date().toISOString().replace(/[:.]/g, "-")}.csv`,
      filteredSorted
    );
  };

  // Visual helpers
  const SevIcon = ({ s }: { s: EthicsSeverity }) => {
    switch (s) {
      case "low":
        return <Shield className="h-4 w-4" aria-hidden />;
      case "medium":
        return <Info className="h-4 w-4" aria-hidden />;
      case "high":
        return <ShieldCheck className="h-4 w-4" aria-hidden />;
      case "critical":
        return <ShieldAlert className="h-4 w-4" aria-hidden />;
    }
  };

  // Error state
  if (error) {
    return (
      <Card aria-label={ariaLabel}>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-3">
          <AlertCircle className="h-5 w-5" aria-hidden />
          <span className="text-sm">Ошибка загрузки: {error}</span>
          {onRetry && (
            <Button onClick={onRetry} variant="outline" size="sm">
              <RefreshCw className="h-4 w-4 mr-2" />
              Повторить
            </Button>
          )}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card aria-label={ariaLabel}>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle className="text-xl">{title}</CardTitle>
            <CardDescription>{description}</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {enableCsvExport && (
              <Button
                variant="outline"
                size="sm"
                onClick={exportCsv}
                aria-label="Экспортировать в CSV"
              >
                <Download className="h-4 w-4 mr-2" />
                CSV
              </Button>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-3">
            <label className="text-xs text-muted-foreground block mb-1">Поиск</label>
            <div className="relative">
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="actor, entity, action, rule, tags…"
                aria-label="Поиск по журналу"
              />
              <Filter className="h-4 w-4 absolute right-2 top-2.5" aria-hidden />
            </div>
          </div>
          <div className="md:col-span-3">
            <label className="text-xs text-muted-foreground block mb-1">Severity</label>
            <Select
              value={sev.join(",")}
              onValueChange={(val) =>
                setSev(val ? (val.split(",").filter(Boolean) as EthicsSeverity[]) : [])
              }
            >
              <SelectTrigger aria-label="Фильтр по уровню">
                <SelectValue placeholder="Любой" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">Любой</SelectItem>
                <SelectItem value="low">low</SelectItem>
                <SelectItem value="medium">medium</SelectItem>
                <SelectItem value="high">high</SelectItem>
                <SelectItem value="critical">critical</SelectItem>
                {/* Multi-select hack: allow combining via comma */}
                <Separator className="my-1" />
                <SelectItem value="high,critical">high,critical</SelectItem>
                <SelectItem value="medium,high,critical">{">= medium"}</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-muted-foreground block mb-1">От</label>
            <Input
              type="datetime-local"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              aria-label="Дата от"
            />
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-muted-foreground block mb-1">До</label>
            <Input
              type="datetime-local"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              aria-label="Дата до"
            />
          </div>
          <div className="md:col-span-2 flex items-end gap-2">
            <Button variant="ghost" size="sm" onClick={clearFilters}>
              Очистить
            </Button>
            <Select
              value={String(pageSize)}
              onValueChange={(v) => setPageSize(Number(v))}
            >
              <SelectTrigger className="w-[120px]" aria-label="Размер страницы">
                <SelectValue placeholder="Размер" />
              </SelectTrigger>
              <SelectContent>
                {pageSizeOptions.map((s) => (
                  <SelectItem key={s} value={String(s)}>
                    {s}/стр
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Column toggles */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Checkbox
              id="col-rule"
              checked={showColumns.rule}
              onCheckedChange={(v) =>
                setShowColumns((s) => ({ ...s, rule: Boolean(v) }))
              }
            />
            <label htmlFor="col-rule" className="text-sm">Правило</label>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="col-tags"
              checked={showColumns.tags}
              onCheckedChange={(v) =>
                setShowColumns((s) => ({ ...s, tags: Boolean(v) }))
              }
            />
            <label htmlFor="col-tags" className="text-sm">Теги</label>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="col-req"
              checked={showColumns.requestId}
              onCheckedChange={(v) =>
                setShowColumns((s) => ({ ...s, requestId: Boolean(v) }))
              }
            />
            <label htmlFor="col-req" className="text-sm">Request ID</label>
          </div>
        </div>

        {/* Loading / Empty */}
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded-md bg-muted" />
            ))}
          </div>
        ) : total === 0 ? (
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <Info className="h-4 w-4" aria-hidden />
            Нет данных по текущим фильтрам.
          </div>
        ) : (
          <>
            {/* Table */}
            <ScrollArea className="w-full">
              <Table role="table" aria-label={ariaLabel}>
                <TableHeader>
                  <TableRow>
                    <Th
                      label="Время"
                      active={sort?.key === "timestamp"}
                      dir={sort?.dir}
                      onClick={() => toggleSort("timestamp")}
                    />
                    <Th
                      label="Актор"
                      active={sort?.key === "actor"}
                      dir={sort?.dir}
                      onClick={() => toggleSort("actor")}
                    />
                    <Th
                      label="Сущность"
                      active={sort?.key === "entity"}
                      dir={sort?.dir}
                      onClick={() => toggleSort("entity")}
                    />
                    <Th
                      label="Действие"
                      active={sort?.key === "action"}
                      dir={sort?.dir}
                      onClick={() => toggleSort("action")}
                    />
                    <Th
                      label="Severity"
                      active={sort?.key === "severity"}
                      dir={sort?.dir}
                      onClick={() => toggleSort("severity")}
                      className="w-[110px]"
                    />
                    <Th
                      label="Outcome"
                      active={sort?.key === "outcome"}
                      dir={sort?.dir}
                      onClick={() => toggleSort("outcome")}
                      className="w-[110px]"
                    />
                    {showColumns.rule && <TableHead className="min-w-[180px]">Правило</TableHead>}
                    {showColumns.tags && <TableHead className="min-w-[160px]">Теги</TableHead>}
                    {showColumns.requestId && <TableHead className="min-w-[160px]">Request ID</TableHead>}
                    <TableHead className="w-[60px]" aria-label="Раскрыть" />
                  </TableRow>
                </TableHeader>

                <TableBody>
                  {pageData.map((r, idx) => {
                    const isOpen = !!expanded[r.id];
                    return (
                      <React.Fragment key={r.id}>
                        <TableRow
                          role="row"
                          tabIndex={0}
                          ref={(el) => rowRefs.current.set(r.id, el)}
                          onKeyDown={(e) => handleKeyDown(e, idx, r.id)}
                          className={classNames(isOpen && "bg-muted/30")}
                        >
                          <TableCell title={r.timestamp}>{formatDate(r.timestamp)}</TableCell>
                          <TableCell className="font-medium">{r.actor}</TableCell>
                          <TableCell>{r.entity}</TableCell>
                          <TableCell>{r.action}</TableCell>
                          <TableCell>
                            <Badge variant={severityBadgeVariant(r.severity)} className="gap-1">
                              <SevIcon s={r.severity} />
                              {r.severity}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <OutcomeBadge outcome={r.outcome} />
                          </TableCell>
                          {showColumns.rule && (
                            <TableCell title={r.ruleId ?? ""}>
                              <div className="flex flex-col">
                                <span className="truncate max-w-[280px]">{r.ruleName ?? "—"}</span>
                                <span className="text-xs text-muted-foreground truncate">
                                  {r.ruleId ?? ""}
                                </span>
                              </div>
                            </TableCell>
                          )}
                          {showColumns.tags && (
                            <TableCell>
                              <div className="flex flex-wrap gap-1">
                                {(r.tags ?? []).slice(0, 6).map((t) => (
                                  <Badge key={t} variant="secondary">
                                    {t}
                                  </Badge>
                                ))}
                                {(r.tags?.length ?? 0) > 6 && (
                                  <Badge variant="outline">+{(r.tags!.length - 6)}</Badge>
                                )}
                              </div>
                            </TableCell>
                          )}
                          {showColumns.requestId && (
                            <TableCell className="text-xs text-muted-foreground">{r.requestId ?? "—"}</TableCell>
                          )}
                          <TableCell className="text-right">
                            <Button
                              size="icon"
                              variant="ghost"
                              aria-expanded={isOpen}
                              aria-label={isOpen ? "Свернуть строку" : "Раскрыть строку"}
                              onClick={() => toggleRow(r.id)}
                            >
                              {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                            </Button>
                          </TableCell>
                        </TableRow>

                        {isOpen && (
                          <TableRow className="bg-muted/30">
                            <TableCell colSpan={showColumns.rule && showColumns.tags && showColumns.requestId ? 10 : showColumns.rule && showColumns.tags ? 9 : showColumns.rule || showColumns.tags || showColumns.requestId ? 8 : 7}>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 py-3">
                                <div>
                                  <div className="text-xs text-muted-foreground mb-1">Rationale</div>
                                  <pre className="text-sm whitespace-pre-wrap break-words rounded-md border p-3 bg-background">
                                    {r.rationale ?? "—"}
                                  </pre>
                                </div>
                                <div>
                                  <div className="text-xs text-muted-foreground mb-1">Metadata</div>
                                  <pre className="text-xs rounded-md border p-3 bg-background overflow-auto max-h-64">
                                    {r.metadata ? pretty(r.metadata) : "—"}
                                  </pre>
                                </div>
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </React.Fragment>
                    );
                  })}
                </TableBody>
              </Table>
            </ScrollArea>

            {/* Pagination */}
            <div className="flex items-center justify-between pt-2">
              <div className="text-xs text-muted-foreground">
                Показано {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} из {total}
              </div>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="В начало"
                  disabled={page === 1}
                  onClick={() => setPage(1)}
                >
                  <ChevronsLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="Назад"
                  disabled={page === 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <span className="text-sm px-2">
                  Стр. {page} / {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="Вперёд"
                  disabled={page === totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="В конец"
                  disabled={page === totalPages}
                  onClick={() => setPage(totalPages)}
                >
                  <ChevronsRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// -----------------------------
// Subcomponents & helpers
// -----------------------------
function Th({
  label,
  active,
  dir,
  onClick,
  className,
}: {
  label: string;
  active?: boolean;
  dir?: "asc" | "desc";
  onClick?: () => void;
  className?: string;
}) {
  return (
    <TableHead
      className={classNames("select-none", className)}
      aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : "none"}
    >
      <button
        type="button"
        onClick={onClick}
        className="inline-flex items-center gap-1 hover:underline focus:outline-none focus:ring-2 focus:ring-ring rounded-sm"
        aria-label={`Сортировать по: ${label}`}
      >
        {label}
        {active ? (
          dir === "asc" ? <SortAsc className="h-4 w-4" /> : <SortDesc className="h-4 w-4" />
        ) : null}
      </button>
    </TableHead>
  );
}

function severityBadgeVariant(s: EthicsSeverity): React.ComponentProps<typeof Badge>["variant"] {
  switch (s) {
    case "low":
      return "secondary";
    case "medium":
      return "outline";
    case "high":
      return "default";
    case "critical":
      return "destructive";
  }
}

function OutcomeBadge({ outcome }: { outcome: EthicsOutcome }) {
  const variant: React.ComponentProps<typeof Badge>["variant"] =
    outcome === "allow"
      ? "secondary"
      : outcome === "review"
      ? "outline"
      : outcome === "deny"
      ? "default"
      : "destructive";
  return <Badge variant={variant}>{outcome}</Badge>;
}

export default EthicsLogTable;
