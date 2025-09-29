// frontend/src/features/ethics/components/MoralContractReport.tsx
import React, {memo, useCallback, useEffect, useMemo, useRef, useState} from "react";

// Utility function stub
const cn = (...classes: (string | undefined | null | false)[]): string => {
  return classes.filter(Boolean).join(' ');
};

// UI Component stubs
const Button = ({ 
  children, 
  variant, 
  size, 
  className, 
  ...props 
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { 
  variant?: string; 
  size?: string; 
}) => (
  <button className={cn('px-3 py-2 rounded-md border', className)} {...props}>{children}</button>
);

const Card = ({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('border rounded-lg shadow-sm bg-white', className)} {...props}>{children}</div>
);
const CardHeader = ({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('px-6 py-4 border-b', className)} {...props}>{children}</div>
);
const CardTitle = ({ children, className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) => (
  <h3 className={cn('text-lg font-semibold', className)} {...props}>{children}</h3>
);
const CardDescription = ({ children, className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) => (
  <p className={cn('text-sm text-gray-600', className)} {...props}>{children}</p>
);
const CardContent = ({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('px-6 py-4', className)} {...props}>{children}</div>
);

const Badge = ({ children, variant, className, ...props }: React.HTMLAttributes<HTMLSpanElement> & { variant?: string }) => (
  <span className={cn('inline-flex items-center px-2 py-1 text-xs rounded-full border', className)} {...props}>{children}</span>
);

const Input = ({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) => (
  <input className={cn('px-3 py-2 border rounded-md', className)} {...props} />
);

const Label = ({ children, className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) => (
  <label className={cn('text-sm font-medium', className)} {...props}>{children}</label>
);

const Separator = ({ 
  className, 
  orientation, 
  ...props 
}: React.HTMLAttributes<HTMLDivElement> & { orientation?: string }) => (
  <div className={cn(orientation === 'vertical' ? 'border-l mx-2' : 'border-t my-4', className)} {...props} />
);

const ScrollArea = ({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('overflow-auto', className)} {...props}>{children}</div>
);

const Switch = ({ 
  checked, 
  onCheckedChange, 
  className, 
  ...props 
}: React.InputHTMLAttributes<HTMLInputElement> & { 
  checked?: boolean; 
  onCheckedChange?: (checked: boolean) => void; 
}) => (
  <input
    type="checkbox"
    checked={checked}
    onChange={(e) => onCheckedChange?.(e.target.checked)}
    className={cn('rounded', className)}
    {...props}
  />
);

const Textarea = ({ className, ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) => (
  <textarea className={cn('px-3 py-2 border rounded-md', className)} {...props} />
);

// Accordion components
const Accordion = ({ 
  children, 
  type, 
  ...props 
}: React.HTMLAttributes<HTMLDivElement> & { type?: string }) => (
  <div {...props}>{children}</div>
);
const AccordionItem = ({ children, value, ...props }: React.HTMLAttributes<HTMLDivElement> & { value: string }) => (
  <div {...props}>{children}</div>
);
const AccordionTrigger = ({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
  <button className="w-full text-left px-3 py-2 hover:bg-gray-100" {...props}>{children}</button>
);
const AccordionContent = ({ children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className="px-3 py-2" {...props}>{children}</div>
);

// Tooltip components
const TooltipProvider = ({ children }: { children: React.ReactNode }) => <div>{children}</div>;
const Tooltip = ({ children }: { children: React.ReactNode }) => <div className="relative inline-block">{children}</div>;
const TooltipTrigger = ({ children, asChild }: { children: React.ReactNode; asChild?: boolean }) => <div>{children}</div>;
const TooltipContent = ({ children }: { children: React.ReactNode }) => (
  <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs bg-black text-white rounded">{children}</div>
);

// Tabs components
const Tabs = ({ 
  children, 
  value, 
  onValueChange, 
  defaultValue, 
  ...props 
}: React.HTMLAttributes<HTMLDivElement> & { 
  value?: string; 
  onValueChange?: (value: string) => void; 
  defaultValue?: string; 
}) => (
  <div {...props}>{children}</div>
);
const TabsList = ({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('flex border-b', className)} {...props}>{children}</div>
);
const TabsTrigger = ({ 
  children, 
  value, 
  className, 
  ...props 
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { value: string }) => (
  <button className={cn('px-3 py-2 border-b-2 border-transparent hover:border-gray-300', className)} {...props}>{children}</button>
);
const TabsContent = ({ 
  children, 
  value, 
  className, 
  ...props 
}: React.HTMLAttributes<HTMLDivElement> & { value: string }) => (
  <div className={cn('mt-4', className)} {...props}>{children}</div>
);

const Skeleton = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('animate-pulse bg-gray-200 rounded', className)} {...props} />
);

// Alert components
const Alert = ({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('p-4 border rounded-md bg-blue-50 border-blue-200', className)} {...props}>{children}</div>
);
const AlertTitle = ({ children, className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) => (
  <h4 className={cn('font-medium', className)} {...props}>{children}</h4>
);
const AlertDescription = ({ children, className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) => (
  <p className={cn('text-sm mt-1', className)} {...props}>{children}</p>
);

// Icon stubs
const Download = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>📥</span>;
const FileJson = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>📄</span>;
const Printer = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>🖨️</span>;
const Shield = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>🛡️</span>;
const CheckCircle2 = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>✅</span>;
const XCircle = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>❌</span>;
const Search = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>🔍</span>;
const Filter = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>🔽</span>;
const Copy = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>📋</span>;
const AlertTriangle = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>⚠️</span>;
const Gauge = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>📊</span>;
const Scale = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>⚖️</span>;
const ListTree = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>🌳</span>;
const LinkIcon = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>🔗</span>;
const Info = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>ℹ️</span>;
const FileSignature = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>📝</span>;
const ExternalLink = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>🔗</span>;
const BarChart3 = ({ className }: { className?: string }) => <span className={cn('inline-block', className)}>📊</span>;

// Recharts stubs
const ResponsiveContainer = ({ children, width, height }: { children: React.ReactNode; width?: string | number; height?: string | number }) => (
  <div style={{ width: width || '100%', height: height || 300 }}>{children}</div>
);
const BarChart = ({ children, data, ...props }: { children: React.ReactNode; data?: any[]; [key: string]: any }) => (
  <div className="bg-gray-100 p-4 rounded">Chart: Bar Chart</div>
);
const Bar = ({ dataKey, fill, ...props }: { dataKey?: string; fill?: string; [key: string]: any }) => null;
const XAxis = ({ dataKey, ...props }: { dataKey?: string; [key: string]: any }) => null;
const YAxis = (props: any) => null;
const RTooltip = (props: any) => null;
const Legend = (props: any) => null;
const Radar = ({ dataKey, stroke, fill, ...props }: { dataKey?: string; stroke?: string; fill?: string; [key: string]: any }) => null;
const RadarChart = ({ children, data, ...props }: { children: React.ReactNode; data?: any[]; [key: string]: any }) => (
  <div className="bg-gray-100 p-4 rounded">Chart: Radar Chart</div>
);
const PolarGrid = (props: any) => null;
const PolarAngleAxis = ({ dataKey, ...props }: { dataKey?: string; [key: string]: any }) => null;
const PolarRadiusAxis = (props: any) => null;

// ----------------------
// Types
// ----------------------
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface EthicalPrincipleScore {
  id: string;
  name: string;
  description?: string;
  score: number; // 0..100
  weight?: number; // 0..1
  risk: RiskLevel;
  notes?: string;
  evidenceIds?: string[];
}

export interface EvidenceItem {
  id: string;
  title: string;
  url?: string;
  excerpt?: string;
  tags?: string[];
  sourceType?: "paper" | "law" | "policy" | "report" | "web" | "internal";
  dateISO?: string; // for sorting
}

export interface DecisionLogItem {
  id: string;
  timestampISO: string;
  actor: string;
  action: string;
  rationale?: string;
  links?: { label: string; url: string }[];
  impact?: "positive" | "neutral" | "negative";
}

export interface RecommendationItem {
  id: string;
  title: string;
  detail?: string;
  owner?: string;
  dueISO?: string;
  severity: RiskLevel;
  status?: "open" | "in_progress" | "done";
}

export interface Signoff {
  approver: string;
  role: string;
  dateISO?: string;
  signatureHash?: string; // e.g., hex of signed digest
}

export interface MoralContractData {
  reportId: string;
  title: string;
  version?: string;
  scope?: string;
  createdISO: string;
  updatedISO?: string;
  owner: string;
  summary?: string;
  overallRisk: RiskLevel;
  principles: EthicalPrincipleScore[];
  evidence: EvidenceItem[];
  decisions: DecisionLogItem[];
  recommendations: RecommendationItem[];
  signoffs?: Signoff[];
  metadata?: Record<string, unknown>;
}

export interface MoralContractReportProps {
  data: MoralContractData;
  className?: string;
  hideChartsOnPrint?: boolean;
  compact?: boolean;
}

// ----------------------
// Utilities
// ----------------------
const riskOrder: RiskLevel[] = ["low", "medium", "high", "critical"];
const riskColor: Record<RiskLevel, string> = {
  low: "bg-emerald-100 text-emerald-800 border-emerald-200",
  medium: "bg-amber-100 text-amber-800 border-amber-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  critical: "bg-red-100 text-red-800 border-red-200",
};
const riskIcon: Record<RiskLevel, React.ReactNode> = {
  low: <CheckCircle2 className="h-4 w-4" aria-hidden="true" />,
  medium: <Gauge className="h-4 w-4" aria-hidden="true" />,
  high: <AlertTriangle className="h-4 w-4" aria-hidden="true" />,
  critical: <Shield className="h-4 w-4" aria-hidden="true" />,
};

function fmtDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit"});
}

function clamp(n: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, n));
}

function weightedScore(principles: EthicalPrincipleScore[]): number {
  const hasWeight = principles.some(p => typeof p.weight === "number");
  if (!hasWeight) {
    const avg = principles.reduce((a, p) => a + clamp(p.score), 0) / Math.max(1, principles.length);
    return Math.round(avg);
  }
  let wsum = 0;
  let acc = 0;
  for (const p of principles) {
    const w = typeof p.weight === "number" ? p.weight! : 0;
    wsum += w;
    acc += clamp(p.score) * w;
  }
  if (wsum === 0) return weightedScore(principles.map(p => ({...p, weight: undefined})));
  return Math.round(acc / wsum);
}

function riskToNumber(r: RiskLevel) {
  return riskOrder.indexOf(r);
}

function classForRisk(r: RiskLevel) {
  return cn("inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium", riskColor[r]);
}

function downloadBlob(filename: string, blob: Blob) {
  const link = document.createElement("a");
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    document.body.removeChild(link);
  }, 0);
}

// ----------------------
// Subcomponents
// ----------------------
const RiskBadge = ({level, label}: {level: RiskLevel; label?: string}) => (
  <span className={classForRisk(level)} aria-label={`risk-${level}`}>
    {riskIcon[level]}
    <span>{label ?? level.toUpperCase()}</span>
  </span>
);

const KeyValue = ({k, v}: {k: string; v?: React.ReactNode}) => (
  <div className="grid grid-cols-3 gap-2 text-sm">
    <div className="text-muted-foreground">{k}</div>
    <div className="col-span-2">{v ?? "—"}</div>
  </div>
);

const EmptyState = ({title, desc}: {title: string; desc?: string}) => (
  <Alert>
    <AlertTitle>{title}</AlertTitle>
    {desc ? <AlertDescription>{desc}</AlertDescription> : null}
  </Alert>
);

// ----------------------
// Main
// ----------------------
function Component({
  data,
  className,
  hideChartsOnPrint = true,
  compact = false,
}: MoralContractReportProps) {
  const [query, setQuery] = useState("");
  const [onlyOpen, setOnlyOpen] = useState(false);
  const [sortByRisk, setSortByRisk] = useState(true);
  const [chartType, setChartType] = useState<"bar" | "radar">("bar");
  const printRef = useRef<HTMLDivElement>(null);
  const [copyOk, setCopyOk] = useState<"idle" | "ok" | "err">("idle");

  // Derived
  const normalizedPrinciples = useMemo(() => {
    const ps = (data?.principles ?? []).map(p => ({
      ...p,
      score: clamp(p.score),
      weight: typeof p.weight === "number" ? p.weight : undefined,
    }));
    return sortByRisk
      ? [...ps].sort((a, b) => riskToNumber(b.risk) - riskToNumber(a.risk) || b.score - a.score)
      : ps;
  }, [data?.principles, sortByRisk]);

  const filteredEvidence = useMemo(() => {
    const term = query.trim().toLowerCase();
    const all = data?.evidence ?? [];
    if (!term) return all;
    return all.filter(e =>
      [e.title, e.excerpt, e.url, (e.tags ?? []).join(" ")].filter(Boolean).some(s => s!.toLowerCase().includes(term)),
    );
  }, [data?.evidence, query]);

  const filteredRecs = useMemo(() => {
    let list = (data?.recommendations ?? []).slice();
    if (onlyOpen) list = list.filter(r => r.status !== "done");
    if (sortByRisk) list.sort((a, b) => riskToNumber(b.severity) - riskToNumber(a.severity));
    if (query.trim()) {
      const t = query.toLowerCase();
      list = list.filter(r => [r.title, r.detail, r.owner].filter(Boolean).some(s => s!.toLowerCase().includes(t)));
    }
    return list;
  }, [data?.recommendations, onlyOpen, sortByRisk, query]);

  const overallScore = useMemo(() => weightedScore(data?.principles ?? []), [data?.principles]);

  const chartData = useMemo(
    () =>
      (data?.principles ?? []).map(p => ({
        name: p.name,
        score: clamp(p.score),
        risk: p.risk,
      })),
    [data?.principles],
  );

  const jsonBlob = useMemo(
    () => new Blob([JSON.stringify(data ?? {}, null, 2)], {type: "application/json"}),
    [data],
  );

  // Handlers
  const handlePrint = useCallback(() => {
    if (printRef.current) window.print();
  }, []);

  const handleDownloadJson = useCallback(() => {
    downloadBlob(`moral-contract-${data?.reportId || "report"}.json`, jsonBlob);
  }, [data?.reportId, jsonBlob]);

  const handleCopySummary = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(data?.summary ?? "");
      setCopyOk("ok");
    } catch {
      setCopyOk("err");
    } finally {
      setTimeout(() => setCopyOk("idle"), 1500);
    }
  }, [data?.summary]);

  useEffect(() => {
    // No-op placeholder for potential analytics hooks
  }, []);

  if (!data) {
    return (
      <div className={cn("space-y-4", className)}>
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  }

  return (
    <TooltipProvider>
      <div ref={printRef} className={cn("space-y-6 print:space-y-3", className)}>
        {/* Header */}
        <div className="flex flex-col gap-3 print:gap-2 md:flex-row md:items-center md:justify-between">
          <div className="space-y-1">
            <h1 className={cn("text-2xl font-semibold tracking-tight", compact && "text-xl")}>
              {data.title}
            </h1>
            <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
              <Badge variant="secondary" className="gap-1">
                <Scale className="h-3.5 w-3.5" />
                Moral Contract
              </Badge>
              <Separator orientation="vertical" className="h-4" />
              <span>Report ID: {data.reportId}</span>
              {data.version && (
                <>
                  <Separator orientation="vertical" className="h-4" />
                  <span>Version: {data.version}</span>
                </>
              )}
              <Separator orientation="vertical" className="h-4" />
              <span>Created: {fmtDate(data.createdISO)}</span>
              {data.updatedISO && (
                <>
                  <Separator orientation="vertical" className="h-4" />
                  <span>Updated: {fmtDate(data.updatedISO)}</span>
                </>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 print:hidden">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="outline" onClick={handleDownloadJson}>
                  <FileJson className="mr-2 h-4 w-4" />
                  Export JSON
                </Button>
              </TooltipTrigger>
              <TooltipContent>Сохранить отчёт в JSON</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button onClick={handlePrint}>
                  <Printer className="mr-2 h-4 w-4" />
                  Print
                </Button>
              </TooltipTrigger>
              <TooltipContent>Печать или экспорт в PDF</TooltipContent>
            </Tooltip>
          </div>
        </div>

        {/* Summary and Score */}
        <div className={cn("grid gap-4 md:grid-cols-3", compact && "md:grid-cols-2")}>
          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ListTree className="h-5 w-5" />
                Summary
              </CardTitle>
              <CardDescription>Краткая выжимка и контекст</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {data.summary ? (
                <>
                  <Textarea readOnly value={data.summary} className="min-h-[96px]" />
                  <div className="flex items-center gap-2">
                    <Button variant="outline" onClick={handleCopySummary}>
                      <Copy className="mr-2 h-4 w-4" />
                      Copy
                    </Button>
                    {copyOk === "ok" && <Badge variant="secondary">Скопировано</Badge>}
                    {copyOk === "err" && <Badge className="bg-red-100 text-red-800">Ошибка копирования</Badge>}
                  </div>
                </>
              ) : (
                <EmptyState title="Нет краткого описания" desc="Поле summary отсутствует." />
              )}
              <Separator />
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <KeyValue k="Owner" v={data.owner} />
                <KeyValue k="Scope" v={data.scope} />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                Overall
              </CardTitle>
              <CardDescription>Итоговый риск и интегральный балл</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between">
                <RiskBadge level={data.overallRisk} label={data.overallRisk.toUpperCase()} />
                <div className="text-right">
                  <div className="text-3xl font-semibold">{overallScore}</div>
                  <div className="text-xs text-muted-foreground">Weighted Score / 100</div>
                </div>
              </div>
              <Separator />
              <div className="space-y-2">
                <Label htmlFor="sort-risk" className="inline-flex items-center gap-2">
                  <Filter className="h-4 w-4" />
                  Сортировать по риску
                </Label>
                <Switch id="sort-risk" checked={sortByRisk} onCheckedChange={setSortByRisk} />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Controls */}
        <Card className="print:hidden">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              Поиск и фильтры
            </CardTitle>
            <CardDescription>Уточните отображение отчёта</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="query">Поиск по тексту</Label>
              <Input
                id="query"
                placeholder="Введите ключевые слова"
                value={query}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setQuery(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="only-open" className="inline-flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                Только открытые рекомендации
              </Label>
              <Switch id="only-open" checked={onlyOpen} onCheckedChange={setOnlyOpen} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="chart-type">Тип диаграммы</Label>
              <Tabs value={chartType} onValueChange={(v: string) => setChartType(v as "bar" | "radar")}>
                <TabsList>
                  <TabsTrigger value="bar">Bar</TabsTrigger>
                  <TabsTrigger value="radar">Radar</TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
          </CardContent>
        </Card>

        {/* Charts */}
        <Card className={cn(hideChartsOnPrint && "print:hidden")}>
          <CardHeader>
            <CardTitle>Оценки по принципам</CardTitle>
            <CardDescription>Нормализованные баллы и распределение риска</CardDescription>
          </CardHeader>
          <CardContent className="h-[320px] w-full">
            {chartData.length === 0 ? (
              <EmptyState title="Нет данных по принципам" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                {chartType === "bar" ? (
                  <BarChart data={chartData}>
                    <XAxis dataKey="name" hide />
                    <YAxis domain={[0, 100]} />
                    <RTooltip />
                    <Legend />
                    <Bar dataKey="score" name="Score" />
                  </BarChart>
                ) : (
                  <RadarChart data={chartData}>
                    <PolarGrid />
                    <PolarAngleAxis dataKey="name" />
                    <PolarRadiusAxis domain={[0, 100]} />
                    <Radar dataKey="score" name="Score" strokeOpacity={0.8} fillOpacity={0.2} />
                    <Legend />
                    <RTooltip />
                  </RadarChart>
                )}
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Principles */}
        <Card>
          <CardHeader>
            <CardTitle>Принципы и комплаенс</CardTitle>
            <CardDescription>Сводка рисков, веса и примечания</CardDescription>
          </CardHeader>
          <CardContent>
            {normalizedPrinciples.length === 0 ? (
              <EmptyState title="Принципы не заданы" />
            ) : (
              <Accordion type="multiple" className="w-full">
                {normalizedPrinciples.map((p) => (
                  <AccordionItem key={p.id} value={p.id}>
                    <AccordionTrigger className="hover:no-underline">
                      <div className="flex w-full items-center justify-between gap-3">
                        <div className="flex min-w-0 items-center gap-3">
                          <Badge variant="outline" className="shrink-0">{p.name}</Badge>
                          <div className="truncate text-sm text-muted-foreground">{p.description}</div>
                        </div>
                        <div className="flex items-center gap-2">
                          <RiskBadge level={p.risk} />
                          <Badge variant="secondary">{p.score}</Badge>
                          {typeof p.weight === "number" && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Badge variant="outline">w={p.weight}</Badge>
                              </TooltipTrigger>
                              <TooltipContent>Вес в итоговом балле</TooltipContent>
                            </Tooltip>
                          )}
                        </div>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent>
                      <div className="grid gap-3 md:grid-cols-3">
                        <div className="md:col-span-2 space-y-2">
                          <Label>Примечания</Label>
                          <div className={cn("rounded-md border p-3", !p.notes && "text-muted-foreground")}>
                            {p.notes || "—"}
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Label>Доказательства</Label>
                          {p.evidenceIds?.length ? (
                            <ul className="list-inside list-disc text-sm">
                              {p.evidenceIds.map(eid => {
                                const e = (data.evidence ?? []).find(x => x.id === eid);
                                return (
                                  <li key={eid} className="flex items-center gap-2">
                                    <LinkIcon className="h-3.5 w-3.5" />
                                    {e?.url ? (
                                      <a className="underline decoration-dotted underline-offset-2" href={e.url} target="_blank" rel="noreferrer">
                                        {e?.title || e.url} <ExternalLink className="ml-1 inline h-3 w-3" />
                                      </a>
                                    ) : (
                                      <span>{e?.title || eid}</span>
                                    )}
                                  </li>
                                );
                              })}
                            </ul>
                          ) : (
                            <div className="text-sm text-muted-foreground">Не указано</div>
                          )}
                        </div>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            )}
          </CardContent>
        </Card>

        {/* Evidence */}
        <Card>
          <CardHeader>
            <CardTitle>Доказательная база</CardTitle>
            <CardDescription>Источники и выдержки</CardDescription>
          </CardHeader>
          <CardContent>
            {filteredEvidence.length === 0 ? (
              <EmptyState title="Нет источников" desc={query ? "Ничего не найдено по запросу." : undefined} />
            ) : (
              <ScrollArea className="h-[260px]">
                <div className="space-y-3 pr-2">
                  {filteredEvidence
                    .slice()
                    .sort((a, b) => (b.dateISO ?? "").localeCompare(a.dateISO ?? ""))
                    .map((e) => (
                    <div key={e.id} className="rounded-md border p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="font-medium">{e.title}</div>
                        <div className="text-xs text-muted-foreground">{fmtDate(e.dateISO)}</div>
                      </div>
                      {e.url && (
                        <a className="mt-1 inline-flex items-center gap-1 text-sm underline underline-offset-2" href={e.url} target="_blank" rel="noreferrer">
                          Открыть источник <ExternalLink className="h-3.5 w-3.5" />
                        </a>
                      )}
                      {e.excerpt && <p className="mt-2 text-sm text-muted-foreground">{e.excerpt}</p>}
                      {e.tags?.length ? (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {e.tags.map(t => (
                            <Badge key={t} variant="outline" className="text-[11px]">{t}</Badge>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* Decisions */}
        <Card>
          <CardHeader>
            <CardTitle>Журнал решений</CardTitle>
            <CardDescription>Хронология действий и аргументации</CardDescription>
          </CardHeader>
          <CardContent>
            {data.decisions?.length ? (
              <div className="space-y-3">
                {data.decisions
                  .slice()
                  .sort((a, b) => (a.timestampISO ?? "").localeCompare(b.timestampISO ?? ""))
                  .map((d) => (
                  <div key={d.id} className="rounded-md border p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary">{d.actor}</Badge>
                        <span className="text-sm text-muted-foreground">{d.action}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">{fmtDate(d.timestampISO)}</span>
                    </div>
                    {d.rationale && <p className="mt-2 text-sm">{d.rationale}</p>}
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <Badge variant={d.impact === "negative" ? "destructive" : d.impact === "positive" ? "default" : "outline"}>
                        Impact: {d.impact ?? "neutral"}
                      </Badge>
                      {d.links?.map((l, idx) => (
                        <a key={idx} className="inline-flex items-center gap-1 text-xs underline underline-offset-2" href={l.url} target="_blank" rel="noreferrer">
                          {l.label} <ExternalLink className="h-3 w-3" />
                        </a>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="Журнал пуст" />
            )}
          </CardContent>
        </Card>

        {/* Recommendations */}
        <Card>
          <CardHeader>
            <CardTitle>Рекомендации по снижению риска</CardTitle>
            <CardDescription>Приоритеты и ответственность</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {filteredRecs.length === 0 ? (
              <EmptyState title="Нет рекомендаций" desc={query || onlyOpen ? "Измените фильтры или поиск." : undefined} />
            ) : (
              <div className={cn("grid gap-3", compact ? "md:grid-cols-2" : "md:grid-cols-3")}>
                {filteredRecs.map((r) => (
                  <div key={r.id} className="rounded-md border p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1">
                        <div className="font-medium">{r.title}</div>
                        {r.detail && <p className="text-sm text-muted-foreground">{r.detail}</p>}
                      </div>
                      <RiskBadge level={r.severity} />
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                      <KeyValue k="Owner" v={r.owner ?? "—"} />
                      <KeyValue k="Due" v={fmtDate(r.dueISO)} />
                      <KeyValue k="Status" v={r.status ?? "open"} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Signoffs */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileSignature className="h-5 w-5" />
              Подписи и утверждения
            </CardTitle>
            <CardDescription>Ответственные лица и контроль целостности</CardDescription>
          </CardHeader>
          <CardContent>
            {data.signoffs?.length ? (
              <div className="grid gap-3 md:grid-cols-2">
                {data.signoffs.map((s, idx) => (
                  <div key={`${s.approver}-${idx}`} className="rounded-md border p-3">
                    <div className="flex items-center justify-between">
                      <div className="font-medium">{s.approver}</div>
                      <div className="text-xs text-muted-foreground">{s.role}</div>
                    </div>
                    <div className="mt-2 grid grid-cols-3 gap-2 text-xs">
                      <KeyValue k="Date" v={fmtDate(s.dateISO)} />
                      <div className="col-span-2">
                        <div className="text-muted-foreground">Signature Hash</div>
                        <code className="block truncate rounded bg-muted px-2 py-1 text-[11px]">
                          {s.signatureHash ?? "—"}
                        </code>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="Нет утверждений" />
            )}
          </CardContent>
        </Card>

        {/* Metadata */}
        {data.metadata && Object.keys(data.metadata).length > 0 && (
          <Card className="break-inside-avoid">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Info className="h-5 w-5" />
                Metadata
              </CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">
{JSON.stringify(data.metadata, null, 2)}
              </pre>
            </CardContent>
          </Card>
        )}

        {/* Print footer */}
        <div className="hidden print:block">
          <Separator className="my-2" />
          <div className="text-xs text-muted-foreground">
            Generated from MoralContractReport • Report ID: {data.reportId} • Printed: {fmtDate(new Date().toISOString())}
          </div>
        </div>

        {/* Global notice */}
        {data.principles.length === 0 && (
          <Alert>
            <AlertTitle>Недостаточно данных для интегральной оценки</AlertTitle>
            <AlertDescription>
              Заполните раздел Principles, чтобы корректно вычислить итоговый балл и отобразить графики.
            </AlertDescription>
          </Alert>
        )}
      </div>

      {/* Print styles to keep charts hidden if needed and improve pagination */}
      <style>{`
        @media print {
          ${hideChartsOnPrint ? `
          .print\\:hidden { display: none !important; }
          ` : ""}
          .print\\:space-y-3 > * + * { margin-top: 0.75rem !important; }
          @page { size: A4; margin: 12mm; }
          h1, h2, h3 { break-after: avoid-page; }
          .break-inside-avoid { break-inside: avoid-page; }
        }
      `}</style>
    </TooltipProvider>
  );
}

export default memo(Component);
