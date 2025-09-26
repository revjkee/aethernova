// frontend/src/widgets/Monitoring/LatencyChart.tsx
import React, { useMemo, useRef, useState, useCallback, useEffect } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Brush,
  ReferenceLine,
  ReferenceArea,
} from "recharts";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Copy, Download, RefreshCcw, Eye, EyeOff, Link as LinkIcon } from "lucide-react";

type LatencyPoint = {
  ts: string | number | Date;
  p50: number;
  p90?: number;
  p99?: number;
  errors?: number; // error rate (0..1 or %), по умолчанию интерпретируем как %
};

type Thresholds = {
  warning?: number;  // миллисекунды или секунды (см. yUnit)
  critical?: number; // миллисекунды или секунды (см. yUnit)
};

type YUnit = "ms" | "s";

export interface LatencyChartProps {
  data: LatencyPoint[];
  title?: string;
  description?: string;
  yUnit?: YUnit; // по умолчанию "ms"
  thresholds?: Thresholds;
  compact?: boolean;
  loading?: boolean;
  error?: string | null;
  // Управление начальными видимостями серий
  defaultSeries?: {
    p50?: boolean;
    p90?: boolean;
    p99?: boolean;
    errors?: boolean;
  };
  // Ограничение по высоте/минимальной высоте
  height?: number; // px
  minHeight?: number; // px
  // Настройка формата времени
  timeFormatter?: (d: Date) => string;
  // Экспорт CSV: имя файла
  csvFileName?: string;
  // Отображать лейбл единиц измерения на оси Y
  showYAxisUnitLabel?: boolean;
  // Управление областью выделения: начальный диапазон индексов
  initialBrush?: { startIndex?: number; endIndex?: number };
}

/** Утилиты форматирования */
function formatUnit(value: number, unit: YUnit): string {
  if (unit === "ms") return `${Number.isFinite(value) ? value.toFixed(0) : value} ms`;
  // seconds
  // для читаемости: < 1s оставляем три знака после запятой
  const v = Number(value);
  if (!Number.isFinite(v)) return String(value);
  return v < 1 ? `${v.toFixed(3)} s` : `${v.toFixed(2)} s`;
}

function toDate(ts: string | number | Date): Date {
  return ts instanceof Date ? ts : new Date(ts);
}

function defaultTimeFormatter(d: Date): string {
  // ISO без миллисекунд
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(
    d.getMinutes()
  )}:${pad(d.getSeconds())}`;
}

function normalizeData(data: LatencyPoint[], unit: YUnit): Array<LatencyPoint & { tsDate: Date; tsNum: number }> {
  return data.map((p) => {
    const tsDate = toDate(p.ts);
    return {
      ...p,
      tsDate,
      tsNum: tsDate.getTime(),
      // данные по латентности интерпретируются как уже в нужных единицах (unit)
    };
  });
}

function inferIntervalMs(sorted: Array<{ tsNum: number }>): number | null {
  if (sorted.length < 2) return null;
  // медиана дельт
  const deltas: number[] = [];
  for (let i = 1; i < sorted.length; i++) deltas.push(sorted[i].tsNum - sorted[i - 1].tsNum);
  deltas.sort((a, b) => a - b);
  const mid = Math.floor(deltas.length / 2);
  return deltas.length % 2 ? deltas[mid] : Math.floor((deltas[mid - 1] + deltas[mid]) / 2);
}

function buildCsv(data: ReturnType<typeof normalizeData>, unit: YUnit): string {
  const header = ["ts_iso", `p50_${unit}`, `p90_${unit}`, `p99_${unit}`, "errors_percent"];
  const rows = data.map((d) => {
    const e = typeof d.errors === "number" ? d.errors : NaN;
    // errors трактуем как проценты, если приходит в (0..1) — умножаем на 100
    const errorsPercent = Number.isFinite(e) ? (e <= 1 ? e * 100 : e) : "";
    return [
      d.tsDate.toISOString(),
      Number.isFinite(d.p50) ? d.p50 : "",
      Number.isFinite(d.p90 ?? NaN) ? d.p90 : "",
      Number.isFinite(d.p99 ?? NaN) ? d.p99 : "",
      Number.isFinite(errorsPercent) ? errorsPercent.toFixed(3) : "",
    ].join(",");
  });
  return [header.join(","), ...rows].join("\n");
}

function downloadBlob(content: string, fileName: string, mime = "text/csv;charset=utf-8"): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Кастомный тултип */
const CustomTooltip: React.FC<{
  active?: boolean;
  payload?: any[];
  label?: number;
  unit: YUnit;
  tf: (d: Date) => string;
}> = ({ active, payload, label, unit, tf }) => {
  if (!active || !payload || payload.length === 0 || typeof label !== "number") return null;
  const when = tf(new Date(label));
  const p50 = payload.find((p) => p.dataKey === "p50")?.value;
  const p90 = payload.find((p) => p.dataKey === "p90")?.value;
  const p99 = payload.find((p) => p.dataKey === "p99")?.value;
  const errors = payload.find((p) => p.dataKey === "errorsDisplay")?.value;

  return (
    <div className="rounded-xl border bg-background p-3 shadow-md text-sm">
      <div className="font-medium">{when}</div>
      <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1">
        {Number.isFinite(p50) && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">p50</span>
            <span className="font-semibold">{formatUnit(p50 as number, unit)}</span>
          </div>
        )}
        {Number.isFinite(p90) && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">p90</span>
            <span className="font-semibold">{formatUnit(p90 as number, unit)}</span>
          </div>
        )}
        {Number.isFinite(p99) && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">p99</span>
            <span className="font-semibold">{formatUnit(p99 as number, unit)}</span>
          </div>
        )}
        {Number.isFinite(errors) && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">errors</span>
            <span className="font-semibold">{(errors as number).toFixed(3)}%</span>
          </div>
        )}
      </div>
    </div>
  );
};

const SeriesToggle: React.FC<{
  label: string;
  checked: boolean;
  onCheckedChange: (val: boolean) => void;
}> = ({ label, checked, onCheckedChange }) => (
  <div className="flex items-center gap-2">
    <Switch checked={checked} onCheckedChange={onCheckedChange} id={`series-${label}`} />
    <Label htmlFor={`series-${label}`} className="cursor-pointer">{label}</Label>
  </div>
);

/** Основной компонент */
export const LatencyChart: React.FC<LatencyChartProps> = ({
  data,
  title = "Latency",
  description,
  yUnit = "ms",
  thresholds,
  compact = false,
  loading = false,
  error = null,
  defaultSeries,
  height = 360,
  minHeight = 280,
  timeFormatter,
  csvFileName = "latency.csv",
  showYAxisUnitLabel = true,
  initialBrush,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const tf = useMemo(() => timeFormatter ?? defaultTimeFormatter, [timeFormatter]);

  const normalized = useMemo(() => {
    const n = normalizeData(data ?? [], yUnit);
    n.sort((a, b) => a.tsNum - b.tsNum);
    return n.map((p) => {
      const errorsPercent =
        typeof p.errors === "number"
          ? (p.errors <= 1 ? p.errors * 100 : p.errors)
          : undefined;
      return { ...p, errorsDisplay: errorsPercent };
    });
  }, [data, yUnit]);

  const intervalMs = useMemo(() => inferIntervalMs(normalized), [normalized]);

  // Управление видимостью серий
  const [showP50, setShowP50] = useState(defaultSeries?.p50 ?? true);
  const [showP90, setShowP90] = useState(defaultSeries?.p90 ?? true);
  const [showP99, setShowP99] = useState(defaultSeries?.p99 ?? true);
  const [showErrors, setShowErrors] = useState(defaultSeries?.errors ?? false);

  // Пороговые значения (локально редактируемые)
  const [warn, setWarn] = useState<number | undefined>(thresholds?.warning);
  const [crit, setCrit] = useState<number | undefined>(thresholds?.critical);

  useEffect(() => {
    setWarn(thresholds?.warning);
    setCrit(thresholds?.critical);
  }, [thresholds?.warning, thresholds?.critical]);

  // Экспорт CSV
  const handleExportCsv = useCallback(() => {
    const csv = buildCsv(normalized, yUnit);
    downloadBlob(csv, csvFileName);
  }, [normalized, yUnit, csvFileName]);

  // Перманентная ссылка (состояние серий/порогов)
  const handleCopyPermalink = useCallback(async () => {
    const url = new URL(window.location.href);
    url.searchParams.set("p50", String(showP50));
    url.searchParams.set("p90", String(showP90));
    url.searchParams.set("p99", String(showP99));
    url.searchParams.set("errors", String(showErrors));
    if (warn !== undefined) url.searchParams.set("warn", String(warn));
    if (crit !== undefined) url.searchParams.set("crit", String(crit));
    await navigator.clipboard.writeText(url.toString());
  }, [showP50, showP90, showP99, showErrors, warn, crit]);

  // Восстановление состояния из query (опционально)
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const b = (v: string | null, def: boolean) => (v == null ? def : v === "true");
    setShowP50(b(q.get("p50"), showP50));
    setShowP90(b(q.get("p90"), showP90));
    setShowP99(b(q.get("p99"), showP99));
    setShowErrors(b(q.get("errors"), showErrors));

    const qWarn = q.get("warn");
    const qCrit = q.get("crit");
    if (qWarn != null && !Number.isNaN(Number(qWarn))) setWarn(Number(qWarn));
    if (qCrit != null && !Number.isNaN(Number(qCrit))) setCrit(Number(qCrit));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // один раз при монтировании

  // Подпись единиц для оси Y
  const yAxisLabel = showYAxisUnitLabel ? (yUnit === "ms" ? "Latency (ms)" : "Latency (s)") : undefined;

  // Состояния загрузки/ошибки/пусто
  if (loading) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </CardHeader>
        <CardContent>
          <div className="h-[200px] min-h-[160px] animate-pulse rounded-2xl bg-muted" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </CardHeader>
        <CardContent>
          <div className="rounded-xl border p-4 text-sm">
            <div className="font-medium">Ошибка</div>
            <div className="text-muted-foreground mt-1">{error}</div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!normalized.length) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </CardHeader>
        <CardContent>
          <div className="rounded-xl border p-8 text-sm text-muted-foreground">
            Данные отсутствуют для отображения.
          </div>
        </CardContent>
      </Card>
    );
  }

  // Ограничение высоты
  const chartHeight = Math.max(compact ? minHeight : height, minHeight);

  // Минимальные/максимальные значения для авто-скейла
  const yDomain = useMemo<[number, number]>(() => {
    const vals: number[] = [];
    normalized.forEach((d) => {
      if (showP50 && Number.isFinite(d.p50)) vals.push(d.p50);
      if (showP90 && Number.isFinite(d.p90 ?? NaN)) vals.push(d.p90 as number);
      if (showP99 && Number.isFinite(d.p99 ?? NaN)) vals.push(d.p99 as number);
      if (warn !== undefined) vals.push(warn);
      if (crit !== undefined) vals.push(crit);
    });
    if (vals.length === 0) return [0, 1];
    const min = Math.min(...vals);
    const max = Math.max(...vals);
    if (!Number.isFinite(min) || !Number.isFinite(max)) return [0, 1];
    const pad = (max - min) * 0.1 || (max || 1) * 0.1;
    return [Math.max(0, min - pad), max + pad];
  }, [normalized, showP50, showP90, showP99, warn, crit]);

  // Подсветка warning/critical зон
  const bands = useMemo(() => {
    const bandList: Array<{ y1: number; y2: number; className: string; key: string }> = [];
    if (warn !== undefined && crit !== undefined && crit > warn) {
      bandList.push({ y1: warn, y2: crit, className: "fill-yellow-500/10", key: "warn" });
      bandList.push({ y1: crit, y2: yDomain[1], className: "fill-red-500/10", key: "crit" });
    } else if (crit !== undefined) {
      bandList.push({ y1: crit, y2: yDomain[1], className: "fill-red-500/10", key: "crit" });
    } else if (warn !== undefined) {
      bandList.push({ y1: warn, y2: yDomain[1], className: "fill-yellow-500/10", key: "warn" });
    }
    return bandList;
  }, [warn, crit, yDomain]);

  // Обработчики инпутов порогов
  const parseNum = (v: string): number | undefined => {
    const num = Number(v);
    return Number.isNaN(num) ? undefined : num;
  };

  return (
    <Card className="w-full" ref={containerRef} aria-label="Latency chart">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="leading-tight">{title}</CardTitle>
          <CardDescription className="mt-1">
            {description ?? (
              <>
                Временной интервал:{" "}
                <Badge variant="secondary" className="align-middle">
                  {intervalMs ? `${Math.round(intervalMs / 1000)}s` : "n/a"}
                </Badge>
              </>
            )}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="secondary" size="sm">
                Действия
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Экспорт</DropdownMenuLabel>
              <DropdownMenuItem onClick={handleExportCsv}>
                <Download className="mr-2 h-4 w-4" /> CSV
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleCopyPermalink}>
                <LinkIcon className="mr-2 h-4 w-4" /> Копировать ссылку
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button
            variant="outline"
            size="icon"
            onClick={() => window.location.reload()}
            aria-label="Обновить"
            title="Обновить"
          >
            <RefreshCcw className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Панель управления сериями и порогами */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="flex flex-wrap items-center gap-4">
            <SeriesToggle label="p50" checked={showP50} onCheckedChange={setShowP50} />
            <SeriesToggle label="p90" checked={showP90} onCheckedChange={setShowP90} />
            <SeriesToggle label="p99" checked={showP99} onCheckedChange={setShowP99} />
            <div className="flex items-center gap-2">
              <Switch checked={showErrors} onCheckedChange={setShowErrors} id="series-errors" />
              <Label htmlFor="series-errors" className="cursor-pointer">
                errors (%)
              </Label>
              <Badge variant="outline" className="ml-1">
                втор. ось
              </Badge>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 justify-start lg:justify-end">
            <div className="flex items-center gap-2">
              <Label htmlFor="warn">Warning ({yUnit})</Label>
              <Input
                id="warn"
                inputMode="decimal"
                placeholder="—"
                className="h-8 w-28"
                value={warn ?? ""}
                onChange={(e) => setWarn(parseNum(e.target.value))}
              />
            </div>
            <div className="flex items-center gap-2">
              <Label htmlFor="crit">Critical ({yUnit})</Label>
              <Input
                id="crit"
                inputMode="decimal"
                placeholder="—"
                className="h-8 w-28"
                value={crit ?? ""}
                onChange={(e) => setCrit(parseNum(e.target.value))}
              />
            </div>
          </div>
        </div>

        {/* Чарт */}
        <div className="w-full" style={{ height: chartHeight, minHeight }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={normalized}
              margin={{ top: 12, right: 24, bottom: 8, left: 16 }}
            >
              <CartesianGrid strokeDasharray="4 4" className="stroke-muted" />
              <XAxis
                dataKey="tsNum"
                type="number"
                domain={["auto", "auto"]}
                tickFormatter={(v) => tf(new Date(v))}
                minTickGap={48}
              />
              <YAxis
                yAxisId="lat"
                domain={yDomain}
                tickFormatter={(v) => formatUnit(v, yUnit)}
                label={
                  yAxisLabel ? { value: yAxisLabel, angle: -90, position: "insideLeft" } : undefined
                }
              />
              {showErrors && (
                <YAxis
                  yAxisId="err"
                  orientation="right"
                  tickFormatter={(v) => `${v.toFixed(1)}%`}
                />
              )}

              {/* Зоны порогов */}
              {bands.map((b) => (
                <ReferenceArea
                  key={b.key}
                  yAxisId="lat"
                  y1={b.y1}
                  y2={b.y2}
                  ifOverflow="extendDomain"
                  className={b.className}
                />
              ))}
              {warn !== undefined && (
                <ReferenceLine
                  yAxisId="lat"
                  y={warn}
                  strokeDasharray="3 3"
                  className="stroke-yellow-500"
                  label={{ value: `warn ${formatUnit(warn, yUnit)}`, position: "right" }}
                />
              )}
              {crit !== undefined && (
                <ReferenceLine
                  yAxisId="lat"
                  y={crit}
                  strokeDasharray="3 3"
                  className="stroke-red-500"
                  label={{ value: `crit ${formatUnit(crit, yUnit)}`, position: "right" }}
                />
              )}

              <Tooltip
                content={<CustomTooltip unit={yUnit} tf={tf} />}
              />
              <Legend
                wrapperStyle={{ paddingTop: 8 }}
                formatter={(v) => <span className="text-sm">{v}</span>}
                onClick={(e: any) => {
                  // Доп. хэндлер по клику на легенде
                  const key = e?.dataKey as string;
                  if (key === "p50") setShowP50((s) => !s);
                  if (key === "p90") setShowP90((s) => !s);
                  if (key === "p99") setShowP99((s) => !s);
                  if (key === "errorsDisplay") setShowErrors((s) => !s);
                }}
              />

              {showP50 && (
                <Line
                  yAxisId="lat"
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="p50"
                  name="p50"
                  stroke="currentColor"
                  className="text-primary"
                  dot={false}
                  strokeWidth={2}
                />
              )}
              {showP90 && (
                <Line
                  yAxisId="lat"
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="p90"
                  name="p90"
                  stroke="currentColor"
                  className="text-green-600 dark:text-green-400"
                  dot={false}
                  strokeWidth={1.75}
                />
              )}
              {showP99 && (
                <Line
                  yAxisId="lat"
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="p99"
                  name="p99"
                  stroke="currentColor"
                  className="text-amber-600 dark:text-amber-400"
                  dot={false}
                  strokeWidth={1.75}
                />
              )}
              {showErrors && (
                <Line
                  yAxisId="err"
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="errorsDisplay"
                  name="errors (%)"
                  stroke="currentColor"
                  className="text-destructive"
                  dot={false}
                  strokeWidth={1}
                />
              )}

              <Brush
                dataKey="tsNum"
                tickFormatter={(v) => tf(new Date(v))}
                startIndex={initialBrush?.startIndex}
                endIndex={initialBrush?.endIndex}
                travellerWidth={8}
                height={24}
                className="fill-muted/40"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Легенда по порогам и копирование */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            {warn !== undefined && (
              <span className="inline-flex items-center gap-1">
                <Eye className="h-3.5 w-3.5" /> warn: {formatUnit(warn, yUnit)}
              </span>
            )}
            {crit !== undefined && (
              <span className="inline-flex items-center gap-1">
                <EyeOff className="h-3.5 w-3.5" /> crit: {formatUnit(crit, yUnit)}
              </span>
            )}
            {intervalMs && (
              <span className="inline-flex items-center gap-1">
                <Copy className="h-3.5 w-3.5" /> interval: {Math.round(intervalMs / 1000)}s
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={async () => {
                try {
                  const txt = buildCsv(normalized, yUnit);
                  await navigator.clipboard.writeText(txt);
                } catch {
                  // копирование может быть заблокировано — в таком случае предлагаем скачать
                  const txt = buildCsv(normalized, yUnit);
                  downloadBlob(txt, csvFileName.replace(/\.csv$/i, "") + "_clipboard.csv", "text/plain;charset=utf-8");
                }
              }}
            >
              <Copy className="mr-2 h-4 w-4" />
              CSV в буфер
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default LatencyChart;
