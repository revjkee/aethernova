// frontend/src/widgets/voting/VotingActivityGraph.tsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ResponsiveContainer,
  ComposedChart,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
  Bar,
  Line,
  Brush,
  ReferenceLine,
} from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

/**
 * Модель точки временного ряда голосований.
 * - ts: временная метка (Date | number | string, преобразуется в Date)
 * - yes/no/abstain: абсолютные голоса за период
 * - eligible: число имеющих право голоса на момент периода (для явки)
 * - voters: фактически проголосовавших (если не задано, считается yes+no+abstain)
 * - label: подпись события/итерации (опционально)
 */
export type VotingPoint = {
  ts: Date | number | string;
  yes: number;
  no: number;
  abstain?: number;
  eligible: number;
  voters?: number;
  label?: string;
};

export type VotingActivityGraphProps = {
  data: VotingPoint[];
  title?: string;
  description?: string;
  height?: number;      // высота графика
  minHeight?: number;   // минимальная высота
  compact?: boolean;    // компактный режим
  loading?: boolean;
  error?: string | null;

  // Управление сериями по умолчанию
  defaultSeries?: {
    yes?: boolean;
    no?: boolean;
    abstain?: boolean;
    turnout?: boolean;       // явка %
    maTurnout?: boolean;     // скользящая средняя явки
  };

  // Скользящая средняя (окно в точках)
  defaultMAWindow?: number;

  // Начальная область Brush (индексы массива data)
  initialBrush?: { startIndex?: number; endIndex?: number };

  // Имя файла для экспорта CSV
  csvFileName?: string;

  // Референсные линии явки (проценты)
  turnoutWarn?: number;   // например 50
  turnoutGoal?: number;   // например 66.7

  // Форматирование оси времени
  timeFormatter?: (d: Date) => string;
};

/* Утилиты */
function toDate(ts: Date | number | string): Date {
  return ts instanceof Date ? ts : new Date(ts);
}
function defaultTimeFormatter(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(
    d.getMinutes()
  )}`;
}
function clamp(n: number, a: number, b: number) {
  return Math.max(a, Math.min(b, n));
}
function rollingMean(values: number[], window: number): number[] {
  if (window <= 1) return values.slice();
  const out: number[] = [];
  let sum = 0;
  const q: number[] = [];
  for (let i = 0; i < values.length; i++) {
    sum += values[i];
    q.push(values[i]);
    if (q.length > window) sum -= q.shift() as number;
    out.push(sum / q.length);
  }
  return out;
}
function buildCsv(rows: any[], csvFileName = "voting.csv"): string {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);
  const data = [headers.join(",")].concat(
    rows.map((r) =>
      headers
        .map((h) => {
          const v = (r as any)[h];
          if (typeof v === "string" && (v.includes(",") || v.includes('"'))) {
            return `"${v.replace(/"/g, '""')}"`;
          }
          return v ?? "";
        })
        .join(",")
    )
  );
  return data.join("\n");
}
function downloadBlob(content: string, fileName: string, mime = "text/csv;charset=utf-8") {
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

/* Кастомный тултип */
const TooltipBox: React.FC<{
  active?: boolean;
  payload?: any[];
  label?: number;
  tf: (d: Date) => string;
}> = ({ active, payload, label, tf }) => {
  if (!active || !payload || typeof label !== "number") return null;
  const p = payload.reduce((acc: Record<string, any>, x: any) => {
    acc[x.dataKey] = x.value;
    return acc;
  }, {});
  const when = tf(new Date(label));
  return (
    <div className="rounded-xl border bg-background p-3 shadow-md text-sm">
      <div className="font-medium">{when}</div>
      <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1">
        {"yes" in p && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Yes</span>
            <span className="font-semibold">{p.yes}</span>
          </div>
        )}
        {"no" in p && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">No</span>
            <span className="font-semibold">{p.no}</span>
          </div>
        )}
        {"abstain" in p && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Abstain</span>
            <span className="font-semibold">{p.abstain}</span>
          </div>
        )}
        {"turnout" in p && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Turnout</span>
            <span className="font-semibold">{(p.turnout as number).toFixed(2)}%</span>
          </div>
        )}
        {"maTurnout" in p && (
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Turnout MA</span>
            <span className="font-semibold">{(p.maTurnout as number).toFixed(2)}%</span>
          </div>
        )}
      </div>
    </div>
  );
};

export const VotingActivityGraph: React.FC<VotingActivityGraphProps> = ({
  data,
  title = "Voting activity",
  description,
  height = 420,
  minHeight = 300,
  compact = false,
  loading = false,
  error = null,
  defaultSeries,
  defaultMAWindow = 5,
  initialBrush,
  csvFileName = "voting_activity.csv",
  turnoutWarn,
  turnoutGoal,
  timeFormatter,
}) => {
  const tf = useMemo(() => timeFormatter ?? defaultTimeFormatter, [timeFormatter]);

  // Подготовка и нормализация данных
  const series = useMemo(() => {
    const sorted = (data ?? [])
      .map((d) => {
        const tsDate = toDate(d.ts);
        const voters = Number.isFinite(d.voters) ? (d.voters as number) : (d.yes || 0) + (d.no || 0) + (d.abstain || 0);
        const eligible = Math.max(0, d.eligible || 0);
        const turnout = eligible > 0 ? (voters / eligible) * 100 : 0;
        return {
          tsNum: tsDate.getTime(),
          tsDate,
          yes: clamp(d.yes || 0, 0, Number.MAX_SAFE_INTEGER),
          no: clamp(d.no || 0, 0, Number.MAX_SAFE_INTEGER),
          abstain: clamp(d.abstain || 0, 0, Number.MAX_SAFE_INTEGER),
          voters,
          eligible,
          turnout, // проценты
          label: d.label,
        };
      })
      .sort((a, b) => a.tsNum - b.tsNum);

    // Скользящая средняя явки
    const ma = rollingMean(sorted.map((x) => x.turnout), Math.max(1, defaultMAWindow));
    return sorted.map((x, i) => ({ ...x, maTurnout: ma[i] }));
  }, [data, defaultMAWindow]);

  // Состояние видимости серий
  const [showYes, setShowYes] = useState(defaultSeries?.yes ?? true);
  const [showNo, setShowNo] = useState(defaultSeries?.no ?? true);
  const [showAbstain, setShowAbstain] = useState(defaultSeries?.abstain ?? true);
  const [showTurnout, setShowTurnout] = useState(defaultSeries?.turnout ?? true);
  const [showMATurnout, setShowMATurnout] = useState(defaultSeries?.maTurnout ?? true);

  // Окно MA (редактируемое)
  const [maWindow, setMAWindow] = useState<number>(defaultMAWindow);

  useEffect(() => {
    setMAWindow(defaultMAWindow);
  }, [defaultMAWindow]);

  // Экспорт CSV
  const handleExportCsv = useCallback(() => {
    const rows = series.map((r) => ({
      ts_iso: r.tsDate.toISOString(),
      yes: r.yes,
      no: r.no,
      abstain: r.abstain,
      voters: r.voters,
      eligible: r.eligible,
      turnout_percent: Number.isFinite(r.turnout) ? r.turnout.toFixed(3) : "",
      ma_turnout_percent: Number.isFinite(r.maTurnout) ? r.maTurnout.toFixed(3) : "",
      label: r.label ?? "",
    }));
    const csv = buildCsv(rows, csvFileName);
    downloadBlob(csv, csvFileName);
  }, [series, csvFileName]);

  // Пермалинк текущих настроек
  const handleCopyPermalink = useCallback(async () => {
    const url = new URL(window.location.href);
    url.searchParams.set("yes", String(showYes));
    url.searchParams.set("no", String(showNo));
    url.searchParams.set("abstain", String(showAbstain));
    url.searchParams.set("turnout", String(showTurnout));
    url.searchParams.set("ma", String(showMATurnout));
    url.searchParams.set("maw", String(maWindow));
    await navigator.clipboard.writeText(url.toString());
  }, [showYes, showNo, showAbstain, showTurnout, showMATurnout, maWindow]);

  // Восстановление состояния из query при монтировании
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const b = (v: string | null, d: boolean) => (v == null ? d : v === "true");
    setShowYes(b(q.get("yes"), showYes));
    setShowNo(b(q.get("no"), showNo));
    setShowAbstain(b(q.get("abstain"), showAbstain));
    setShowTurnout(b(q.get("turnout"), showTurnout));
    setShowMATurnout(b(q.get("ma"), showMATurnout));
    const w = q.get("maw");
    if (w && !Number.isNaN(Number(w))) setMAWindow(Math.max(1, Number(w)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
  if (!series.length) {
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

  // Диапазоны осей
  const turnoutMax = Math.min(100, Math.max(100, Math.ceil(Math.max(...series.map((s) => s.turnout), 100))));
  const chartHeight = Math.max(compact ? minHeight : height, minHeight);

  // Обработчик клика по легенде
  const onLegendClick = (e: any) => {
    const key = e?.dataKey as string;
    if (key === "yes") setShowYes((v) => !v);
    if (key === "no") setShowNo((v) => !v);
    if (key === "abstain") setShowAbstain((v) => !v);
    if (key === "turnout") setShowTurnout((v) => !v);
    if (key === "maTurnout") setShowMATurnout((v) => !v);
  };

  return (
    <Card className="w-full" aria-label="Voting activity graph">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="leading-tight">{title}</CardTitle>
          <CardDescription className="mt-1">
            {description ?? (
              <>
                Визуализация распределения голосов и явки по времени.{" "}
                <Badge variant="secondary" className="align-middle">stacked bars + turnout</Badge>
              </>
            )}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="secondary" size="sm">Действия</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Экспорт</DropdownMenuLabel>
              <DropdownMenuItem onClick={handleExportCsv}>Скачать CSV</DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleCopyPermalink}>Копировать ссылку</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>Обновить</Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Панель управления */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <Switch checked={showYes} onCheckedChange={setShowYes} id="series-yes" />
              <Label htmlFor="series-yes">Yes</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={showNo} onCheckedChange={setShowNo} id="series-no" />
              <Label htmlFor="series-no">No</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={showAbstain} onCheckedChange={setShowAbstain} id="series-abstain" />
              <Label htmlFor="series-abstain">Abstain</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={showTurnout} onCheckedChange={setShowTurnout} id="series-turnout" />
              <Label htmlFor="series-turnout">Turnout %</Label>
              <Badge variant="outline" className="ml-1">правая ось</Badge>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={showMATurnout} onCheckedChange={setShowMATurnout} id="series-ma" />
              <Label htmlFor="series-ma">Turnout MA</Label>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 justify-start lg:justify-end">
            <div className="flex items-center gap-2">
              <Label htmlFor="maw">MA окно</Label>
              <Input
                id="maw"
                inputMode="numeric"
                className="h-8 w-20"
                value={maWindow}
                onChange={(e) => setMAWindow(Math.max(1, Number(e.target.value) || 1))}
              />
            </div>
          </div>
        </div>

        {/* График */}
        <div className="w-full" style={{ height: chartHeight, minHeight }}>
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart
              data={series}
              margin={{ top: 12, right: 28, bottom: 8, left: 16 }}
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
                yAxisId="votes"
                tickFormatter={(v) => String(v)}
                label={{ value: "Votes", angle: -90, position: "insideLeft" }}
              />
              <YAxis
                yAxisId="turnout"
                orientation="right"
                domain={[0, turnoutMax]}
                tickFormatter={(v) => `${v}%`}
                label={{ value: "Turnout (%)", angle: 90, position: "insideRight" }}
              />

              <Tooltip content={<TooltipBox tf={tf} />} />
              <Legend formatter={(v) => <span className="text-sm">{v}</span>} onClick={onLegendClick} />

              {/* Столбцы голосов */}
              {showYes && (
                <Bar
                  yAxisId="votes"
                  dataKey="yes"
                  name="Yes"
                  fill="currentColor"
                  className="text-emerald-600 dark:text-emerald-400"
                  stackId="votes"
                />
              )}
              {showNo && (
                <Bar
                  yAxisId="votes"
                  dataKey="no"
                  name="No"
                  fill="currentColor"
                  className="text-rose-600 dark:text-rose-400"
                  stackId="votes"
                />
              )}
              {showAbstain && (
                <Bar
                  yAxisId="votes"
                  dataKey="abstain"
                  name="Abstain"
                  fill="currentColor"
                  className="text-amber-600 dark:text-amber-400"
                  stackId="votes"
                />
              )}

              {/* Линии явки */}
              {showTurnout && (
                <Line
                  yAxisId="turnout"
                  type="monotone"
                  dataKey="turnout"
                  name="Turnout"
                  stroke="currentColor"
                  className="text-primary"
                  dot={false}
                  strokeWidth={2}
                  isAnimationActive={false}
                />
              )}
              {showMATurnout && (
                <Line
                  yAxisId="turnout"
                  type="monotone"
                  dataKey="maTurnout"
                  name="Turnout MA"
                  stroke="currentColor"
                  className="text-blue-600 dark:text-blue-400"
                  dot={false}
                  strokeWidth={1.5}
                  isAnimationActive={false}
                />
              )}

              {/* Референсные линии по явке */}
              {Number.isFinite(turnoutWarn) && (
                <ReferenceLine
                  yAxisId="turnout"
                  y={turnoutWarn as number}
                  stroke="currentColor"
                  className="text-yellow-500"
                  strokeDasharray="3 3"
                  label={{ value: `warn ${turnoutWarn}%`, position: "right" }}
                />
              )}
              {Number.isFinite(turnoutGoal) && (
                <ReferenceLine
                  yAxisId="turnout"
                  y={turnoutGoal as number}
                  stroke="currentColor"
                  className="text-emerald-500"
                  strokeDasharray="3 3"
                  label={{ value: `goal ${turnoutGoal}%`, position: "right" }}
                />
              )}

              <Brush
                dataKey="tsNum"
                startIndex={initialBrush?.startIndex}
                endIndex={initialBrush?.endIndex}
                height={24}
                travellerWidth={8}
                tickFormatter={(v) => tf(new Date(v))}
                className="fill-muted/40"
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        {/* Примечание */}
        <div className="text-xs text-muted-foreground">
          Явка вычисляется как voters / eligible * 100. Если voters не задано, берется сумма yes + no + abstain.
        </div>
      </CardContent>
    </Card>
  );
};

export default VotingActivityGraph;
