import React, { useCallback, useMemo, useRef, useState } from "react";
import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip as ReTooltip,
  Legend,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Download, RefreshCw, AlertTriangle, Info } from "lucide-react";

/**
 * Тип отдельного домена соответствия.
 * score: текущая оценка в диапазоне 0–100
 * target: целевой порог (0–100), по умолчанию 85
 * weight: вес домена при расчете интегрального индекса (0..1), по умолчанию равномерно
 */
export interface ComplianceDomain {
  key: string;          // уникальный ключ, например "gdpr"
  label: string;        // человекочитаемое имя, например "GDPR"
  score: number;        // 0..100
  target?: number;      // 0..100
  weight?: number;      // 0..1
  description?: string; // краткое описание домена
}

/**
 * Настройки визуализации.
 */
export interface ComplianceRadarProps {
  title?: string;
  subtitle?: string;
  domains: ComplianceDomain[];
  /** Если true — показываем скелетон/лоадер поверх контента */
  loading?: boolean;
  /** Включить экспорт PNG/CSV */
  enableExport?: boolean;
  /** Вызывать при клике по сектору/точке */
  onPointClick?: (domain: ComplianceDomain) => void;
  /** Высота чарта в px (адаптивная ширина остается) */
  height?: number;
  /** Жесткая нормализация пределов радиуса (по умолчанию 0..100) */
  radiusDomain?: [number, number];
  /** Порог для подсветки высокого риска (если score < riskThreshold) */
  riskThreshold?: number; // по умолчанию 60
  /** Включить легенду и тултип */
  showLegend?: boolean;
  showTooltip?: boolean;
  /** Пользовательский класс контейнера */
  className?: string;
}

/** Значения по умолчанию */
const DEFAULT_TARGET = 85;
const DEFAULT_RISK_THRESHOLD = 60;

type RadarDatum = {
  subject: string;
  key: string;
  score: number;
  target: number;
};

/** Нормализация чисел в пределах 0..100 */
function clamp01(x: number): number {
  if (Number.isNaN(x) || !Number.isFinite(x)) return 0;
  return Math.max(0, Math.min(100, x));
}

/** Вычисление интегрального взвешенного индекса соответствия */
function computeWeightedIndex(domains: ComplianceDomain[]): number {
  if (!domains.length) return 0;
  const weightsProvided = domains.some((d) => typeof d.weight === "number");
  const weightSum = weightsProvided
    ? domains.reduce((acc, d) => acc + (d.weight ?? 0), 0)
    : domains.length;

  if (weightSum <= 0) return 0;

  const total = domains.reduce((acc, d) => {
    const w = weightsProvided ? (d.weight ?? 0) : 1;
    return acc + clamp01(d.score) * (w / weightSum);
  }, 0);

  return Math.round(total * 100) / 100;
}

/** Цветовая зона риска: красный < порога, желтый между порогом и target, зеленый >= target */
function zoneForScore(score: number, target: number, risk: number): "low" | "medium" | "high" {
  if (score < risk) return "low";
  if (score < target) return "medium";
  return "high";
}

/** Классы Tailwind для бейджей зоны */
function badgeClass(zone: "low" | "medium" | "high"): string {
  switch (zone) {
    case "low":
      return "bg-red-600/10 text-red-700 dark:text-red-300 border border-red-600/30";
    case "medium":
      return "bg-yellow-600/10 text-yellow-700 dark:text-yellow-300 border border-yellow-600/30";
    default:
      return "bg-emerald-600/10 text-emerald-700 dark:text-emerald-300 border border-emerald-600/30";
  }
}

/** Цвет для линий на радаре по зоне риска */
function strokeFillByZone(zone: "low" | "medium" | "high") {
  switch (zone) {
    case "low":
      return { stroke: "currentColor", fill: "rgba(220,38,38,0.25)" }; // red-600
    case "medium":
      return { stroke: "currentColor", fill: "rgba(234,179,8,0.25)" }; // yellow-500
    default:
      return { stroke: "currentColor", fill: "rgba(16,185,129,0.25)" }; // emerald-500
  }
}

/** Утилита экспорта SVG Recharts в PNG */
async function exportChartAsPNG(svgEl: SVGSVGElement, fileName = "compliance-radar.png") {
  const serializer = new XMLSerializer();
  const svgString = serializer.serializeToString(svgEl);

  // Создаем Blob из SVG
  const svgBlob = new Blob([svgString], { type: "image/svg+xml;charset=utf-8" });
  const url = URL.createObjectURL(svgBlob);

  // Загружаем в Image и рисуем на canvas
  const img = new Image();
  const devicePixelRatio = window.devicePixelRatio || 1;
  const width = svgEl.viewBox.baseVal.width || svgEl.getBoundingClientRect().width || 800;
  const height = svgEl.viewBox.baseVal.height || svgEl.getBoundingClientRect().height || 600;

  const canvas = document.createElement("canvas");
  canvas.width = Math.ceil(width * devicePixelRatio);
  canvas.height = Math.ceil(height * devicePixelRatio);
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  // Масштаб для четкости на HiDPI
  ctx.scale(devicePixelRatio, devicePixelRatio);

  await new Promise<void>((resolve, reject) => {
    img.onload = () => {
      ctx.clearRect(0, 0, width, height);
      ctx.drawImage(img, 0, 0, width, height);
      URL.revokeObjectURL(url);
      resolve();
    };
    img.onerror = (e) => reject(e);
    img.src = url;
  });

  // Скачиваем PNG
  const a = document.createElement("a");
  a.download = fileName;
  a.href = canvas.toDataURL("image/png");
  a.click();
}

/** Экспорт CSV */
function exportCSV(domains: ComplianceDomain[], fileName = "compliance-radar.csv") {
  const header = ["key", "label", "score", "target", "weight", "description"];
  const rows = domains.map((d) => [
    d.key,
    d.label.replace(/"/g, '""'),
    String(clamp01(d.score)),
    String(typeof d.target === "number" ? clamp01(d.target) : DEFAULT_TARGET),
    String(typeof d.weight === "number" ? d.weight : ""),
    d.description ? `"${d.description.replace(/"/g, '""')}"` : "",
  ]);
  const csv = [header.join(","), ...rows.map((r) => r.join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
}

/** Кастомный тултип Recharts */
const CustomTooltip: React.FC<{
  active?: boolean;
  payload?: any[];
  label?: string;
}> = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null;
  const datum = payload[0]?.payload as RadarDatum | undefined;
  if (!datum) return null;

  return (
    <div
      role="dialog"
      aria-label={`Детали домена ${label}`}
      className="rounded-xl border bg-background/95 backdrop-blur px-3 py-2 shadow-lg text-sm"
    >
      <div className="font-medium">{label}</div>
      <div className="mt-1 grid grid-cols-2 gap-x-6 gap-y-1">
        <div className="text-muted-foreground">Текущий</div>
        <div>{datum.score}</div>
        <div className="text-muted-foreground">Целевой</div>
        <div>{datum.target}</div>
        <div className="text-muted-foreground">Дельта</div>
        <div>{Math.round((datum.score - datum.target) * 100) / 100}</div>
      </div>
    </div>
  );
};

export const ComplianceRadar: React.FC<ComplianceRadarProps> = ({
  title = "Compliance Radar",
  subtitle = "Обзор доменов соответствия",
  domains,
  loading = false,
  enableExport = true,
  onPointClick,
  height = 420,
  radiusDomain = [0, 100],
  riskThreshold = DEFAULT_RISK_THRESHOLD,
  showLegend = true,
  showTooltip = true,
  className,
}) => {
  const [chartKey, setChartKey] = useState<number>(0);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const cleaned = useMemo<ComplianceDomain[]>(
    () =>
      domains
        .filter(
          (d) =>
            d &&
            typeof d.key === "string" &&
            typeof d.label === "string" &&
            Number.isFinite(d.score)
        )
        .map((d) => ({
          ...d,
          score: clamp01(d.score),
          target: typeof d.target === "number" ? clamp01(d.target) : DEFAULT_TARGET,
          weight: typeof d.weight === "number" ? d.weight : undefined,
        })),
    [domains]
  );

  const weightedIndex = useMemo(() => computeWeightedIndex(cleaned), [cleaned]);

  const data = useMemo<RadarDatum[]>(
    () =>
      cleaned.map((d) => ({
        subject: d.label,
        key: d.key,
        score: d.score,
        target: d.target ?? DEFAULT_TARGET,
      })),
    [cleaned]
  );

  const hasData = cleaned.length > 0;

  const handleRefresh = useCallback(() => {
    // Перерисовка чарта без смены данных, полезно при глитчах ресайза
    setChartKey((k) => k + 1);
  }, []);

  const handleExportPNG = useCallback(() => {
    const svg = svgRef.current;
    if (!svg) return;
    exportChartAsPNG(svg, "compliance-radar.png");
  }, []);

  const handleExportCSV = useCallback(() => {
    exportCSV(cleaned, "compliance-radar.csv");
  }, [cleaned]);

  const riskZones = useMemo(() => {
    const zones = cleaned.map((d) => ({
      key: d.key,
      label: d.label,
      zone: zoneForScore(d.score, d.target ?? DEFAULT_TARGET, riskThreshold),
    }));
    const counts = zones.reduce(
      (acc, z) => {
        acc[z.zone]++;
        return acc;
      },
      { low: 0, medium: 0, high: 0 } as Record<"low" | "medium" | "high", number>
    );
    return { zones, counts };
  }, [cleaned, riskThreshold]);

  return (
    <Card
      className={[
        "w-full border-muted/50 shadow-sm",
        "rounded-2xl",
        "bg-background",
        className ?? "",
      ].join(" ")}
      aria-busy={loading ? "true" : "false"}
      aria-live="polite"
      aria-label="Радар соответствия"
    >
      <CardHeader className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <CardTitle className="text-xl md:text-2xl">{title}</CardTitle>
          <div className="flex items-center gap-2">
            {enableExport && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleExportCSV}
                  aria-label="Экспорт в CSV"
                >
                  <Download className="mr-2 h-4 w-4" />
                  CSV
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleExportPNG}
                  aria-label="Экспорт в PNG"
                >
                  <Download className="mr-2 h-4 w-4" />
                  PNG
                </Button>
              </>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              aria-label="Обновить визуализацию"
            >
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
          <span>{subtitle}</span>
          <span className="inline-flex items-center gap-2">
            <Info className="h-4 w-4" />
            Интегральный индекс:
            <Badge className="ml-1 bg-primary/10 text-primary border border-primary/20">
              {weightedIndex}
            </Badge>
          </span>
          <span className="inline-flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Риск-порог:
            <Badge variant="outline" className="ml-1">
              {riskThreshold}
            </Badge>
          </span>
          <div className="ml-auto flex items-center gap-2">
            <Badge className={badgeClass("low")}>Высокий риск</Badge>
            <Badge className={badgeClass("medium")}>Средний риск</Badge>
            <Badge className={badgeClass("high")}>Низкий риск</Badge>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        {!hasData && !loading && (
          <div
            className="flex h-64 items-center justify-center rounded-xl border border-dashed"
            role="status"
            aria-label="Нет данных"
          >
            Нет данных для отображения
          </div>
        )}

        {loading && (
          <div className="animate-pulse rounded-xl border p-4">
            <div className="mb-4 h-6 w-40 rounded bg-muted" />
            <div className="h-[360px] rounded bg-muted" />
          </div>
        )}

        {hasData && !loading && (
          <div className="w-full">
            <div className="relative">
              <div className="absolute left-2 top-2 z-[1] text-xs text-muted-foreground">
                Диапазон: {radiusDomain[0]}–{radiusDomain[1]}
              </div>
              <ResponsiveContainer width="100%" height={height}>
                {/* Обертка для получения ссылки на SVG */}
                <RadarChart
                  key={chartKey}
                  data={data}
                  cx="50%"
                  cy="50%"
                  outerRadius="70%"
                  onClick={(e) => {
                    // Recharts onClick для всей области; достанем активный payload
                    const payload = (e && (e as any).activePayload?.[0]?.payload) as
                      | RadarDatum
                      | undefined;
                    if (payload && onPointClick) {
                      const domain = cleaned.find((d) => d.key === payload.key);
                      if (domain) onPointClick(domain);
                    }
                  }}
                  // Пробросим ref до вложенного svg через callback после монтирования
                  ref={
                    // @ts-expect-error — типы Recharts не экспонируют внутренний svg,
                    // поэтому достанем его по селектору на следующем тике.
                    (node: any) => {
                      if (!node) return;
                      // небольшой timeout чтобы DOM построился
                      setTimeout(() => {
                        const svg = (node.container?.querySelector?.("svg") ??
                          node?.container) as SVGSVGElement | null;
                        if (svg) {
                          svgRef.current = svg;
                        }
                      }, 0);
                    }
                  }
                >
                  <PolarGrid className="text-muted-foreground/40" />
                  <PolarAngleAxis
                    dataKey="subject"
                    tick={{ fontSize: 12 }}
                    className="fill-foreground"
                  />
                  <PolarRadiusAxis
                    angle={30}
                    domain={radiusDomain}
                    tick={{ fontSize: 10 }}
                  />
                  {/* Текущий скор */}
                  <Radar
                    name="Текущий"
                    dataKey="score"
                    stroke="currentColor"
                    fillOpacity={0.3}
                    className="text-primary"
                  />
                  {/* Целевой контур */}
                  <Radar
                    name="Целевой"
                    dataKey="target"
                    stroke="currentColor"
                    fillOpacity={0.1}
                    className="text-muted-foreground"
                  />

                  {showTooltip && <ReTooltip content={<CustomTooltip />} />}
                  {showLegend && <Legend verticalAlign="bottom" height={36} />}
                </RadarChart>
              </ResponsiveContainer>
            </div>

            {/* Сводка рисков */}
            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <div className="rounded-xl border p-3">
                <div className="text-sm text-muted-foreground">Высокий риск</div>
                <div className="mt-1 text-lg font-semibold">{riskZones.counts.low}</div>
              </div>
              <div className="rounded-xl border p-3">
                <div className="text-sm text-muted-foreground">Средний риск</div>
                <div className="mt-1 text-lg font-semibold">{riskZones.counts.medium}</div>
              </div>
              <div className="rounded-xl border p-3">
                <div className="text-sm text-muted-foreground">Низкий риск</div>
                <div className="mt-1 text-lg font-semibold">{riskZones.counts.high}</div>
              </div>
            </div>

            {/* Таблица доменов */}
            <div className="mt-4 overflow-x-auto">
              <table
                className="w-full text-sm"
                aria-label="Таблица доменов соответствия"
              >
                <thead>
                  <tr className="text-left text-muted-foreground">
                    <th className="px-2 py-2">Домен</th>
                    <th className="px-2 py-2">Скор</th>
                    <th className="px-2 py-2">Цель</th>
                    <th className="px-2 py-2">Дельта</th>
                    <th className="px-2 py-2">Вес</th>
                    <th className="px-2 py-2">Зона</th>
                  </tr>
                </thead>
                <tbody>
                  {cleaned.map((d) => {
                    const z = zoneForScore(d.score, d.target ?? DEFAULT_TARGET, riskThreshold);
                    const delta = Math.round((d.score - (d.target ?? DEFAULT_TARGET)) * 100) / 100;
                    const sf = strokeFillByZone(z);
                    return (
                      <tr key={d.key} className="border-t">
                        <td className="px-2 py-2">
                          <div className="flex flex-col">
                            <span className="font-medium">{d.label}</span>
                            {d.description && (
                              <span className="text-xs text-muted-foreground">
                                {d.description}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-2 py-2">{d.score}</td>
                        <td className="px-2 py-2">{d.target ?? DEFAULT_TARGET}</td>
                        <td className="px-2 py-2">{delta}</td>
                        <td className="px-2 py-2">{d.weight ?? "—"}</td>
                        <td className="px-2 py-2">
                          <Badge className={badgeClass(z)}>{z === "low" ? "Высокий" : z === "medium" ? "Средний" : "Низкий"}</Badge>
                          <span
                            className="ml-2 inline-block h-3 w-3 rounded-full align-middle"
                            style={{ background: sf.fill }}
                            aria-hidden="true"
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ComplianceRadar;
