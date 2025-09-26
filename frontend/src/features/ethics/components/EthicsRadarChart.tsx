// frontend/src/features/ethics/components/EthicsRadarChart.tsx
import * as React from "react";
import { memo, useMemo } from "react";
import { motion } from "framer-motion";
import {
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Tooltip,
  Legend,
} from "recharts";
import { cn } from "@/shared/lib/cn"; // если у вас нет cn, замените на свою утилиту или удалите
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";

// -----------------------------
// Types
// -----------------------------
export type EthicsDatum = {
  dimension: string;
  score: number;      // фактическое значение
  baseline?: number;  // опционально: прошлое/референт
  target?: number;    // опционально: целевое
};

export type PaletteName = "default" | "protanopiaSafe" | "grayscale";

export interface EthicsRadarChartProps {
  title?: string;
  description?: string;
  data: EthicsDatum[];
  /**
   * Минимум/максимум шкалы (по умолчанию 0..100)
   */
  minValue?: number;
  maxValue?: number;

  /**
   * Отображать ли baseline/target серии
   */
  showBaseline?: boolean;
  showTarget?: boolean;

  /**
   * Имя палитры для цветов серий
   */
  palette?: PaletteName;

  /**
   * Компактный режим уменьшает поля и подписи
   */
  compact?: boolean;

  /**
   * Кастомные форматтеры
   */
  valueFormatter?: (v: number) => string;
  dimensionFormatter?: (s: string) => string;

  /**
   * Обработчик клика по сектору/вершине
   */
  onDimensionClick?: (payload: { dimension: string; score: number }) => void;

  /**
   * Класс для контейнера
   */
  className?: string;

  /**
   * Высота диаграммы (px). По умолчанию 360
   */
  height?: number;

  /**
   * Показать легенду и тултип
   */
  showLegend?: boolean;
  showTooltip?: boolean;

  /**
   * Пользовательский ARIA-лейбл
   */
  ariaLabel?: string;
}

// -----------------------------
// Palette utils
// -----------------------------
const PALETTES: Record<
  PaletteName,
  { score: string; baseline: string; target: string; grid: string }
> = {
  default: {
    score: "hsl(222, 100%, 61%)", // синий
    baseline: "hsl(270, 95%, 68%)", // фиолетовый
    target: "hsl(147, 70%, 45%)", // зелёный
    grid: "hsl(215, 16%, 80%)",
  },
  protanopiaSafe: {
    score: "hsl(210, 90%, 50%)", // сине-голубой
    baseline: "hsl(40, 90%, 55%)", // оранжевый
    target: "hsl(120, 55%, 45%)", // зелёный
    grid: "hsl(215, 16%, 80%)",
  },
  grayscale: {
    score: "hsl(210, 9%, 40%)",
    baseline: "hsl(210, 9%, 55%)",
    target: "hsl(210, 9%, 30%)",
    grid: "hsl(215, 16%, 80%)",
  },
};

function getPalette(name?: PaletteName) {
  return PALETTES[name ?? "default"] ?? PALETTES.default;
}

// -----------------------------
// Tooltip Renderer
// -----------------------------
const DefaultTooltip = memo(function DefaultTooltip({
  active,
  payload,
  label,
  valueFormatter,
}: {
  active?: boolean;
  payload?: any[];
  label?: string;
  valueFormatter: (v: number) => string;
}) {
  if (!active || !payload || payload.length === 0) return null;

  // payload: массив точек разных серий в одной угловой метке
  return (
    <div
      className="rounded-xl border bg-background p-3 shadow-md text-sm"
      role="dialog"
      aria-label={`Показатели для ${label}`}
    >
      <div className="font-medium mb-1">{label}</div>
      <ul className="space-y-1">
        {payload.map((p, i) => {
          const name = p.name as string;
          const val = typeof p.value === "number" ? p.value : NaN;
          return (
            <li key={`${name}-${i}`} className="flex items-center gap-2">
              <span
                className="inline-block h-2 w-2 rounded-full"
                style={{ background: p.color }}
                aria-hidden
              />
              <span className="text-muted-foreground">{name}:</span>
              <span className="font-medium">
                {Number.isFinite(val) ? valueFormatter(val) : "—"}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
});

// -----------------------------
// Empty & Error states
// -----------------------------
function EmptyState({ message = "Нет данных для отображения" }) {
  return (
    <div
      className="flex h-[220px] items-center justify-center text-sm text-muted-foreground"
      role="status"
      aria-live="polite"
    >
      {message}
    </div>
  );
}

// -----------------------------
// Component
// -----------------------------
export const EthicsRadarChart = memo(function EthicsRadarChart({
  title = "Ethics Radar",
  description,
  data,
  minValue = 0,
  maxValue = 100,
  showBaseline = true,
  showTarget = true,
  palette: paletteName = "default",
  compact = false,
  valueFormatter,
  dimensionFormatter,
  onDimensionClick,
  className,
  height = 360,
  showLegend = true,
  showTooltip = true,
  ariaLabel,
}: EthicsRadarChartProps) {
  const palette = getPalette(paletteName);

  const vf = useMemo(
    () => valueFormatter ?? ((v: number) => `${v.toFixed(0)}`),
    [valueFormatter]
  );
  const df = useMemo(
    () => dimensionFormatter ?? ((s: string) => s),
    [dimensionFormatter]
  );

  // Валидация диапазона
  const domain = useMemo<[number, number]>(() => {
    const lo = Number.isFinite(minValue) ? minValue : 0;
    const hi = Number.isFinite(maxValue) ? maxValue : 100;
    return lo < hi ? [lo, hi] : [0, 100];
  }, [minValue, maxValue]);

  // Подготовка данных: приводим отсутствующие baseline/target к null
  const prepared = useMemo(() => {
    return (data ?? []).map((d) => ({
      dimension: df(d.dimension),
      score: clampNumber(d.score, domain[0], domain[1]),
      baseline:
        typeof d.baseline === "number"
          ? clampNumber(d.baseline, domain[0], domain[1])
          : null,
      target:
        typeof d.target === "number"
          ? clampNumber(d.target, domain[0], domain[1])
          : null,
    }));
  }, [data, df, domain]);

  const hasData = prepared.length > 0;

  // Анимированное появление карточки
  return (
    <Card className={cn("w-full", className)}>
      <CardHeader className={cn(compact ? "py-3" : "py-4")}>
        <CardTitle className={cn("text-lg", compact ? "text-base" : "text-lg")}>
          {title}
        </CardTitle>
        {description ? (
          <CardDescription className={cn(compact ? "text-xs" : "text-sm")}>
            {description}
          </CardDescription>
        ) : null}
      </CardHeader>

      <CardContent className={cn(compact ? "py-2" : "py-4")}>
        {!hasData ? (
          <EmptyState />
        ) : (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35, ease: "easeOut" }}
            aria-label={ariaLabel ?? "Диаграмма радар этических показателей"}
            role="img"
          >
            <div style={{ width: "100%", height }}>
              <ResponsiveContainer>
                <RadarChart
                  data={prepared}
                  cx="50%"
                  cy="50%"
                  outerRadius="75%"
                  margin={
                    compact
                      ? { top: 10, right: 10, bottom: 10, left: 10 }
                      : { top: 16, right: 24, bottom: 16, left: 24 }
                  }
                >
                  {/* Определения градиентов и паттернов */}
                  <defs>
                    <radialGradient id="radarScore" cx="50%" cy="50%" r="60%">
                      <stop offset="0%" stopColor={palette.score} stopOpacity={0.45} />
                      <stop offset="100%" stopColor={palette.score} stopOpacity={0.1} />
                    </radialGradient>
                    <linearGradient id="radarBaseline" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor={palette.baseline} stopOpacity={0.7} />
                      <stop offset="100%" stopColor={palette.baseline} stopOpacity={0.2} />
                    </linearGradient>
                    <pattern
                      id="radarTargetPattern"
                      patternUnits="userSpaceOnUse"
                      width="6"
                      height="6"
                      patternTransform="rotate(45)"
                    >
                      <rect width="6" height="6" fill="transparent" />
                      <line
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="6"
                        stroke={palette.target}
                        strokeWidth="2"
                        opacity="0.6"
                      />
                    </pattern>
                  </defs>

                  <PolarGrid
                    stroke={palette.grid}
                    strokeOpacity={0.5}
                    gridType="polygon"
                  />
                  <PolarAngleAxis
                    dataKey="dimension"
                    tick={{ fontSize: compact ? 10 : 12, fill: "currentColor" }}
                  />
                  <PolarRadiusAxis
                    domain={domain}
                    tickFormatter={vf}
                    tick={{ fontSize: compact ? 10 : 12, fill: "currentColor" }}
                    angle={90}
                    axisLine={false}
                  />

                  {/* Основная серия: фактический score */}
                  <Radar
                    name="Score"
                    dataKey="score"
                    stroke={palette.score}
                    fill="url(#radarScore)"
                    strokeWidth={2}
                    dot={{ r: 3, onClick: dotClickHandler(prepared, onDimensionClick) }}
                    isAnimationActive
                  />

                  {/* Бейзлайн (если указан и включен) */}
                  {showBaseline && prepared.some((d) => d.baseline !== null) ? (
                    <Radar
                      name="Baseline"
                      dataKey="baseline"
                      stroke={palette.baseline}
                      fill="url(#radarBaseline)"
                      fillOpacity={0.25}
                      strokeDasharray="4 2"
                      strokeWidth={2}
                      dot={{ r: 2, onClick: dotClickHandler(prepared, onDimensionClick) }}
                      isAnimationActive
                    />
                  ) : null}

                  {/* Цель (если указана и включена) */}
                  {showTarget && prepared.some((d) => d.target !== null) ? (
                    <Radar
                      name="Target"
                      dataKey="target"
                      stroke={palette.target}
                      fill="url(#radarTargetPattern)"
                      fillOpacity={0.2}
                      strokeWidth={2}
                      dot={{ r: 2, onClick: dotClickHandler(prepared, onDimensionClick) }}
                      isAnimationActive
                    />
                  ) : null}

                  {/* Подсказка и легенда */}
                  {showTooltip ? (
                    <Tooltip
                      content={(args) => (
                        <DefaultTooltip {...args} valueFormatter={vf} />
                      )}
                    />
                  ) : null}
                  {showLegend ? (
                    <Legend
                      verticalAlign="bottom"
                      wrapperStyle={{
                        paddingTop: compact ? 4 : 8,
                        color: "currentColor",
                      }}
                    />
                  ) : null}
                </RadarChart>
              </ResponsiveContainer>
            </div>

            {/* Скрытая таблица для доступности/скринридеров */}
            <VisuallyHiddenTable data={prepared} vf={vf} />
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
});

// -----------------------------
// Helpers
// -----------------------------
function clampNumber(v: number, min: number, max: number) {
  if (!Number.isFinite(v)) return min;
  return Math.min(Math.max(v, min), max);
}

function dotClickHandler(
  rows: { dimension: string; score: number; baseline: number | null; target: number | null }[],
  cb?: (payload: { dimension: string; score: number }) => void
) {
  if (!cb) return undefined as any;
  return (_: any, index: number) => {
    const r = rows[index];
    if (r) cb({ dimension: r.dimension, score: r.score });
  };
}

function VisuallyHiddenTable({
  data,
  vf,
}: {
  data: { dimension: string; score: number; baseline: number | null; target: number | null }[];
  vf: (v: number) => string;
}) {
  // Таблица для SR, не мешает визуально
  return (
    <table className="sr-only" aria-hidden={false} aria-label="Табличное представление радар-данных">
      <thead>
        <tr>
          <th>Dimension</th>
          <th>Score</th>
          <th>Baseline</th>
          <th>Target</th>
        </tr>
      </thead>
      <tbody>
        {data.map((d) => (
          <tr key={d.dimension}>
            <td>{d.dimension}</td>
            <td>{vf(d.score)}</td>
            <td>{d.baseline === null ? "—" : vf(d.baseline)}</td>
            <td>{d.target === null ? "—" : vf(d.target)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default EthicsRadarChart;
