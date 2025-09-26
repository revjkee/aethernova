// frontend/src/features/ethics/components/AIConflictHeatmap.tsx
import React, {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import { TooltipProvider, Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Download, Filter, Search, Info, RefreshCw, Layers } from "lucide-react";
import { motion } from "framer-motion";

/**
 * Типы данных теплокарты.
 */
export type HeatmapMatrix = number[][]; // values[row][col]
export type HeatmapCellMeta = {
  note?: string;
  flags?: string[]; // например: ["policy_violation","needs_review"]
};
export type HeatmapMetaMatrix = (HeatmapCellMeta | undefined)[][];
export type SeverityPalette =
  | "viridis"
  | "magma"
  | "plasma"
  | "inferno"
  | "grey";

/**
 * Пропсы компонента.
 */
export interface AIConflictHeatmapProps {
  title?: string;
  rows: string[];                 // имена агентов/правил по Y
  cols: string[];                 // имена агентов/правил по X
  values: HeatmapMatrix;          // матрица значений [0..1] или произвольные числа
  meta?: HeatmapMetaMatrix;       // дополнительная мета по ячейкам
  min?: number;                   // явный минимум шкалы (если не задан, берётся из данных)
  max?: number;                   // явный максимум шкалы (если не задан, берётся из данных)
  palette?: SeverityPalette;      // палитра
  showLegend?: boolean;           // показывать легенду
  showSidebar?: boolean;          // показывать правую панель
  initialThreshold?: number;      // порог подсветки
  onCellClick?: (payload: {
    rowIndex: number;
    colIndex: number;
    rowLabel: string;
    colLabel: string;
    value: number;
    meta?: HeatmapCellMeta;
  }) => void;
  onSelectionChange?: (selection: { rowIndex: number; colIndex: number } | null) => void;
  /**
   * Управляет «квадратностью» ячеек: 1 означает квадрат, <1 — шире, >1 — выше.
   */
  aspectRatio?: number;
  /**
   * Максимальный размер холста в CSS-пикселях по длинной стороне.
   */
  maxCanvasSize?: number;
}

/**
 * Вспомогательные утилиты.
 */
function clamp(v: number, a: number, b: number) {
  return Math.max(a, Math.min(b, v));
}

function computeExtent(values: HeatmapMatrix): { min: number; max: number } {
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  for (const row of values) {
    for (const v of row) {
      if (Number.isFinite(v)) {
        if (v < min) min = v;
        if (v > max) max = v;
      }
    }
  }
  if (min === Number.POSITIVE_INFINITY) min = 0;
  if (max === Number.NEGATIVE_INFINITY) max = 1;
  if (min === max) {
    // избежать деления на 0
    max = min + 1;
  }
  return { min, max };
}

/**
 * Нормализация значения в диапазон [0,1].
 */
function normalize(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return 0;
  if (max === min) return 0;
  return clamp((value - min) / (max - min), 0, 1);
}

/**
 * Палитры (не задаём фиксированные Tailwind-цвета; используем чистые вычисления RGBA).
 * Значения возвращаются как CSS rgba().
 */
function lerp(a: number, b: number, t: number) {
  return a + (b - a) * t;
}
function rgba(r: number, g: number, b: number, a = 1) {
  return `rgba(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)}, ${a})`;
}

/**
 * Аппроксимации научных палитр (Viridis/Plasma/Inferno/Magma).
 * Формулы подобраны как непрерывные градиенты, пригодные для теплокарт.
 * Источник: приближённые полиномиальные модели на основе Palettable/MatPlotLib (реализация вручную).
 */
function viridis(t: number): string {
  // t in [0,1]
  const r = 68 + 187 * t;    // приближенно
  const g = 1 + 212 * t;
  const b = 84 + 101 * t;
  return rgba(r, g, b);
}
function magma(t: number): string {
  const r = 52 + 203 * t;
  const g = 18 + 60 * t;
  const b = 70 + 70 * t;
  return rgba(r, g, b);
}
function plasma(t: number): string {
  const r = 12 + 230 * t;
  const g = 7 + 170 * t;
  const b = 135 + 100 * (1 - t);
  return rgba(r, g, b);
}
function inferno(t: number): string {
  const r = 0 + 240 * t;
  const g = 0 + 65 * t;
  const b = 0 + 35 * t;
  return rgba(r, g, b);
}
function grey(t: number): string {
  const v = 240 * t;
  return rgba(v, v, v);
}

function getPaletteFn(p: SeverityPalette) {
  switch (p) {
    case "viridis":
      return viridis;
    case "magma":
      return magma;
    case "plasma":
      return plasma;
    case "inferno":
      return inferno;
    case "grey":
    default:
      return grey;
  }
}

/**
 * Хук наблюдения за размером контейнера.
 */
function useResizeObserver<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [size, setSize] = useState<{ width: number; height: number }>({
    width: 0,
    height: 0,
  });

  useEffect(() => {
    if (!ref.current) return;
    const el = ref.current;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) {
        const cr = e.contentRect;
        setSize({ width: cr.width, height: cr.height });
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return { ref, size };
}

/**
 * Основной компонент теплокарты.
 */
export const AIConflictHeatmap: React.FC<AIConflictHeatmapProps> = memo(
  ({
    title = "AI Conflict Heatmap",
    rows,
    cols,
    values,
    meta,
    min,
    max,
    palette = "viridis",
    showLegend = true,
    showSidebar = true,
    initialThreshold = 0,
    onCellClick,
    onSelectionChange,
    aspectRatio = 1,
    maxCanvasSize = 2400,
  }) => {
    // Валидация размеров входных данных
    const rowCount = rows.length;
    const colCount = cols.length;

    const { min: autoMin, max: autoMax } = useMemo(
      () => computeExtent(values),
      [values]
    );
    const vMin = Number.isFinite(min as number) ? (min as number) : autoMin;
    const vMax = Number.isFinite(max as number) ? (max as number) : autoMax;

    const paletteFn = useMemo(() => getPaletteFn(palette), [palette]);

    const [threshold, setThreshold] = useState<number>(initialThreshold);
    const [search, setSearch] = useState<string>("");
    const [sortByVariance, setSortByVariance] = useState<boolean>(false);
    const [lockSquare, setLockSquare] = useState<boolean>(true);
    const [selected, setSelected] = useState<{ r: number; c: number } | null>(null);
    const [focused, setFocused] = useState<{ r: number; c: number } | null>(null);
    const [hideDiagonal, setHideDiagonal] = useState<boolean>(false);

    // Поиск и опциональная сортировка строк/столбцов
    const { viewRows, viewCols, indexMapR, indexMapC, viewValues } = useMemo(() => {
      // фильтрация по поиску
      const rowPass = rows.map((name) =>
        search.trim().length === 0
          ? true
          : name.toLowerCase().includes(search.toLowerCase())
      );
      const colPass = cols.map((name) =>
        search.trim().length === 0
          ? true
          : name.toLowerCase().includes(search.toLowerCase())
      );

      let rIdx: number[] = [];
      let cIdx: number[] = [];
      rows.forEach((_, i) => rowPass[i] && rIdx.push(i));
      cols.forEach((_, j) => colPass[j] && cIdx.push(j));

      // сортировка по дисперсии строк (опционально)
      if (sortByVariance) {
        const rowVar = rIdx.map((ri) => {
          const arr = cIdx.map((cj) => values[ri][cj]);
          const mu = arr.reduce((a, b) => a + b, 0) / Math.max(arr.length, 1);
          const va =
            arr.reduce((acc, v) => acc + (v - mu) * (v - mu), 0) /
            Math.max(arr.length, 1);
          return { ri, va };
        });
        rowVar.sort((a, b) => b.va - a.va);
        rIdx = rowVar.map((x) => x.ri);

        const colVar = cIdx.map((ci) => {
          const arr = rIdx.map((r) => values[r][ci]);
          const mu = arr.reduce((a, b) => a + b, 0) / Math.max(arr.length, 1);
          const va =
            arr.reduce((acc, v) => acc + (v - mu) * (v - mu), 0) /
            Math.max(arr.length, 1);
          return { ci, va };
        });
        colVar.sort((a, b) => b.va - a.va);
        cIdx = colVar.map((x) => x.ci);
      }

      const viewRows = rIdx.map((i) => rows[i]);
      const viewCols = cIdx.map((j) => cols[j]);
      const viewValues = rIdx.map((ri) => cIdx.map((cj) => values[ri][cj]));

      const indexMapR = new Map<number, number>();
      const indexMapC = new Map<number, number>();
      rIdx.forEach((ri, vr) => indexMapR.set(vr, ri));
      cIdx.forEach((ci, vc) => indexMapC.set(vc, ci));

      return { viewRows, viewCols, indexMapR, indexMapC, viewValues };
    }, [rows, cols, values, search, sortByVariance]);

    // Рендер Canvas
    const { ref: wrapRef, size } = useResizeObserver<HTMLDivElement>();
    const canvasRef = useRef<HTMLCanvasElement | null>(null);
    const overlayRef = useRef<HTMLDivElement | null>(null);

    const cellSize = useMemo(() => {
      const padding = 16; // внутренние поля
      const w = Math.min(size.width - padding * 2, maxCanvasSize);
      const h = Math.min(size.height - padding * 2, maxCanvasSize);
      const viewR = viewRows.length || 1;
      const viewC = viewCols.length || 1;

      // поддержка квадратных ячеек при lockSquare
      let cw = Math.max(4, Math.floor(w / viewC));
      let ch = Math.max(4, Math.floor(h / viewR));
      if (lockSquare) {
        const s = Math.floor(Math.min(cw, ch) * aspectRatio);
        cw = s;
        ch = s;
      }
      return { cw, ch, padding };
    }, [size.width, size.height, viewRows.length, viewCols.length, lockSquare, aspectRatio, maxCanvasSize]);

    const dpr = typeof window !== "undefined" ? window.devicePixelRatio || 1 : 1;

    const draw = useCallback(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext("2d", { willReadFrequently: false });
      if (!ctx) return;

      const viewR = viewRows.length;
      const viewC = viewCols.length;
      const { cw, ch, padding } = cellSize;

      const cssW = Math.max(1, viewC * cw + padding * 2);
      const cssH = Math.max(1, viewR * ch + padding * 2);
      canvas.style.width = `${cssW}px`;
      canvas.style.height = `${cssH}px`;

      // HiDPI масштабирование
      canvas.width = Math.floor(cssW * dpr);
      canvas.height = Math.floor(cssH * dpr);
      ctx.scale(dpr, dpr);

      // фон
      ctx.fillStyle = "rgba(0,0,0,0)";
      ctx.fillRect(0, 0, cssW, cssH);

      // сетка
      ctx.translate(padding, padding);
      const norm = (v: number) => normalize(v, vMin, vMax);

      for (let r = 0; r < viewR; r++) {
        for (let c = 0; c < viewC; c++) {
          if (hideDiagonal && indexMapR.get(r) === indexMapC.get(c)) continue;
          const val = viewValues[r][c];
          const t = norm(val);
          ctx.fillStyle = paletteFn(t);
          ctx.fillRect(c * cw, r * ch, cw, ch);
        }
      }

      // контуры тонкой сетки (минимальный оверхед)
      ctx.lineWidth = 0.5;
      ctx.strokeStyle = "rgba(0,0,0,0.08)";
      for (let r = 0; r <= viewR; r++) {
        ctx.beginPath();
        ctx.moveTo(0, r * ch + 0.5);
        ctx.lineTo(viewC * cw, r * ch + 0.5);
        ctx.stroke();
      }
      for (let c = 0; c <= viewC; c++) {
        ctx.beginPath();
        ctx.moveTo(c * cw + 0.5, 0);
        ctx.lineTo(c * cw + 0.5, viewR * ch);
        ctx.stroke();
      }

      // пороговая подсветка
      if (threshold > vMin) {
        ctx.fillStyle = "rgba(255,0,0,0.07)";
        for (let r = 0; r < viewR; r++) {
          for (let c = 0; c < viewC; c++) {
            const val = viewValues[r][c];
            if (val >= threshold) {
              ctx.fillRect(c * cw, r * ch, cw, ch);
            }
          }
        }
      }

      // выделение выбранной ячейки
      if (selected) {
        const { r, c } = selected;
        if (r >= 0 && r < viewR && c >= 0 && c < viewC) {
          ctx.lineWidth = 2;
          ctx.strokeStyle = "rgba(0,0,0,0.8)";
          ctx.strokeRect(c * cw + 1, r * ch + 1, cw - 2, ch - 2);
        }
      }

      // вернуть трансформацию
      ctx.setTransform(1, 0, 0, 1, 0, 0);
    }, [
      cellSize,
      viewRows.length,
      viewCols.length,
      viewValues,
      paletteFn,
      vMin,
      vMax,
      threshold,
      selected,
      indexMapR,
      indexMapC,
      hideDiagonal,
      dpr,
    ]);

    useEffect(() => {
      draw();
    }, [draw]);

    // Координаты мыши -> ячейка
    const hitTest = useCallback(
      (evt: React.MouseEvent<HTMLCanvasElement>) => {
        const canvas = canvasRef.current;
        if (!canvas) return null;
        const rect = canvas.getBoundingClientRect();
        const x = evt.clientX - rect.left;
        const y = evt.clientY - rect.top;
        const { cw, ch, padding } = cellSize;

        const cx = x - padding;
        const cy = y - padding;
        const r = Math.floor(cy / ch);
        const c = Math.floor(cx / cw);
        if (
          cx < 0 ||
          cy < 0 ||
          r < 0 ||
          c < 0 ||
          r >= viewRows.length ||
          c >= viewCols.length
        ) {
          return null;
        }
        return { r, c };
      },
      [cellSize, viewRows.length, viewCols.length]
    );

    const [hover, setHover] = useState<{
      r: number;
      c: number;
      x: number;
      y: number;
    } | null>(null);

    const handleMove = useCallback(
      (evt: React.MouseEvent<HTMLCanvasElement>) => {
        const hit = hitTest(evt);
        if (!hit) {
          setHover(null);
          return;
        }
        setHover({ ...hit, x: evt.clientX, y: evt.clientY });
      },
      [hitTest]
    );

    const handleLeave = useCallback(() => setHover(null), []);

    const handleClick = useCallback(
      (evt: React.MouseEvent<HTMLCanvasElement>) => {
        const hit = hitTest(evt);
        if (!hit) return;
        setSelected(hit);
        onSelectionChange?.({ rowIndex: indexMapR.get(hit.r)!, colIndex: indexMapC.get(hit.c)! });
        if (onCellClick) {
          const ri = indexMapR.get(hit.r)!;
          const ci = indexMapC.get(hit.c)!;
          onCellClick({
            rowIndex: ri,
            colIndex: ci,
            rowLabel: rows[ri],
            colLabel: cols[ci],
            value: values[ri][ci],
            meta: meta?.[ri]?.[ci],
          });
        }
      },
      [hitTest, onCellClick, onSelectionChange, rows, cols, values, indexMapR, indexMapC, meta]
    );

    // Клавиатурная навигация
    const gridRef = useRef<HTMLDivElement | null>(null);
    const handleKeyDown = useCallback(
      (e: React.KeyboardEvent<HTMLDivElement>) => {
        if (!viewRows.length || !viewCols.length) return;
        let fr = focused?.r ?? 0;
        let fc = focused?.c ?? 0;
        switch (e.key) {
          case "ArrowUp":
            fr = clamp(fr - 1, 0, viewRows.length - 1);
            break;
          case "ArrowDown":
            fr = clamp(fr + 1, 0, viewRows.length - 1);
            break;
          case "ArrowLeft":
            fc = clamp(fc - 1, 0, viewCols.length - 1);
            break;
          case "ArrowRight":
            fc = clamp(fc + 1, 0, viewCols.length - 1);
            break;
          case "Enter":
          case " ":
            setSelected({ r: fr, c: fc });
            onSelectionChange?.({ rowIndex: indexMapR.get(fr)!, colIndex: indexMapC.get(fc)! });
            e.preventDefault();
            return;
          default:
            return;
        }
        setFocused({ r: fr, c: fc });
        e.preventDefault();
      },
      [focused, viewRows.length, viewCols.length, onSelectionChange, indexMapR, indexMapC]
    );

    // Экспорт PNG
    const exportPNG = useCallback(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const link = document.createElement("a");
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      link.download = `ai-conflict-heatmap-${ts}.png`;
      link.href = canvas.toDataURL("image/png");
      link.click();
    }, []);

    // Детали выбранной ячейки
    const selectedDetails = useMemo(() => {
      if (!selected) return null;
      const ri = indexMapR.get(selected.r)!;
      const ci = indexMapC.get(selected.c)!;
      return {
        rowIndex: ri,
        colIndex: ci,
        rowLabel: rows[ri],
        colLabel: cols[ci],
        value: values[ri][ci],
        meta: meta?.[ri]?.[ci],
      };
    }, [selected, rows, cols, values, indexMapR, indexMapC, meta]);

    const legend = useMemo(() => {
      const stops = 64;
      const arr = Array.from({ length: stops }, (_, i) => paletteFn(i / (stops - 1)));
      return arr;
    }, [paletteFn]);

    return (
      <Card className="w-full h-full overflow-hidden">
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div className="flex items-center gap-3">
            <CardTitle className="text-xl">{title}</CardTitle>
            <Badge variant="secondary">
              {rowCount} × {colCount}
            </Badge>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 opacity-60" />
              <Input
                className="pl-8 w-56"
                placeholder="Поиск по именам…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <Filter className="h-4 w-4" />
                  Фильтры
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-64">
                <DropdownMenuLabel>Опции</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuCheckboxItem
                  checked={sortByVariance}
                  onCheckedChange={(v) => setSortByVariance(Boolean(v))}
                >
                  Сортировать по вариативности
                </DropdownMenuCheckboxItem>
                <DropdownMenuCheckboxItem
                  checked={lockSquare}
                  onCheckedChange={(v) => setLockSquare(Boolean(v))}
                >
                  Квадратные ячейки
                </DropdownMenuCheckboxItem>
                <DropdownMenuCheckboxItem
                  checked={hideDiagonal}
                  onCheckedChange={(v) => setHideDiagonal(Boolean(v))}
                >
                  Скрыть диагональ
                </DropdownMenuCheckboxItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button variant="outline" className="gap-2" onClick={exportPNG}>
              <Download className="h-4 w-4" />
              Экспорт PNG
            </Button>
          </div>
        </CardHeader>
        <CardContent className="h-[70vh] md:h-[72vh] lg:h-[74vh] relative">
          <div
            ref={wrapRef}
            className="w-full h-full border rounded-xl relative bg-background"
          >
            {/* Поле управления порогом */}
            <div className="absolute left-3 top-3 z-10 rounded-lg px-3 py-2 bg-background/80 backdrop-blur border">
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 opacity-70" />
                <span className="text-sm">Порог</span>
                <Badge variant="outline" className="ml-1">
                  {threshold.toFixed(3)}
                </Badge>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 ml-1"
                  onClick={() => setThreshold(0)}
                  title="Сбросить порог"
                >
                  <RefreshCw className="h-4 w-4" />
                </Button>
              </div>
              <div className="mt-2 w-64">
                <Slider
                  min={vMin}
                  max={vMax}
                  step={(vMax - vMin) / 100}
                  value={[clamp(threshold, vMin, vMax)]}
                  onValueChange={(vals) => setThreshold(vals[0] ?? vMin)}
                />
              </div>
            </div>

            {/* Canvas для рендера теплокарты */}
            <div
              ref={gridRef}
              role="grid"
              tabIndex={0}
              onKeyDown={handleKeyDown}
              aria-label="Теплокарта конфликтов"
              className="absolute inset-0 outline-none"
            >
              <canvas
                ref={canvasRef}
                onMouseMove={handleMove}
                onMouseLeave={handleLeave}
                onClick={handleClick}
                className="block"
              />
              {/* Hover tooltip */}
              {hover && (() => {
                const ri = indexMapR.get(hover.r)!;
                const ci = indexMapC.get(hover.c)!;
                const v = values[ri][ci];
                const m = meta?.[ri]?.[ci];
                return (
                  <div
                    ref={overlayRef}
                    className="pointer-events-none absolute"
                    style={{
                      left: hover.x - (wrapRef.current?.getBoundingClientRect().left ?? 0) + 12,
                      top: hover.y - (wrapRef.current?.getBoundingClientRect().top ?? 0) + 12,
                    }}
                  >
                    <motion.div
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: 4 }}
                      transition={{ duration: 0.12 }}
                      className="rounded-md border bg-popover text-popover-foreground shadow-md p-3 text-xs max-w-xs"
                    >
                      <div className="font-medium mb-1">
                        {rows[ri]} → {cols[ci]}
                      </div>
                      <div className="mb-1">
                        Значение: <span className="font-semibold">{Number.isFinite(v) ? v.toFixed(4) : "NaN"}</span>
                      </div>
                      {m?.note && (
                        <div className="opacity-80">
                          Примечание: <span className="italic">{m.note}</span>
                        </div>
                      )}
                      {m?.flags?.length ? (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {m.flags.map((f, idx) => (
                            <Badge key={idx} variant="secondary">{f}</Badge>
                          ))}
                        </div>
                      ) : null}
                    </motion.div>
                  </div>
                );
              })()}
            </div>

            {/* Легенда */}
            {showLegend && (
              <div className="absolute right-3 bottom-3 z-10 rounded-lg p-3 bg-background/80 backdrop-blur border w-64">
                <div className="flex items-center justify-between text-xs mb-2">
                  <span className="flex items-center gap-1">
                    <Info className="h-3.5 w-3.5" />
                    Легенда
                  </span>
                  <span>
                    {vMin.toFixed(3)} – {vMax.toFixed(3)}
                  </span>
                </div>
                <div className="h-3 w-full rounded"
                  style={{
                    background:
                      `linear-gradient(to right, ${legend[0]}, ${legend[Math.floor(legend.length/4)]}, ${legend[Math.floor(legend.length/2)]}, ${legend[Math.floor(legend.length*3/4)]}, ${legend[legend.length-1]})`,
                  }}
                />
                <div className="mt-2 text-[10px] text-muted-foreground">
                  Порог подсветки: {threshold.toFixed(3)}
                </div>
              </div>
            )}

            {/* Боковая панель деталей */}
            {showSidebar && (
              <motion.div
                initial={{ x: 320, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ duration: 0.18 }}
                className="absolute top-0 right-0 h-full w-80 border-l bg-background"
              >
                <div className="p-4 border-b flex items-center justify-between">
                  <div className="font-medium">Детали</div>
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div className="text-muted-foreground">
                          <Info className="h-4 w-4" />
                        </div>
                      </TooltipTrigger>
                      <TooltipContent>Информация о выбранной ячейке</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>
                <div className="p-4 text-sm space-y-3">
                  {!selectedDetails ? (
                    <div className="text-muted-foreground">
                      Выберите ячейку для подробностей.
                    </div>
                  ) : (
                    <>
                      <div className="space-y-1">
                        <div className="text-xs uppercase text-muted-foreground">Координаты</div>
                        <div>{selectedDetails.rowLabel} → {selectedDetails.colLabel}</div>
                        <div className="text-muted-foreground">
                          [{selectedDetails.rowIndex}, {selectedDetails.colIndex}]
                        </div>
                      </div>
                      <div className="space-y-1">
                        <div className="text-xs uppercase text-muted-foreground">Значение</div>
                        <div className="text-base font-semibold">
                          {Number.isFinite(selectedDetails.value)
                            ? selectedDetails.value.toFixed(6)
                            : "NaN"}
                        </div>
                      </div>
                      {selectedDetails.meta?.note && (
                        <div className="space-y-1">
                          <div className="text-xs uppercase text-muted-foreground">Примечание</div>
                          <div className="italic">{selectedDetails.meta.note}</div>
                        </div>
                      )}
                      {selectedDetails.meta?.flags?.length ? (
                        <div className="space-y-1">
                          <div className="text-xs uppercase text-muted-foreground">Флаги</div>
                          <div className="flex flex-wrap gap-1">
                            {selectedDetails.meta.flags.map((f, i) => (
                              <Badge key={i} variant="secondary">{f}</Badge>
                            ))}
                          </div>
                        </div>
                      ) : null}
                    </>
                  )}
                </div>
              </motion.div>
            )}
          </div>
        </CardContent>
      </Card>
    );
  }
);

AIConflictHeatmap.displayName = "AIConflictHeatmap";

export default AIConflictHeatmap;
