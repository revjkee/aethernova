import React, {
  useRef,
  useEffect,
  useMemo,
  useCallback,
  useState,
  memo,
  CSSProperties,
  MutableRefObject,
} from "react";

/**
 * Публичные типы
 */
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface AuditCell {
  x: number;            // индекс колонки
  y: number;            // индекс строки
  value: number;        // численное значение риска (0..1 или произвольное)
  level?: RiskLevel;    // дискретный уровень (опционален; если задан — приоритетен в легенде)
  id?: string | number; // стабильный идентификатор ячейки (для обратных вызовов/логов)
  tags?: string[];      // произвольные метки аудита (контроли, стандарты, и т.п.)
}

export interface AxisLabels {
  x?: string[]; // метки столбцов
  y?: string[]; // метки строк
}

export interface Thresholds {
  low: number;
  medium: number;
  high: number;
  critical?: number; // при отсутствии — берется Infinity
}

export interface Palette {
  low: string;
  medium: string;
  high: string;
  critical: string;
  empty?: string; // цвет для NaN/отсутствующих значений
  grid?: string;  // цвет сетки/рамок
}

export interface HeatmapMetrics {
  min: number;
  max: number;
  mean: number;
  count: number;
  nan: number;
}

export interface TooltipFormatter {
  (cell: AuditCell, labels: { x?: string; y?: string }): string;
}

export interface AuditRiskHeatmapProps {
  data: AuditCell[];                 // плоский массив ячеек
  cols: number;                      // количество столбцов
  rows: number;                      // количество строк
  labels?: AxisLabels;               // подписи осей
  thresholds?: Thresholds;           // пороги дискретных уровней
  palette?: Palette;                 // настраиваемые цвета
  valueDomain?: [number, number];    // явный домен для value; иначе авто
  padding?: number;                  // внутренние отступы вокруг холста
  cellGap?: number;                  // зазор между ячейками
  fontFamily?: string;
  fontSize?: number;                 // базовый размер шрифта
  showGrid?: boolean;
  showLegend?: boolean;
  showAxis?: boolean;
  showFocusRing?: boolean;
  ariaLabel?: string;                // общая aria‑метка графика
  tooltipFormatter?: TooltipFormatter;
  onHover?: (cell: AuditCell | null) => void;
  onSelect?: (cell: AuditCell | null) => void;
  filterLevels?: RiskLevel[];        // если задан — отображать только эти уровни
  // Экспорт
  onExportPng?: (blob: Blob) => void;
  onExportCsv?: (csv: string) => void;
  // Начальные трансформации
  initialScale?: number;
  initialTranslate?: { x: number; y: number };
  // Производительность
  willReadFrequently?: boolean;      // подсказка для canvas
  // Ключевая функция для доступа из родителя
  refApi?: MutableRefObject<AuditRiskHeatmapApi | null>;
}

/**
 * Публичное API виджета
 */
export interface AuditRiskHeatmapApi {
  resetView: () => void;
  zoomIn: (center?: { x: number; y: number }) => void;
  zoomOut: (center?: { x: number; y: number }) => void;
  toPNG: (scale?: number) => Promise<Blob>;
  toCSV: () => string;
  getMetrics: () => HeatmapMetrics;
}

/**
 * Значения по умолчанию
 */
const DEFAULT_THRESHOLDS: Thresholds = {
  low: 0.25,
  medium: 0.5,
  high: 0.75,
  critical: Infinity,
};

const DEFAULT_PALETTE: Palette = {
  low: "hsl(145, 55%, 42%)",      // green
  medium: "hsl(46, 100%, 50%)",   // yellow
  high: "hsl(14, 90%, 55%)",      // orange
  critical: "hsl(0, 80%, 48%)",   // red
  empty: "hsl(210, 15%, 92%)",    // light gray
  grid: "rgba(0,0,0,0.08)",
};

const CSS_VARS = {
  bg: "--risk-heatmap-bg",
  fg: "--risk-heatmap-fg",
  axis: "--risk-heatmap-axis",
  legendBg: "--risk-heatmap-legend-bg",
  legendFg: "--risk-heatmap-legend-fg",
  focus: "--risk-heatmap-focus",
};

/**
 * Утилиты
 */
const clamp = (v: number, min: number, max: number) => Math.max(min, Math.min(max, v));

function computeMetrics(data: AuditCell[], domain?: [number, number]): HeatmapMetrics {
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  let sum = 0;
  let n = 0;
  let nan = 0;
  for (const c of data) {
    const v = c.value;
    if (Number.isFinite(v)) {
      min = v < min ? v : min;
      max = v > max ? v : max;
      sum += v;
      n++;
    } else {
      nan++;
    }
  }
  if (n === 0) {
    return { min: NaN, max: NaN, mean: NaN, count: 0, nan };
  }
  if (domain) {
    min = domain[0];
    max = domain[1];
  }
  return { min, max, mean: sum / n, count: n, nan };
}

function valueToLevel(v: number | undefined, t: Thresholds): RiskLevel | undefined {
  if (v == null || !Number.isFinite(v)) return undefined;
  if (v < t.low) return "low";
  if (v < t.medium) return "medium";
  if (v < t.high) return "high";
  return "critical";
}

function lerp(a: number, b: number, t: number) {
  return a + (b - a) * t;
}

// Простая непрерывная палитра: зелёный → жёлтый → красный
function continuousColor(v: number, min: number, max: number): string {
  if (!Number.isFinite(v)) return DEFAULT_PALETTE.empty!;
  if (min === max) return DEFAULT_PALETTE.medium;
  const t = clamp((v - min) / (max - min), 0, 1);
  // 0..0.5 — зелёный→жёлтый, 0.5..1 — жёлтый→красный
  if (t < 0.5) {
    const k = t / 0.5;
    // green hsl(145,55%,42%) -> yellow hsl(46,100%,50%)
    const h = lerp(145, 46, k);
    const s = lerp(55, 100, k);
    const l = lerp(42, 50, k);
    return `hsl(${h}, ${s}%, ${l}%)`;
  } else {
    const k = (t - 0.5) / 0.5;
    // yellow -> red hsl(0,80%,48%)
    const h = lerp(46, 0, k);
    const s = lerp(100, 80, k);
    const l = lerp(50, 48, k);
    return `hsl(${h}, ${s}%, ${l}%)`;
  }
}

function getDevicePixelRatioSafe(): number {
  if (typeof window === "undefined") return 1;
  const dpr = (window.devicePixelRatio || 1);
  return clamp(dpr, 1, 3);
}

function makeCsv(
  cells: AuditCell[],
  cols: number,
  rows: number,
  labels?: AxisLabels
): string {
  const lines: string[] = [];
  const header = ["Row", "Col", "YLabel", "XLabel", "Value", "Level", "Tags"];
  lines.push(header.join(","));
  for (const c of cells) {
    const yl = labels?.y?.[c.y] ?? "";
    const xl = labels?.x?.[c.x] ?? "";
    const tags = (c.tags ?? []).join("|");
    lines.push([c.y, c.x, yl, xl, c.value, c.level ?? "", tags].join(","));
  }
  return lines.join("\n");
}

/**
 * Основной компонент
 */
export const AuditRiskHeatmap = memo(function AuditRiskHeatmap(props: AuditRiskHeatmapProps) {
  const {
    data,
    cols,
    rows,
    labels,
    thresholds = DEFAULT_THRESHOLDS,
    palette = DEFAULT_PALETTE,
    valueDomain,
    padding = 48,
    cellGap = 1,
    fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif",
    fontSize = 12,
    showGrid = false,
    showLegend = true,
    showAxis = true,
    showFocusRing = true,
    ariaLabel = "Карта аудита и уровней риска",
    tooltipFormatter,
    onHover,
    onSelect,
    filterLevels,
    onExportPng,
    onExportCsv,
    initialScale = 1,
    initialTranslate = { x: 0, y: 0 },
    willReadFrequently = true,
    refApi,
  } = props;

  // Контейнер и канвасы
  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const overlayRef = useRef<HTMLCanvasElement | null>(null);

  // Размеры
  const [width, setWidth] = useState<number>(800);
  const [height, setHeight] = useState<number>(480);

  // Матрица вида
  const [scale, setScale] = useState<number>(initialScale);
  const [translate, setTranslate] = useState<{ x: number; y: number }>(initialTranslate);

  // Наведение/фокус
  const [hoverCell, setHoverCell] = useState<AuditCell | null>(null);
  const [focusCell, setFocusCell] = useState<{ x: number; y: number } | null>(null);

  // Метрики
  const metrics = useMemo(() => computeMetrics(data, valueDomain), [data, valueDomain]);

  // Индекс быстрых запросов ячеек
  const grid = useMemo(() => {
    // Создаем 2D‑решетку ссылок на ячейки для O(1) доступа
    const arr: (AuditCell | undefined)[][] = Array.from({ length: rows }, () =>
      Array<AuditCell | undefined>(cols).fill(undefined)
    );
    for (const c of data) {
      if (c.x >= 0 && c.x < cols && c.y >= 0 && c.y < rows) {
        arr[c.y][c.x] = {
          ...c,
          level: c.level ?? valueToLevel(c.value, thresholds),
        };
      }
    }
    return arr;
  }, [data, cols, rows, thresholds]);

  // Фильтр уровней
  const isLevelAllowed = useCallback(
    (lvl?: RiskLevel) => {
      if (!filterLevels || filterLevels.length === 0) return true;
      return lvl ? filterLevels.includes(lvl) : false;
    },
    [filterLevels]
  );

  // Адаптивные размеры контейнера с ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) {
        const cr = e.contentRect;
        setWidth(Math.max(320, Math.floor(cr.width)));
        setHeight(Math.max(240, Math.floor(cr.height)));
      }
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Рендер на оффскрине и перенос на основной холст
  const render = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const dpr = getDevicePixelRatioSafe();
    const innerW = Math.max(1, width);
    const innerH = Math.max(1, height);
    canvas.width = Math.floor(innerW * dpr);
    canvas.height = Math.floor(innerH * dpr);
    canvas.style.width = `${innerW}px`;
    canvas.style.height = `${innerH}px`;

    const ctx = canvas.getContext("2d", { willReadFrequently })!;
    if (!ctx) return;

    // Бэкграунд
    const bg = getComputedStyle(canvas).getPropertyValue(CSS_VARS.bg) || "#ffffff";
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.fillStyle = bg.trim() || "#ffffff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.scale(dpr, dpr);

    // Геометрия области теплокарты
    const left = showAxis ? padding : 8;
    const top = 8;
    const right = showLegend ? padding : 8;
    const bottom = showAxis ? padding : 8;
    const plotW = Math.max(1, innerW - left - right);
    const plotH = Math.max(1, innerH - top - bottom);

    // Трансформация вида (масштаб/сдвиг)
    ctx.save();
    ctx.beginPath();
    ctx.rect(left, top, plotW, plotH);
    ctx.clip();

    ctx.translate(left + translate.x, top + translate.y);
    ctx.scale(scale, scale);

    // Размеры ячейки
    const cellW = Math.max(1, (plotW / cols) - cellGap);
    const cellH = Math.max(1, (plotH / rows) - cellGap);

    const min = metrics.min;
    const max = metrics.max;

    // Рисуем ячейки
    for (let y = 0; y < rows; y++) {
      const rowArr = grid[y];
      for (let x = 0; x < cols; x++) {
        const c = rowArr[x];
        let color: string;
        if (!c || !Number.isFinite(c.value)) {
          color = palette.empty ?? DEFAULT_PALETTE.empty!;
        } else {
          const lvl = c.level ?? valueToLevel(c.value, thresholds);
          if (!isLevelAllowed(lvl)) continue;
          // Если задан дискретный уровень — используем палитру уровня, иначе непрерывную
          if (lvl) {
            color = (palette as any)[lvl] ?? continuousColor(c.value, min, max);
          } else {
            color = continuousColor(c.value, min, max);
          }
        }
        const px = x * (cellW + cellGap);
        const py = y * (cellH + cellGap);
        ctx.fillStyle = color;
        ctx.fillRect(px, py, cellW, cellH);

        if (showGrid) {
          ctx.strokeStyle = palette.grid ?? DEFAULT_PALETTE.grid!;
          ctx.lineWidth = Math.max(0.5, 1 / scale);
          ctx.strokeRect(px + 0.25, py + 0.25, cellW - 0.5, cellH - 0.5);
        }
      }
    }

    ctx.restore();

    // Оси
    if (showAxis) {
      const axisColor =
        getComputedStyle(canvas).getPropertyValue(CSS_VARS.axis) || "rgba(0,0,0,0.65)";
      ctx.fillStyle = axisColor.trim();
      ctx.font = `${fontSize}px ${fontFamily}`;
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";

      // Y‑метки (подмножество для производительности)
      const maxY = Math.min(rows, Math.floor(plotH / (fontSize * 1.2)));
      const stepY = Math.ceil(rows / maxY) || 1;
      for (let y = 0; y < rows; y += stepY) {
        const label = labels?.y?.[y];
        if (!label) continue;
        const py = top + (y + 0.5) * (plotH / rows);
        ctx.fillText(label, left - 6, py);
      }

      // X‑метки
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      const maxX = Math.min(cols, Math.floor(plotW / (fontSize * 1.2)));
      const stepX = Math.ceil(cols / maxX) || 1;
      for (let x = 0; x < cols; x += stepX) {
        const label = labels?.x?.[x];
        if (!label) continue;
        const px = left + (x + 0.5) * (plotW / cols);
        ctx.fillText(label, px, top + plotH + 6);
      }
    }

    // Фокус‑рамка
    if (showFocusRing && focusCell) {
      const ctx2 = overlayRef.current?.getContext("2d");
      if (ctx2) {
        const dpr2 = getDevicePixelRatioSafe();
        const ov = overlayRef.current!;
        ov.width = Math.floor(innerW * dpr2);
        ov.height = Math.floor(innerH * dpr2);
        ov.style.width = `${innerW}px`;
        ov.style.height = `${innerH}px`;
        ctx2.setTransform(1, 0, 0, 1, 0, 0);
        ctx2.scale(dpr2, dpr2);
        ctx2.clearRect(0, 0, innerW, innerH);

        const focusColor =
          getComputedStyle(ov).getPropertyValue(CSS_VARS.focus) || "rgba(0, 100, 255, 0.9)";
        ctx2.strokeStyle = focusColor.trim();
        ctx2.lineWidth = 2;

        const left = showAxis ? padding : 8;
        const top = 8;
        const right = showLegend ? padding : 8;
        const bottom = showAxis ? padding : 8;
        const plotW = Math.max(1, innerW - left - right);
        const plotH = Math.max(1, innerH - top - bottom);
        const cellW = Math.max(1, (plotW / cols) - cellGap);
        const cellH = Math.max(1, (plotH / rows) - cellGap);

        const tx = (left + translate.x);
        const ty = (top + translate.y);

        const px = tx + (focusCell.x * (cellW + cellGap)) * scale;
        const py = ty + (focusCell.y * (cellH + cellGap)) * scale;

        ctx2.strokeRect(
          Math.floor(px) + 0.5,
          Math.floor(py) + 0.5,
          Math.floor(cellW * scale),
          Math.floor(cellH * scale)
        );
      }
    } else if (overlayRef.current) {
      const ctx2 = overlayRef.current.getContext("2d");
      if (ctx2) ctx2.clearRect(0, 0, overlayRef.current.width, overlayRef.current.height);
    }
  }, [
    width,
    height,
    rows,
    cols,
    grid,
    metrics.min,
    metrics.max,
    padding,
    cellGap,
    fontSize,
    fontFamily,
    showGrid,
    showAxis,
    showLegend,
    showFocusRing,
    translate.x,
    translate.y,
    scale,
    thresholds,
    palette,
    willReadFrequently,
    focusCell,
  ]);

  // Ререндер по изменению зависимостей
  useEffect(() => {
    let raf = 0;
    const loop = () => {
      raf = requestAnimationFrame(() => {
        render();
      });
    };
    loop();
    return () => cancelAnimationFrame(raf);
  }, [render]);

  // Хит‑тест с учетом трансформаций
  const pickCell = useCallback(
    (clientX: number, clientY: number): AuditCell | null => {
      const canvas = canvasRef.current;
      if (!canvas) return null;
      const rect = canvas.getBoundingClientRect();

      const x = clientX - rect.left;
      const y = clientY - rect.top;

      const left = showAxis ? padding : 8;
      const top = 8;
      const right = showLegend ? padding : 8;
      const bottom = showAxis ? padding : 8;

      const plotW = Math.max(1, width - left - right);
      const plotH = Math.max(1, height - top - bottom);

      // Обратная трансформация
      const rx = (x - left - translate.x) / scale;
      const ry = (y - top - translate.y) / scale;

      const cellW = Math.max(1, (plotW / cols) - cellGap);
      const cellH = Math.max(1, (plotH / rows) - cellGap);

      const cx = Math.floor(rx / (cellW + cellGap));
      const cy = Math.floor(ry / (cellH + cellGap));

      if (cx < 0 || cy < 0 || cx >= cols || cy >= rows) return null;

      const c = grid[cy][cx];
      if (!c) return null;
      if (!isLevelAllowed(c.level ?? valueToLevel(c.value, thresholds))) return null;
      return c;
    },
    [
      cols,
      rows,
      grid,
      isLevelAllowed,
      thresholds,
      padding,
      width,
      height,
      showAxis,
      showLegend,
      cellGap,
      scale,
      translate.x,
      translate.y,
    ]
  );

  // События мыши/клавиатуры
  const onPointerMove = useCallback(
    (e: React.PointerEvent<HTMLCanvasElement>) => {
      const c = pickCell(e.clientX, e.clientY);
      setHoverCell(c);
      onHover?.(c ?? null);
    },
    [pickCell, onHover]
  );

  const onPointerLeave = useCallback(() => {
    setHoverCell(null);
    onHover?.(null);
  }, [onHover]);

  const onClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const c = pickCell(e.clientX, e.clientY);
      if (c) {
        setFocusCell({ x: c.x, y: c.y });
        onSelect?.(c);
      } else {
        onSelect?.(null);
      }
    },
    [pickCell, onSelect]
  );

  const onWheel = useCallback(
    (e: React.WheelEvent<HTMLCanvasElement>) => {
      e.preventDefault();
      const delta = -e.deltaY;
      const factor = delta > 0 ? 1.08 : 0.92;
      const newScale = clamp(scale * factor, 0.25, 8);
      // Центрируем зум относительно положения курсора
      const rect = canvasRef.current!.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;

      const left = showAxis ? padding : 8;
      const top = 8;
      const sx = (cx - left - translate.x) / scale;
      const sy = (cy - top - translate.y) / scale;

      const nx = cx - left - sx * newScale;
      const ny = cy - top - sy * newScale;

      setScale(newScale);
      setTranslate({ x: nx, y: ny });
    },
    [scale, translate.x, translate.y, padding, showAxis]
  );

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      // Управление фокусом и масштабом
      if (e.key === "+" || e.key === "=") {
        setScale((s) => clamp(s * 1.1, 0.25, 8));
        e.preventDefault();
        return;
      }
      if (e.key === "-" || e.key === "_") {
        setScale((s) => clamp(s * 0.9, 0.25, 8));
        e.preventDefault();
        return;
      }
      if (e.key === "0") {
        setScale(1);
        setTranslate({ x: 0, y: 0 });
        e.preventDefault();
        return;
      }
      if (!focusCell) {
        if (e.key === "ArrowRight" || e.key === "ArrowDown" || e.key === "ArrowLeft" || e.key === "ArrowUp") {
          setFocusCell({ x: 0, y: 0 });
          e.preventDefault();
        }
        return;
      }
      if (e.key === "ArrowRight") {
        setFocusCell((f) => f ? { x: Math.min(cols - 1, f.x + 1), y: f.y } : f);
        e.preventDefault();
      } else if (e.key === "ArrowLeft") {
        setFocusCell((f) => f ? { x: Math.max(0, f.x - 1), y: f.y } : f);
        e.preventDefault();
      } else if (e.key === "ArrowDown") {
        setFocusCell((f) => f ? { x: f.x, y: Math.min(rows - 1, f.y + 1) } : f);
        e.preventDefault();
      } else if (e.key === "ArrowUp") {
        setFocusCell((f) => f ? { x: f.x, y: Math.max(0, f.y - 1) } : f);
        e.preventDefault();
      } else if (e.key === "Enter" || e.key === " ") {
        if (focusCell) {
          const c = grid[focusCell.y][focusCell.x];
          if (c) onSelect?.(c);
        }
        e.preventDefault();
      }
    },
    [focusCell, cols, rows, grid, onSelect]
  );

  // Экспорт PNG
  const toPNG = useCallback(
    async (scaleOut = 2): Promise<Blob> => {
      const canvas = canvasRef.current;
      if (!canvas) throw new Error("Canvas not ready");
      const w = Math.max(1, width);
      const h = Math.max(1, height);

      const out = document.createElement("canvas");
      out.width = Math.floor(w * scaleOut);
      out.height = Math.floor(h * scaleOut);
      const ctx = out.getContext("2d")!;
      ctx.scale(scaleOut, scaleOut);

      // Вызов рендера в контекст export‑canvas
      // Упрощенно: копируем текущий визуальный холст
      ctx.drawImage(canvas, 0, 0, w, h, 0, 0, w, h);

      return await new Promise<Blob>((resolve) => out.toBlob((b) => resolve(b!), "image/png"));
    },
    [width, height]
  );

  // Экспорт CSV
  const toCSV = useCallback(() => {
    const csv = makeCsv(
      data.map((c) => ({ ...c, level: c.level ?? valueToLevel(c.value, thresholds) })),
      cols,
      rows,
      labels
    );
    return csv;
  }, [data, cols, rows, labels, thresholds]);

  // Экспорт через props
  useEffect(() => {
    if (onExportPng) {
      toPNG().then(onExportPng).catch(() => void 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onExportPng]);

  useEffect(() => {
    if (onExportCsv) {
      onExportCsv(toCSV());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onExportCsv]);

  // Публикование API
  useEffect(() => {
    if (!refApi) return;
    refApi.current = {
      resetView: () => {
        setScale(1);
        setTranslate({ x: 0, y: 0 });
      },
      zoomIn: (center) => {
        setScale((s) => clamp(s * 1.2, 0.25, 8));
        if (center) setTranslate(center);
      },
      zoomOut: (center) => {
        setScale((s) => clamp(s / 1.2, 0.25, 8));
        if (center) setTranslate(center);
      },
      toPNG,
      toCSV,
      getMetrics: () => metrics,
    };
    return () => {
      refApi.current = null;
    };
  }, [refApi, toPNG, toCSV, metrics]);

  // Тултип
  const tooltip = useMemo(() => {
    if (!hoverCell) return null;
    const labelX = labels?.x?.[hoverCell.x];
    const labelY = labels?.y?.[hoverCell.y];
    if (tooltipFormatter) {
      return tooltipFormatter(hoverCell, { x: labelX, y: labelY });
    }
    const lvl = hoverCell.level ?? valueToLevel(hoverCell.value, thresholds);
    return `Y: ${labelY ?? hoverCell.y}\nX: ${labelX ?? hoverCell.x}\nValue: ${hoverCell.value}\nLevel: ${lvl ?? "n/a"}`;
  }, [hoverCell, labels, tooltipFormatter, thresholds]);

  const containerStyle = useMemo<CSSProperties>(() => {
    return {
      position: "relative",
      width: "100%",
      height: "100%",
      // Тема по CSS‑переменным с дефолтами
      [CSS_VARS.bg as any]: "var(--risk-heatmap-bg, #ffffff)",
      [CSS_VARS.fg as any]: "var(--risk-heatmap-fg, #222222)",
      [CSS_VARS.axis as any]: "var(--risk-heatmap-axis, rgba(0,0,0,0.65))",
      [CSS_VARS.legendBg as any]: "var(--risk-heatmap-legend-bg, rgba(0,0,0,0.04))",
      [CSS_VARS.legendFg as any]: "var(--risk-heatmap-legend-fg, rgba(0,0,0,0.75))",
      [CSS_VARS.focus as any]: "var(--risk-heatmap-focus, rgba(0, 100, 255, 0.9))",
      color: "var(--risk-heatmap-fg, #222222)",
      outline: "none",
      userSelect: "none",
    };
  }, []);

  return (
    <div
      ref={containerRef}
      style={containerStyle}
      role="application"
      aria-label={ariaLabel}
      tabIndex={0}
      onKeyDown={onKeyDown}
    >
      <canvas
        ref={canvasRef}
        onPointerMove={onPointerMove}
        onPointerLeave={onPointerLeave}
        onClick={onClick}
        onWheel={onWheel}
        style={{
          display: "block",
          width: "100%",
          height: "100%",
          cursor: "crosshair",
        }}
      />
      <canvas
        ref={overlayRef}
        aria-hidden="true"
        style={{
          pointerEvents: "none",
          position: "absolute",
          inset: 0,
        }}
      />
      {showLegend && (
        <Legend
          palette={palette}
          thresholds={thresholds}
          metrics={metrics}
          style={{
            position: "absolute",
            top: 8,
            right: 8,
          }}
        />
      )}
      {hoverCell && (
        <TooltipOverlay text={tooltip!} canvasRef={canvasRef} />
      )}
    </div>
  );
});

/**
 * Легенда (минимальная стоимость рендера)
 */
const Legend: React.FC<{
  palette: Palette;
  thresholds: Thresholds;
  metrics: HeatmapMetrics;
  style?: CSSProperties;
}> = ({ palette, thresholds, metrics, style }) => {
  const box: CSSProperties = {
    background: `var(${CSS_VARS.legendBg}, rgba(0,0,0,0.04))`,
    color: `var(${CSS_VARS.legendFg}, rgba(0,0,0,0.75))`,
    borderRadius: 8,
    padding: "8px 10px",
    fontSize: 12,
    lineHeight: 1.25,
    minWidth: 160,
    boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
    ...style,
  };
  const row: CSSProperties = { display: "flex", alignItems: "center", gap: 8, marginTop: 4 };
  const sw = (c: string) => ({
    width: 14,
    height: 14,
    borderRadius: 3,
    background: c,
    border: "1px solid rgba(0,0,0,0.1)",
    flex: "0 0 auto",
  });

  return (
    <div role="note" aria-label="Легенда уровней риска" style={box}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>Уровни риска</div>
      <div style={row}><span style={sw(palette.low)} /> Низкий {"<"} {thresholds.low}</div>
      <div style={row}><span style={sw(palette.medium)} /> Средний {"<"} {thresholds.medium}</div>
      <div style={row}><span style={sw(palette.high)} /> Высокий {"<"} {thresholds.high}</div>
      <div style={row}><span style={sw(palette.critical)} /> Критический {thresholds.high}+</div>
      <div style={{ borderTop: "1px solid rgba(0,0,0,0.08)", margin: "8px 0" }} />
      <div style={{ fontWeight: 600, marginBottom: 4 }}>Метрики</div>
      <div>Min: {Number.isFinite(metrics.min) ? metrics.min.toFixed(3) : "n/a"}</div>
      <div>Max: {Number.isFinite(metrics.max) ? metrics.max.toFixed(3) : "n/a"}</div>
      <div>Mean: {Number.isFinite(metrics.mean) ? metrics.mean.toFixed(3) : "n/a"}</div>
      <div>Count: {metrics.count} {metrics.nan ? `(NaN: ${metrics.nan})` : ""}</div>
    </div>
  );
};

/**
 * Тултип поверх канваса, позиционирование — рядом с курсором
 */
const TooltipOverlay: React.FC<{
  text: string;
  canvasRef: React.RefObject<HTMLCanvasElement>;
}> = ({ text, canvasRef }) => {
  const [pos, setPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const onMove = (e: PointerEvent) => {
      const rect = el.getBoundingClientRect();
      setPos({ x: e.clientX - rect.left + 12, y: e.clientY - rect.top + 12 });
    };
    el.addEventListener("pointermove", onMove, { passive: true });
    return () => el.removeEventListener("pointermove", onMove as any);
  }, [canvasRef]);

  return (
    <div
      role="tooltip"
      style={{
        position: "absolute",
        transform: `translate(${pos.x}px, ${pos.y}px)`,
        maxWidth: 320,
        whiteSpace: "pre",
        pointerEvents: "none",
        background: "rgba(20,20,20,0.92)",
        color: "#fff",
        padding: "8px 10px",
        borderRadius: 8,
        fontSize: 12,
        lineHeight: 1.25,
        boxShadow: "0 2px 8px rgba(0,0,0,0.2)",
      }}
    >
      {text}
    </div>
  );
};

export default AuditRiskHeatmap;
