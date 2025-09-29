// frontend/src/widgets/XAI/ExplanationDeltaViewer.tsx
"use client";

import * as React from "react";
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

/* Встроенные иконки (без lucide-react) */
const SvgCopy: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M8 8h10v12H8z" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M6 16H4V4h12v2" stroke="currentColor" strokeWidth="2" fill="none"/></svg>
);
const SvgDownload: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M12 3v12m0 0l-4-4m4 4l4-4" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M5 21h14" stroke="currentColor" strokeWidth="2"/></svg>
);
const SvgRefresh: React.FC<React.SVGProps<SVGSVGElement>> = (p) => (
  <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M21 12a9 9 0 10-3.5 7" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M21 3v6h-6" stroke="currentColor" strokeWidth="2" fill="none"/></svg>
);

/* Типы данных */
export type ExplanationDeltaViewerProps = {
  before?: string;
  after?: string;

  /** Если переданы — используются для тепловой карты. Длина = числу токенов после токенизации. */
  attributionsBefore?: number[];
  attributionsAfter?: number[];

  /** Опционально можно передать заранее токены; иначе токенизация по пробельным+знакам. */
  tokensBefore?: string[];
  tokensAfter?: string[];

  title?: string;
  description?: string;

  loading?: boolean;
  error?: string | null;

  /** Нормировка атрибуций: 'abs' | 'signed' */
  normalization?: "abs" | "signed";

  /** Максимальное значение для нормировки; если не задано — вычисляется по данным. */
  maxMagnitude?: number;

  /** Высота области визуализации */
  height?: number;

  /** Экспортируемые имена */
  exportFileBaseName?: string;

  /** Порог отсечения очень малых значений при окраске (0..1), по умолчанию 0.02 */
  cutoff?: number;

  /** Скрыть панель управления */
  hideControls?: boolean;
};

/* Токенизация: разбиваем на «слова» и разрывы, чтобы сохранять пробелы */
function tokenize(s: string): string[] {
  // Будем разделять по группам: слова/числа/символы + пробелы/переносы
  const re = /[\p{L}\p{N}_]+|[^\s\p{L}\p{N}_]|[\s]+/gu;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) out.push(m[0]);
  return out;
}

/* LCS для вычисления диффа по токенам. Возвращает кортежи {type, tokens} */
type DiffChunk =
  | { type: "equal"; a: string[] }
  | { type: "insert"; b: string[] }
  | { type: "delete"; a: string[] }
  | { type: "replace"; a: string[]; b: string[] };

function diffTokens(a: string[], b: string[]): DiffChunk[] {
  const n = a.length, m = b.length;
  // DP по длине LCS
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j++) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const chunks: DiffChunk[] = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      // equal stretch
      const startI = i, startJ = j;
      while (i < n && j < m && a[i] === b[j]) { i++; j++; }
      chunks.push({ type: "equal", a: a.slice(startI, i) });
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      const del: string[] = [];
      while (i < n && (j >= m || dp[i + 1][j] >= dp[i][j + 1]) && a[i] !== b[j]) {
        if (dp[i + 1][j] === dp[i][j]) break;
        del.push(a[i]); i++;
      }
      if (del.length) chunks.push({ type: "delete", a: del });
      else { chunks.push({ type: "replace", a: [a[i++]], b: [b[j++]] }); }
    } else {
      const ins: string[] = [];
      while (j < m && (i >= n || dp[i][j + 1] > dp[i + 1][j]) && a[i] !== b[j]) {
        if (dp[i][j + 1] === dp[i][j]) break;
        ins.push(b[j]); j++;
      }
      if (ins.length) chunks.push({ type: "insert", b: ins });
      else { chunks.push({ type: "replace", a: [a[i++]], b: [b[j++]] }); }
    }
  }
  if (i < n && j < m) chunks.push({ type: "replace", a: a.slice(i), b: b.slice(j) });
  else if (i < n) chunks.push({ type: "delete", a: a.slice(i) });
  else if (j < m) chunks.push({ type: "insert", b: b.slice(j) });
  return chunks;
}

/* Нормировка атрибуций: возвращает числа в [0..1] (abs) или [-1..1] (signed) */
function normalizeAttributions(values: number[], mode: "abs" | "signed", maxMag?: number): number[] {
  const absMax = maxMag ?? Math.max(1e-9, ...values.map((v) => Math.abs(v)));
  if (mode === "abs") return values.map((v) => Math.min(1, Math.abs(v) / absMax));
  return values.map((v) => Math.max(-1, Math.min(1, v / absMax)));
}

/* Палитра для signed: отрицательные — синие, положительные — красные */
function colorFor(value: number, cutoff: number, mode: "abs" | "signed"): string {
  // Возвращаем inline-style backgroundColor (rgba)
  if (mode === "abs") {
    const a = value; // 0..1
    if (a < cutoff) return "transparent";
    // янтарно-оранжевый оттенок
    const alpha = Math.min(0.85, 0.15 + 0.7 * a);
    return `rgba(245, 158, 11, ${alpha})`; // amber-500
  } else {
    const a = Math.abs(value);
    if (a < cutoff) return "transparent";
    const alpha = Math.min(0.85, 0.15 + 0.7 * a);
    if (value >= 0) return `rgba(239, 68, 68, ${alpha})`; // red-500
    return `rgba(59, 130, 246, ${alpha})`; // blue-500
  }
}

/* Утилиты */
function downloadBlob(content: string, fileName: string, mime = "application/json;charset=utf-8") {
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

function toCSV(rows: Record<string, any>[]): string {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);
  const esc = (v: any) => {
    if (v == null) return "";
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [headers.join(","), ...rows.map((r) => headers.map((h) => esc(r[h])).join(","))].join("\n");
}

/* Отрисовка токенов с фоном */
const TokenSpan: React.FC<{ token: string; bg?: string; className?: string; strike?: boolean }> = ({
  token,
  bg,
  className,
  strike,
}) => (
  <span
    className={cn("rounded-sm px-0.5", strike ? "line-through decoration-rose-500" : "", className)}
    style={bg ? { backgroundColor: bg } : undefined}
  >
    {token}
  </span>
);

/* Основной компонент */
export const ExplanationDeltaViewer: React.FC<ExplanationDeltaViewerProps> = ({
  before = "",
  after = "",
  attributionsBefore,
  attributionsAfter,
  tokensBefore,
  tokensAfter,
  title = "Explanation delta viewer",
  description,
  loading = false,
  error = null,
  normalization = "signed",
  maxMagnitude,
  height = 320,
  exportFileBaseName = "explanation_delta",
  cutoff = 0.02,
  hideControls = false,
}) => {
  const [mode, setMode] = useState<"diff" | "saliency-before" | "saliency-after" | "saliency-delta">("diff");
  const [wrap, setWrap] = useState(true);

  /* Токенизация */
  const tokensA = useMemo(() => tokensBefore ?? tokenize(before), [tokensBefore, before]);
  const tokensB = useMemo(() => tokensAfter ?? tokenize(after), [tokensAfter, after]);

  /* Дифф */
  const chunks = useMemo(() => diffTokens(tokensA, tokensB), [tokensA, tokensB]);

  /* Нормированные атрибуции и дельта */
  const normA = useMemo(
    () => (attributionsBefore ? normalizeAttributions(attributionsBefore, normalization, maxMagnitude) : undefined),
    [attributionsBefore, normalization, maxMagnitude]
  );
  const normB = useMemo(
    () => (attributionsAfter ? normalizeAttributions(attributionsAfter, normalization, maxMagnitude) : undefined),
    [attributionsAfter, normalization, maxMagnitude]
  );
  const delta = useMemo(() => {
    if (!normA || !normB) return undefined;
    const len = Math.max(normA.length, normB.length);
    const out = new Array(len).fill(0).map((_, i) => (normB[i] ?? 0) - (normA[i] ?? 0));
    return out;
  }, [normA, normB]);

  /* Экспорт данных */
  const handleExportJSON = useCallback(() => {
    const payload = {
      before,
      after,
      tokensBefore: tokensA,
      tokensAfter: tokensB,
      attributionsBefore,
      attributionsAfter,
      normalization,
      cutoff,
      chunks,
      exportedAt: new Date().toISOString(),
    };
    downloadBlob(JSON.stringify(payload, null, 2), `${exportFileBaseName}.json`);
  }, [before, after, tokensA, tokensB, attributionsBefore, attributionsAfter, normalization, cutoff, chunks, exportFileBaseName]);

  const handleExportCSV = useCallback(() => {
    const rows: Record<string, any>[] = [];
    const maxLen = Math.max(tokensA.length, tokensB.length);
    for (let i = 0; i < maxLen; i++) {
      rows.push({
        index: i,
        token_before: tokensA[i] ?? "",
        token_after: tokensB[i] ?? "",
        attr_before: attributionsBefore?.[i] ?? "",
        attr_after: attributionsAfter?.[i] ?? "",
      });
    }
    downloadBlob(toCSV(rows), `${exportFileBaseName}.csv`, "text/csv;charset=utf-8");
  }, [tokensA, tokensB, attributionsBefore, attributionsAfter, exportFileBaseName]);

  /* Копирование после/до */
  const doCopy = useCallback(async (s: string) => {
    await navigator.clipboard.writeText(s);
  }, []);

  /* Шорткаты */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
        if (e.key.toLowerCase() === "1") setMode("diff");
        if (e.key.toLowerCase() === "2") setMode("saliency-before");
        if (e.key.toLowerCase() === "3") setMode("saliency-after");
        if (e.key.toLowerCase() === "4") setMode("saliency-delta");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  /* Состояния */
  if (loading) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </CardHeader>
        <CardContent>
          <div className="h-[160px] min-h-[140px] animate-pulse rounded-2xl bg-muted" />
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

  const empty = (!before || tokensA.length === 0) && (!after || tokensB.length === 0);
  if (empty) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </CardHeader>
        <CardContent>
          <div className="rounded-xl border p-8 text-sm text-muted-foreground">Нет данных для отображения.</div>
        </CardContent>
      </Card>
    );
  }

  /* Рендеры */
  const renderDiff = () => (
    <div
      className={cn(
        "rounded-xl border p-3 text-sm leading-7",
        wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"
      )}
      style={{ minHeight: height }}
      aria-label="Diff view"
    >
      {chunks.map((c, idx) => {
        if (c.type === "equal") {
          return c.a.map((t, i) => <TokenSpan key={`${idx}-eq-${i}`} token={t} />);
        }
        if (c.type === "delete") {
          return c.a.map((t, i) => (
            <TokenSpan key={`${idx}-del-${i}`} token={t} strike className="bg-rose-50/70 text-rose-700 dark:bg-rose-500/15" />
          ));
        }
        if (c.type === "insert") {
          return c.b.map((t, i) => (
            <TokenSpan key={`${idx}-ins-${i}`} token={t} className="bg-emerald-50/70 text-emerald-700 dark:bg-emerald-500/15" />
          ));
        }
        // replace: показываем удаление затем вставку
        return (
          <span key={`${idx}-rep`} className="inline">
            {c.a.map((t, i) => (
              <TokenSpan key={`${idx}-rep-a-${i}`} token={t} strike className="bg-rose-50/70 text-rose-700 dark:bg-rose-500/15" />
            ))}
            {c.b.map((t, i) => (
              <TokenSpan key={`${idx}-rep-b-${i}`} token={t} className="bg-emerald-50/70 text-emerald-700 dark:bg-emerald-500/15" />
            ))}
          </span>
        );
      })}
    </div>
  );

  const renderSaliency = (tokens: string[], norm?: number[], label?: string) => (
    <div
      className={cn(
        "rounded-xl border p-3 text-sm leading-7",
        wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"
      )}
      style={{ minHeight: height }}
      aria-label={`${label ?? "saliency"} view`}
    >
      {tokens.map((t, i) => {
        const v = norm?.[i] ?? 0;
        const bg = colorFor(v, cutoff, normalization);
        return <TokenSpan key={`${label}-${i}`} token={t} bg={bg} />;
      })}
    </div>
  );

  const renderDelta = () => {
    // Длина берём по max из before/after
    const len = Math.max(tokensA.length, tokensB.length);
    const tok = tokensB.length >= tokensA.length ? tokensB : tokensA;
    const vals = delta ?? new Array(len).fill(0);
    return (
      <div
        className={cn(
          "rounded-xl border p-3 text-sm leading-7",
          wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"
        )}
        style={{ minHeight: height }}
        aria-label="delta saliency view"
      >
        {tok.map((t, i) => {
          const bg = colorFor(vals[i] ?? 0, cutoff, "signed");
          return <TokenSpan key={`delta-${i}`} token={t} bg={bg} />;
        })}
      </div>
    );
  };

  return (
    <Card className="w-full" aria-label="Explanation delta viewer">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="leading-tight">{title}</CardTitle>
          <CardDescription className="mt-1">
            {description ?? (
              <>
                Сравнение объяснений модели: дифф по токенам, тепловые карты атрибуций и дельта.{" "}
                <Badge variant="secondary" className="align-middle">Alt+1..4 — переключение режимов</Badge>
              </>
            )}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => handleExportJSON()}>
            <SvgDownload className="mr-2 h-4 w-4" />
            JSON
          </Button>
          <Button variant="secondary" size="sm" onClick={() => handleExportCSV()}>
            <SvgDownload className="mr-2 h-4 w-4" />
            CSV
          </Button>
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
            <SvgRefresh className="mr-2 h-4 w-4" />
            Обновить
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {!hideControls && (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="flex flex-wrap items-center gap-3">
              <Tabs value={mode} onValueChange={(v: string) => setMode(v as "diff" | "saliency-before" | "saliency-after" | "saliency-delta")}>
                <TabsList className="grid grid-cols-4">
                  <TabsTrigger value="diff">Diff</TabsTrigger>
                  <TabsTrigger value="saliency-before">Saliency (до)</TabsTrigger>
                  <TabsTrigger value="saliency-after">Saliency (после)</TabsTrigger>
                  <TabsTrigger value="saliency-delta">Delta</TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
            <div className="flex flex-wrap items-center gap-3 justify-start lg:justify-end">
              <div className="flex items-center gap-2">
                <Switch checked={wrap} onCheckedChange={setWrap} id="wrap" />
                <Label htmlFor="wrap">Перенос строк</Label>
              </div>
              <div className="flex items-center gap-2">
                <Label htmlFor="cutoff">Cutoff</Label>
                <Input
                  id="cutoff"
                  className="h-8 w-24"
                  inputMode="decimal"
                  value={cutoff}
                  onChange={(e) => {
                    const v = Number(e.target.value);
                    if (!Number.isNaN(v)) (e.target as any).value = String(Math.max(0, Math.min(1, v)));
                  }}
                  onBlur={(e) => {
                    const v = Number(e.target.value);
                    if (!Number.isNaN(v)) (e.target as any).value = String(Math.max(0, Math.min(1, v)));
                  }}
                />
              </div>
              <div className="flex items-center gap-2">
                <Label>Нормировка</Label>
                <Tabs value={normalization} onValueChange={() => { /* readonly в рамках пропсов */ }}>
                  <TabsList className="grid grid-cols-2">
                    <TabsTrigger value="signed" aria-disabled className="cursor-default">signed</TabsTrigger>
                    <TabsTrigger value="abs" aria-disabled className="cursor-default">abs</TabsTrigger>
                  </TabsList>
                </Tabs>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => doCopy(mode === "diff" ? after : (mode === "saliency-before" ? before : after))}
                title="Копировать активный текст"
              >
                <SvgCopy className="mr-2 h-4 w-4" />
                Копировать
              </Button>
            </div>
          </div>
        )}

        {/* Визуализация */}
        <div>
          {mode === "diff" && renderDiff()}
          {mode === "saliency-before" && renderSaliency(tokensA, normA, "before")}
          {mode === "saliency-after" && renderSaliency(tokensB, normB, "after")}
          {mode === "saliency-delta" && renderDelta()}
        </div>

        <div className="text-xs text-muted-foreground">
          Цветовая шкала: красный — положительное влияние, синий — отрицательное; интенсивность соответствует модулю значения.
          Для режима abs используется однотонная шкала (янтарный).
        </div>
      </CardContent>
    </Card>
  );
};

export default ExplanationDeltaViewer;
