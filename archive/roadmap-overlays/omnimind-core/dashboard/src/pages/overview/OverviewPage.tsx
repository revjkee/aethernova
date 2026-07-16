'use client';

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  Suspense,
} from 'react';
import clsx from 'clsx';

/** ---------------------------
 * Типы доменной модели
 * -------------------------- */
type KpiPoint = { t: number; v: number };
type KpiSeries = KpiPoint[];

type OverviewAggs = {
  uptimePct: number;          // 0..100
  latencyP95Ms: number;       // миллисекунды
  errorRatePct: number;       // 0..100
  throughputRps: number;      // req/sec
  activeUsers: number;
  servicesHealthy: number;    // healthy сервисов
  servicesTotal: number;      // всего сервисов
  // временные ряды для спарклайнов
  seriesLatency: KpiSeries;
  seriesErrors: KpiSeries;
  seriesRps: KpiSeries;
  updatedAt: string;          // ISO
};

type RecentEvent = {
  id: string;
  ts: string;                 // ISO
  level: 'INFO' | 'WARN' | 'ERROR';
  service: string;
  message: string;
};

type OverviewPayload = {
  aggs: OverviewAggs;
  recent: RecentEvent[];
};

/** ---------------------------
 * Утилиты
 * -------------------------- */

/** Форматирование чисел с локалью и fallback. */
function nf(
  v: number,
  opts: Intl.NumberFormatOptions = {}
): string {
  try {
    return new Intl.NumberFormat(undefined, opts).format(v);
  } catch {
    return String(v);
  }
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

/** Рисуем мини-спарклайн на чистом SVG. */
function Sparkline({
  data,
  w = 120,
  h = 36,
  strokeClass = 'stroke-foreground',
  fillClass = 'fill-foreground',
  area = true,
  strokeWidth = 1.5,
}: {
  data: KpiSeries;
  w?: number;
  h?: number;
  strokeClass?: string;
  fillClass?: string;
  area?: boolean;
  strokeWidth?: number;
}) {
  if (!data || data.length === 0) {
    return <div className="h-9 w-[120px] rounded bg-muted/60 skeleton" aria-hidden />;
  }
  const xs = data.map((p) => p.t);
  const ys = data.map((p) => p.v);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);

  // защита от деления на 0
  const dx = maxX - minX || 1;
  const dy = maxY - minY || 1;

  const scaleX = (t: number) => ((t - minX) / dx) * (w - 2) + 1;
  const scaleY = (v: number) => h - (((v - minY) / dy) * (h - 2) + 1);

  const points = data.map((p) => [scaleX(p.t), scaleY(p.v)] as const);

  const d = points
    .map(([x, y], i) => (i === 0 ? `M ${x},${y}` : `L ${x},${y}`))
    .join(' ');

  const areaD =
    `M ${points[0][0]},${h} ` +
    points.map(([x, y]) => `L ${x},${y}`).join(' ') +
    ` L ${points[points.length - 1][0]},${h} Z`;

  const last = points[points.length - 1];

  return (
    <svg
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      role="img"
      aria-label="Тренд"
    >
      {area && (
        <path
          d={areaD}
          className={clsx(fillClass)}
          style={{ opacity: 0.08 }}
        />
      )}
      <path
        d={d}
        className={clsx(strokeClass)}
        strokeWidth={strokeWidth}
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Точка на конце */}
      <circle
        cx={last[0]}
        cy={last[1]}
        r={2.2}
        className={clsx(fillClass)}
        aria-hidden
      />
    </svg>
  );
}

/** Экспоненциальный ретрай с AbortController. */
async function fetchWithRetry<T>(
  input: RequestInfo,
  init: RequestInit & { retries?: number; backoffMs?: number } = {}
): Promise<T> {
  const { retries = 2, backoffMs = 400, signal, ...rest } = init;
  let attempt = 0;
  // поддержка внешнего AbortSignal
  const ac = new AbortController();
  const signals: AbortSignal[] = [];
  if (signal) signals.push(signal);
  signals.push(ac.signal);

  const anyAborted = () => signals.some((s) => (s as any)?.aborted);

  const composeSignal = (() => {
    if (!signal) return ac.signal;
    // простой прокси для отмены по любому сигналу
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    signals.forEach((s) => s.addEventListener('abort', onAbort, { once: true }));
    return controller.signal;
  })();

  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (anyAborted()) throw new DOMException('Aborted', 'AbortError');
    try {
      const res = await fetch(input, { ...rest, signal: composeSignal, cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = (await res.json()) as T;
      return json;
    } catch (e) {
      if (attempt >= retries || anyAborted()) throw e;
      await new Promise((r) => setTimeout(r, backoffMs * Math.pow(2, attempt)));
      attempt++;
    }
  }
}

/** ---------------------------
 * Главная страница Overview
 * -------------------------- */
export default function OverviewPage() {
  const [data, setData] = useState<OverviewPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      // Ожидается серверный эндпоинт вашего ядра:
      // GET /api/overview → OverviewPayload
      const payload = await fetchWithRetry<OverviewPayload>('/api/overview', {
        signal: ac.signal,
        retries: 2,
        backoffMs: 500,
      });
      setData(payload);
    } catch (e: any) {
      setError(e?.message ?? 'Load error');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => abortRef.current?.abort();
  }, [load]);

  const aggs = data?.aggs;

  const kpis = useMemo(
    () => [
      {
        key: 'uptime',
        label: 'Uptime',
        value: aggs ? `${clamp(aggs.uptimePct, 0, 100).toFixed(2)}%` : '—',
        hint: 'Процент времени доступности',
        trend: aggs?.seriesRps ?? [],
      },
      {
        key: 'latency',
        label: 'P95 Latency',
        value: aggs ? `${nf(aggs.latencyP95Ms)} ms` : '—',
        hint: '95-й перцентиль задержки',
        trend: aggs?.seriesLatency ?? [],
      },
      {
        key: 'errors',
        label: 'Error Rate',
        value: aggs ? `${clamp(aggs.errorRatePct, 0, 100).toFixed(2)}%` : '—',
        hint: 'Процент неуспехов',
        trend: aggs?.seriesErrors ?? [],
      },
      {
        key: 'rps',
        label: 'Throughput',
        value: aggs ? `${nf(aggs.throughputRps)} rps` : '—',
        hint: 'Запросов в секунду',
        trend: aggs?.seriesRps ?? [],
      },
      {
        key: 'users',
        label: 'Active users',
        value: aggs ? nf(aggs.activeUsers) : '—',
        hint: 'DAU/активные за период',
        trend: aggs?.seriesRps ?? [],
      },
      {
        key: 'services',
        label: 'Services healthy',
        value: aggs
          ? `${nf(aggs.servicesHealthy)} / ${nf(aggs.servicesTotal)}`
          : '—',
        hint: 'Зелёных/всего сервисов',
        trend: aggs?.seriesErrors ?? [],
      },
    ],
    [aggs]
  );

  /** Цвет тренда по последним двум точкам (простая эвристика). */
  const trendColor = (series: KpiSeries) => {
    if (!series || series.length < 2) return 'stroke-foreground fill-foreground';
    const a = series[series.length - 2].v;
    const b = series[series.length - 1].v;
    return b >= a ? 'stroke-emerald-500 fill-emerald-500' : 'stroke-red-500 fill-red-500';
    // при желании подменяйте для метрик «чем ниже тем лучше» (latency/error)
  };

  return (
    <main className="container-desktop py-6 space-y-6" aria-labelledby="overview-title">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 id="overview-title" className="text-xl font-semibold tracking-tight">
            Overview
          </h1>
          <p className="text-sm text-muted-foreground">
            Сводка состояния OmniMind Core. Обновлено:{' '}
            <time dateTime={aggs?.updatedAt ?? ''}>
              {aggs ? new Date(aggs.updatedAt).toLocaleString() : '—'}
            </time>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={load}
            className="btn"
            aria-label="Обновить данные"
          >
            Refresh
          </button>
        </div>
      </header>

      {/* KPI grid */}
      <section aria-label="Ключевые метрики">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {kpis.map((k) => (
            <article key={k.key} className="card">
              <div className="card-content flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <div className="text-sm text-muted-foreground">{k.label}</div>
                  <div className="mt-1 text-2xl font-semibold tabular-nums">
                    {loading ? (
                      <span className="inline-block h-7 w-24 rounded bg-muted/60 skeleton" aria-hidden />
                    ) : (
                      k.value
                    )}
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">{k.hint}</div>
                </div>
                <div className="shrink-0">
                  {loading ? (
                    <div className="h-9 w-[120px] rounded bg-muted/60 skeleton" aria-hidden />
                  ) : (
                    <Sparkline
                      data={k.trend}
                      strokeClass={trendColor(k.trend)}
                      fillClass={trendColor(k.trend)}
                    />
                  )}
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* Health summary */}
      <section className="card" aria-label="Итог здоровья сервисов">
        <div className="card-content">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <span
                className={clsx(
                  'inline-block h-3 w-3 rounded-full',
                  (aggs?.servicesHealthy ?? 0) === (aggs?.servicesTotal ?? 0)
                    ? 'bg-emerald-500'
                    : 'bg-amber-500'
                )}
                aria-hidden
              />
              <div className="text-sm">
                Сервисов в норме:{' '}
                <strong className="tabular-nums">
                  {loading ? '—' : `${aggs?.servicesHealthy}/${aggs?.servicesTotal}`}
                </strong>
              </div>
            </div>
            <div className="text-sm text-muted-foreground">
              Uptime:{' '}
              <strong className="tabular-nums">
                {loading ? '—' : `${clamp(aggs!.uptimePct, 0, 100).toFixed(2)}%`}
              </strong>
              , P95:{' '}
              <strong className="tabular-nums">
                {loading ? '—' : `${nf(aggs!.latencyP95Ms)} ms`}
              </strong>
              , Errors:{' '}
              <strong className="tabular-nums">
                {loading ? '—' : `${clamp(aggs!.errorRatePct, 0, 100).toFixed(2)}%`}
              </strong>
              , RPS:{' '}
              <strong className="tabular-nums">
                {loading ? '—' : nf(aggs!.throughputRps)}
              </strong>
            </div>
          </div>
        </div>
      </section>

      {/* Recent events */}
      <section className="card" aria-label="Недавние события">
        <div className="card-header">
          <h2 className="text-sm font-medium">Недавние события</h2>
        </div>
        <div className="card-content p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-muted-foreground">
                <tr className="[&>th]:px-4 [&>th]:py-2 text-left">
                  <th>Время</th>
                  <th>Уровень</th>
                  <th>Сервис</th>
                  <th>Сообщение</th>
                </tr>
              </thead>
              <tbody className="[&>tr:not(:last-child)]:border-b">
                {loading
                  ? Array.from({ length: 6 }).map((_, i) => (
                      <tr key={i} className="[&>td]:px-4 [&>td]:py-2">
                        <td><div className="h-4 w-36 rounded bg-muted/60 skeleton" /></td>
                        <td><div className="h-4 w-16 rounded bg-muted/60 skeleton" /></td>
                        <td><div className="h-4 w-28 rounded bg-muted/60 skeleton" /></td>
                        <td><div className="h-4 w-[28rem] max-w-[70vw] rounded bg-muted/60 skeleton" /></td>
                      </tr>
                    ))
                  : (data?.recent ?? []).map((e) => (
                      <tr key={e.id} className="[&>td]:px-4 [&>td]:py-2 align-top">
                        <td>
                          <time dateTime={e.ts}>
                            {new Date(e.ts).toLocaleString()}
                          </time>
                        </td>
                        <td>
                          <span
                            className={clsx(
                              'inline-flex items-center rounded px-2 py-0.5 text-xs font-medium',
                              e.level === 'ERROR' && 'bg-red-500/10 text-red-600',
                              e.level === 'WARN' && 'bg-amber-500/10 text-amber-700',
                              e.level === 'INFO' && 'bg-emerald-500/10 text-emerald-700'
                            )}
                            aria-label={`Уровень ${e.level}`}
                          >
                            {e.level}
                          </span>
                        </td>
                        <td className="text-muted-foreground">{e.service}</td>
                        <td className="break-words">{e.message}</td>
                      </tr>
                    ))}
                {!loading && (data?.recent?.length ?? 0) === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-6 text-center text-muted-foreground">
                      Нет событий за выбранный период
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Ошибка загрузки */}
      {error && (
        <section role="alert" className="card border-red-200">
          <div className="card-content text-sm">
            <div className="font-medium text-red-600">Ошибка загрузки</div>
            <div className="text-muted-foreground">{error}</div>
          </div>
        </section>
      )}
    </main>
  );
}

/** -------------
 * Примечания:
 * 1) Ожидается эндпоинт /api/overview, возвращающий OverviewPayload.
 * 2) Скелетоны, токены цвета и утилиты завязаны на глобальные стили из globals.css.
 * 3) Для ARIA разметки использованы role/aria-label/time/tabular-nums.
 * 4) Для Next.js App Router компонент помечен как client.
 * ------------- */
