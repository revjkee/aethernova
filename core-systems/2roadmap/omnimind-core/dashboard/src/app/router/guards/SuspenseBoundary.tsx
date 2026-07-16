import React, { ReactNode, Suspense, useEffect, useMemo, useRef, useState } from "react";

/**
 * Управляемый контроллер показа fallback.
 * - Показывает fallback только после delayMs, чтобы избежать мерцаний на быстрых загрузках.
 * - Поддерживает как ReactNode, так и функцию (state) => ReactNode для динамики.
 * - Добавляет ARIA-атрибуты для ассистивных технологий.
 */
function FallbackWithDelay({
  fallback,
  delayMs,
  "aria-live": ariaLive,
  role,
  className,
  "data-testid": testId,
}: {
  fallback: ReactNode | ((state: { delayed: boolean }) => ReactNode);
  delayMs: number;
  "aria-live"?: "polite" | "assertive" | "off";
  role?: string;
  className?: string;
  "data-testid"?: string;
}) {
  const [delayed, setDelayed] = useState(delayMs <= 0);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    if (delayMs <= 0) return;
    timer.current = window.setTimeout(() => setDelayed(true), delayMs);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [delayMs]);

  if (!delayed) return null;

  const content = typeof fallback === "function" ? (fallback as (s: { delayed: boolean }) => ReactNode)({ delayed }) : fallback;
  return (
    <div
      role={role ?? "status"}
      aria-live={ariaLive ?? "polite"}
      className={className}
      data-testid={testId}
    >
      {content ?? <div>Loading…</div>}
    </div>
  );
}

export type SuspenseBoundaryProps = {
  /**
   * Дочерний узел, который может «подвешиваться» (lazy/awaited).
   */
  children: ReactNode;

  /**
   * Что показывать во время ожидания:
   * - ReactNode
   * - функция (state) => ReactNode, где state.delayed сообщает, что задержка истекла.
   */
  fallback?: ReactNode | ((state: { delayed: boolean }) => ReactNode);

  /**
   * Задержка перед показом fallback (мс). 0 — показать сразу.
   * По умолчанию 180 мс, чтобы убрать микромерцания.
   */
  delayMs?: number;

  /**
   * ARIA-настройки для доступности.
   */
  ariaLive?: "polite" | "assertive" | "off";
  role?: string;

  /**
   * Служебные атрибуты для тестов/стилей.
   */
  className?: string;
  "data-testid"?: string;
};

/**
 * SuspenseBoundary — обёртка над React.Suspense с управляемой задержкой показа fallback.
 * Использование:
 * <SuspenseBoundary fallback={<Spinner />} delayMs={200}><LazyPage/></SuspenseBoundary>
 */
export function SuspenseBoundary({
  children,
  fallback,
  delayMs = 180,
  ariaLive,
  role,
  className,
  "data-testid": testId,
}: SuspenseBoundaryProps) {
  const memoFallback = useMemo(
    () => (
      <FallbackWithDelay
        fallback={fallback ?? <div>Loading…</div>}
        delayMs={delayMs}
        aria-live={ariaLive}
        role={role}
        className={className}
        data-testid={testId ?? "suspense-fallback"}
      />
    ),
    [fallback, delayMs, ariaLive, role, className, testId]
  );

  return <Suspense fallback={memoFallback}>{children}</Suspense>;
}

export default SuspenseBoundary;
