// frontend/src/shared/components/ZKProofBadge.tsx
import React, { memo, useCallback, useMemo, useState } from "react";
import type { ComponentPropsWithoutRef, ReactNode } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Timer,
  HelpCircle,
  Copy,
  ExternalLink,
  X,
} from "lucide-react";

/**
 * Вспомогательная функция объединения классов без сторонних зависимостей.
 */
function cn(...classes: Array<string | undefined | false | null>): string {
  return classes.filter(Boolean).join(" ");
}

/**
 * Типы статусов проверки ZK-доказательства.
 */
export type ZkProofStatus = "verified" | "pending" | "failed" | "unknown";

/**
 * Размеры бейджа.
 */
export type ZkProofBadgeSize = "sm" | "md" | "lg";

/**
 * Режим отображения: компактный (иконка + короткий текст) или подробный (доп. данные).
 */
export type ZkProofBadgeMode = "compact" | "detailed";

export interface ZkProofMeta {
  /**
   * Хеш/идентификатор доказательства (например, Keccak/Blake2/poseidon хеш).
   * Отображается укороченным и доступен для копирования.
   */
  proofHash?: string;

  /**
   * Тип/система доказательства (e.g., zkSNARK, zkSTARK, PLONK).
   * Не влияет на логику; только для UI/лейбла.
   */
  proofType?: string;

  /**
   * Имя/идентификатор верификатора (контракт, сервис, ключ, версия схемы).
   */
  verifier?: string;

  /**
   * UNIX ms или ISO-строка времени верификации/создания.
   */
  timestamp?: number | string;

  /**
   * Ссылка на внешний ресурс (блок-эксплорер/дашборд/лог).
   */
  explorerUrl?: string;

  /**
   * Дополнительный узкий контекст (например, чейн, сеть, версия схемы).
   */
  context?: string;
}

export interface ZkProofBadgeProps extends Omit<ComponentPropsWithoutRef<"div">, "onClick"> {
  /**
   * Текущий статус.
   */
  status: ZkProofStatus;

  /**
   * Метаданные доказательства.
   */
  meta?: ZkProofMeta;

  /**
   * Размер бейджа.
   */
  size?: ZkProofBadgeSize;

  /**
   * Режим отображения.
   */
  mode?: ZkProofBadgeMode;

  /**
   * Явный лейбл (перекроет авто-лейбл из статуса).
   */
  label?: ReactNode;

  /**
   * Вариант интеракции:
   * - href: делает кликабельным ссылкой
   * - onClick: делает кликабельным кнопкой
   * Если не передано, элемент — статичный бейдж.
   */
  href?: string;
  onClick?: () => void;
  target?: "_blank" | "_self" | "_parent" | "_top";

  /**
   * Включить кнопку копирования хеша (если он передан).
   * По умолчанию true.
   */
  enableCopy?: boolean;

  /**
   * Управление визуальным подсказками (title/aria).
   * По умолчанию true.
   */
  enableHints?: boolean;

  /**
   * Пользовательские классы Tailwind.
   */
  className?: string;

  /**
   * Внешнее управление состоянием "подробностей" (например, для модалки).
   */
  detailsOpen?: boolean;
  onDetailsOpenChange?: (open: boolean) => void;

  /**
   * Отключить встроенную модалку подробностей (оставив только слот childrenDetails).
   */
  disableInlineDetails?: boolean;

  /**
   * Кастомное содержимое подробного вида (заменяет дефолтную таблицу).
   */
  childrenDetails?: ReactNode;
}

/**
 * Справочник по статусам: иконка, стили, текст по умолчанию.
 */
const STATUS_MAP: Record<
  ZkProofStatus,
  {
    icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
    label: string;
    tone: {
      ring: string;
      bg: string;
      text: string;
      hover: string;
      icon: string;
      badgeText: string;
    };
  }
> = {
  verified: {
    icon: ShieldCheck,
    label: "ZK Verified",
    tone: {
      ring: "ring-emerald-500/30",
      bg: "bg-emerald-50 dark:bg-emerald-900/20",
      text: "text-emerald-800 dark:text-emerald-200",
      hover: "hover:bg-emerald-100/80 dark:hover:bg-emerald-900/40",
      icon: "text-emerald-600 dark:text-emerald-300",
      badgeText: "text-emerald-900 dark:text-emerald-50",
    },
  },
  pending: {
    icon: Timer,
    label: "ZK Pending",
    tone: {
      ring: "ring-amber-500/30",
      bg: "bg-amber-50 dark:bg-amber-900/20",
      text: "text-amber-800 dark:text-amber-200",
      hover: "hover:bg-amber-100/80 dark:hover:bg-amber-900/40",
      icon: "text-amber-600 dark:text-amber-300",
      badgeText: "text-amber-900 dark:text-amber-50",
    },
  },
  failed: {
    icon: ShieldAlert,
    label: "ZK Failed",
    tone: {
      ring: "ring-rose-500/30",
      bg: "bg-rose-50 dark:bg-rose-900/20",
      text: "text-rose-800 dark:text-rose-200",
      hover: "hover:bg-rose-100/80 dark:hover:bg-rose-900/40",
      icon: "text-rose-600 dark:text-rose-300",
      badgeText: "text-rose-900 dark:text-rose-50",
    },
  },
  unknown: {
    icon: HelpCircle,
    label: "ZK Unknown",
    tone: {
      ring: "ring-slate-500/30",
      bg: "bg-slate-50 dark:bg-slate-900/20",
      text: "text-slate-700 dark:text-slate-200",
      hover: "hover:bg-slate-100/80 dark:hover:bg-slate-900/40",
      icon: "text-slate-600 dark:text-slate-300",
      badgeText: "text-slate-900 dark:text-slate-50",
    },
  },
};

/**
 * Обрезка длинных строк с сохранением начала и конца.
 */
function ellipsizeCenter(value: string, head = 8, tail = 6): string {
  if (!value) return "";
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/**
 * Безопасное форматирование времени.
 */
function formatTimestamp(ts?: number | string): string | undefined {
  if (ts === undefined) return undefined;
  try {
    const date = typeof ts === "number" ? new Date(ts) : new Date(ts);
    const iso = date.toISOString();
    return iso.replace("T", " ").replace("Z", " UTC");
  } catch {
    return undefined;
  }
}

/**
 * Встроенная легковесная "модалка" (без порталов/ловушек фокуса; простая и автономная).
 * При необходимости можно заменить на вашу библиотеку диалогов.
 */
function InlineModal(props: {
  open: boolean;
  title?: ReactNode;
  onClose: () => void;
  children?: ReactNode;
}) {
  if (!props.open) return null;
  return (
    <div
      aria-modal="true"
      role="dialog"
      className="fixed inset-0 z-50 flex items-center justify-center"
    >
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-sm"
        onClick={props.onClose}
        aria-hidden
      />
      <div className="relative z-10 w-full max-w-xl rounded-2xl border border-slate-200/60 dark:border-slate-800/80 bg-white dark:bg-slate-900 shadow-xl">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200/60 dark:border-slate-800/80">
          <div className="text-sm font-semibold text-slate-800 dark:text-slate-100">
            {props.title}
          </div>
          <button
            type="button"
            aria-label="Close"
            className="p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800"
            onClick={props.onClose}
          >
            <X className="h-5 w-5" aria-hidden />
          </button>
        </div>
        <div className="p-4">{props.children}</div>
      </div>
    </div>
  );
}

/**
 * Основной компонент бейджа статуса ZK-доказательства.
 */
export const ZKProofBadge = memo(function ZKProofBadge({
  status,
  meta,
  size = "md",
  mode = "compact",
  label,
  href,
  onClick,
  target = "_blank",
  enableCopy = true,
  enableHints = true,
  className,
  detailsOpen,
  onDetailsOpenChange,
  disableInlineDetails = false,
  childrenDetails,
  ...divProps
}: ZkProofBadgeProps) {
  const { icon: Icon, label: defaultLabel, tone } = STATUS_MAP[status];

  const [copied, setCopied] = useState(false);
  const [internalDetailsOpen, setInternalDetailsOpen] = useState(false);

  const isInteractive = Boolean(href || onClick);
  const resolvedLabel = label ?? defaultLabel;

  const sizeCfg = useMemo(() => {
    switch (size) {
      case "sm":
        return { padX: "px-2.5", padY: "py-1", gap: "gap-1.5", text: "text-xs", icon: "h-3.5 w-3.5" };
      case "lg":
        return { padX: "px-3.5", padY: "py-2", gap: "gap-2", text: "text-sm", icon: "h-5 w-5" };
      case "md":
      default:
        return { padX: "px-3", padY: "py-1.5", gap: "gap-2", text: "text-sm", icon: "h-4 w-4" };
    }
  }, [size]);

  const handleCopy = useCallback(async () => {
    if (!meta?.proofHash || !enableCopy) return;
    try {
      await navigator.clipboard.writeText(meta.proofHash);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Игнорируем — в некоторых окружениях clipboard может быть недоступен.
    }
  }, [meta?.proofHash, enableCopy]);

  const openDetails = useCallback(() => {
    if (onDetailsOpenChange) {
      onDetailsOpenChange(true);
    } else {
      setInternalDetailsOpen(true);
    }
  }, [onDetailsOpenChange]);

  const closeDetails = useCallback(() => {
    if (onDetailsOpenChange) {
      onDetailsOpenChange(false);
    } else {
      setInternalDetailsOpen(false);
    }
  }, [onDetailsOpenChange]);

  const isDetailsOpen = detailsOpen ?? internalDetailsOpen;

  const content = (
    <div
      {...divProps}
      className={cn(
        "inline-flex items-center rounded-full border",
        sizeCfg.padX,
        sizeCfg.padY,
        sizeCfg.gap,
        sizeCfg.text,
        tone.bg,
        "border-transparent",
        tone.ring,
        "ring-1",
        isInteractive ? "transition-colors cursor-pointer " + tone.hover : "",
        "select-none",
        className
      )}
      title={enableHints ? (typeof resolvedLabel === "string" ? resolvedLabel : undefined) : undefined}
      data-testid="zk-proof-badge"
      role={isInteractive ? "button" : "status"}
      aria-live="polite"
      aria-label={typeof resolvedLabel === "string" ? resolvedLabel : undefined}
    >
      <Icon className={cn(sizeCfg.icon, tone.icon)} aria-hidden />
      <span className={cn("font-medium", tone.badgeText)}>
        {resolvedLabel}
      </span>

      {mode === "detailed" && (
        <>
          {meta?.proofType && (
            <span className={cn("rounded-md px-1.5 py-0.5 border", tone.text, "border-current/20")}>
              {meta.proofType}
            </span>
          )}
          {meta?.context && (
            <span className={cn("rounded-md px-1.5 py-0.5 border", tone.text, "border-current/20")}>
              {meta.context}
            </span>
          )}
          {meta?.verifier && (
            <span className={cn("truncate max-w-[10rem]", tone.text)} title={meta.verifier}>
              {meta.verifier}
            </span>
          )}
          {meta?.proofHash && (
            <button
              type="button"
              onClick={enableCopy ? handleCopy : undefined}
              className={cn(
                "inline-flex items-center rounded-md px-1.5 py-0.5 border",
                "hover:bg-black/5 dark:hover:bg-white/5",
                tone.text,
                "border-current/20"
              )}
              aria-label="Copy proof hash"
              title={enableHints ? "Copy proof hash" : undefined}
            >
              <span className="mr-1 font-mono">
                {ellipsizeCenter(meta.proofHash, size === "lg" ? 10 : 8, 6)}
              </span>
              <Copy className={cn("h-3.5 w-3.5", copied ? "opacity-40" : "")} aria-hidden />
            </button>
          )}
          {meta?.explorerUrl && (
            <a
              className={cn(
                "inline-flex items-center rounded-md px-1.5 py-0.5 border",
                "hover:bg-black/5 dark:hover:bg-white/5",
                tone.text,
                "border-current/20"
              )}
              href={meta.explorerUrl}
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Open in explorer"
            >
              <ExternalLink className="h-3.5 w-3.5 mr-1" aria-hidden />
              <span className="underline decoration-dotted underline-offset-2">Explorer</span>
            </a>
          )}
          <button
            type="button"
            onClick={openDetails}
            className={cn(
              "inline-flex items-center rounded-md px-1.5 py-0.5 border",
              "hover:bg-black/5 dark:hover:bg-white/5",
              tone.text,
              "border-current/20"
            )}
            aria-expanded={isDetailsOpen}
            aria-controls="zk-proof-details"
          >
            Details
          </button>
        </>
      )}
    </div>
  );

  const wrapperProps = {
    onClick,
    href,
    target,
  };

  const Wrapper: React.FC<{ children: ReactNode }> = ({ children }) => {
    if (href) {
      return (
        <a
          {...(wrapperProps as Required<Pick<ZkProofBadgeProps, "href" | "target">>)}
          className="no-underline"
          rel={target === "_blank" ? "noopener noreferrer" : undefined}
        >
          {children}
        </a>
      );
    }
    if (onClick) {
      return (
        <button type="button" onClick={onClick} className="bg-transparent">
          {children}
        </button>
      );
    }
    return <>{children}</>;
  };

  const ts = formatTimestamp(meta?.timestamp);

  return (
    <>
      <Wrapper>{content}</Wrapper>

      {/* Встроенная модалка подробностей (можно отключить и управлять извне) */}
      {!disableInlineDetails && (
        <InlineModal
          open={Boolean(isDetailsOpen)}
          onClose={closeDetails}
          title={
            <div className="flex items-center gap-2">
              <Icon className={cn("h-4 w-4", STATUS_MAP[status].tone.icon)} aria-hidden />
              <span>ZK Proof details</span>
            </div>
          }
        >
          <div id="zk-proof-details" className="space-y-3">
            {childrenDetails ? (
              childrenDetails
            ) : (
              <div className="overflow-hidden rounded-xl border border-slate-200/60 dark:border-slate-800/80">
                <table className="w-full text-sm">
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                    <tr>
                      <td className="w-40 px-3 py-2 text-slate-500">Status</td>
                      <td className="px-3 py-2">
                        <span
                          className={cn(
                            "inline-flex items-center gap-1.5 rounded-md px-2 py-1",
                            STATUS_MAP[status].tone.bg,
                            STATUS_MAP[status].tone.badgeText
                          )}
                        >
                          <Icon className="h-4 w-4" aria-hidden />
                          {STATUS_MAP[status].label}
                        </span>
                      </td>
                    </tr>
                    {meta?.proofType && (
                      <tr>
                        <td className="w-40 px-3 py-2 text-slate-500">Proof type</td>
                        <td className="px-3 py-2">{meta.proofType}</td>
                      </tr>
                    )}
                    {meta?.context && (
                      <tr>
                        <td className="w-40 px-3 py-2 text-slate-500">Context</td>
                        <td className="px-3 py-2">{meta.context}</td>
                      </tr>
                    )}
                    {meta?.verifier && (
                      <tr>
                        <td className="w-40 px-3 py-2 text-slate-500">Verifier</td>
                        <td className="px-3 py-2">{meta.verifier}</td>
                      </tr>
                    )}
                    {meta?.proofHash && (
                      <tr>
                        <td className="w-40 px-3 py-2 text-slate-500">Proof hash</td>
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-2">
                            <code className="font-mono text-xs">{meta.proofHash}</code>
                            {enableCopy && (
                              <button
                                type="button"
                                onClick={handleCopy}
                                className="inline-flex items-center rounded-md border border-slate-200 dark:border-slate-700 px-2 py-1 hover:bg-slate-50 dark:hover:bg-slate-800"
                              >
                                <Copy className="h-4 w-4 mr-1" aria-hidden />
                                {copied ? "Copied" : "Copy"}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                    {ts && (
                      <tr>
                        <td className="w-40 px-3 py-2 text-slate-500">Timestamp</td>
                        <td className="px-3 py-2">{ts}</td>
                      </tr>
                    )}
                    {meta?.explorerUrl && (
                      <tr>
                        <td className="w-40 px-3 py-2 text-slate-500">Explorer</td>
                        <td className="px-3 py-2">
                          <a
                            className="inline-flex items-center underline decoration-dotted underline-offset-2"
                            href={meta.explorerUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <ExternalLink className="h-4 w-4 mr-1" aria-hidden />
                            Open link
                          </a>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </InlineModal>
      )}
    </>
  );
});

/**
 * Утилита для вычисления статуса на клиенте, если нужно отобразить
 * промежуточные состояния (например, нет данных = unknown).
 */
export function resolveZkStatus(input?: Partial<{ verified: boolean; pending: boolean; failed: boolean }>): ZkProofStatus {
  if (!input) return "unknown";
  if (input.failed) return "failed";
  if (input.pending) return "pending";
  if (input.verified) return "verified";
  return "unknown";
}

export default ZKProofBadge;
