import React, {
  memo,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  PropsWithChildren,
} from "react";
import { motion, AnimatePresence } from "framer-motion";

// shadcn/ui — дизайн-система
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// Иконки lucide-react (поддерживается импорт конкретных иконок)
import {
  ShieldCheck,
  Zap,
  Cpu,
  ExternalLink,
  Lock,
  Activity,
  BadgeCheck,
  ArrowRight,
} from "lucide-react";

// Вспомогательные типы
type LucideIcon = React.ComponentType<React.SVGProps<SVGSVGElement>>;

export type FeatureItem = {
  id: string;
  title: string;
  description?: string;
  icon?: LucideIcon | React.ReactNode;
  href?: string;
  ctaLabel?: string;
  tag?: string;
  tagVariant?: "default" | "secondary" | "destructive" | "outline";
  emphasis?: "default" | "primary" | "success" | "warning" | "danger";
  disabled?: boolean;
  onClick?: () => void;
  // произвольные данные для аналитики
  analytics?: Record<string, unknown>;
};

export type FeatureCardsProps = {
  items: FeatureItem[] | null | undefined;
  title?: string;
  description?: string;
  headerAside?: React.ReactNode;
  // сетка
  columns?: {
    base?: number; // по умолчанию 1
    sm?: number;   // ≥640px
    md?: number;   // ≥768px
    lg?: number;   // ≥1024px
    xl?: number;   // ≥1280px
  };
  variant?: "default" | "compact" | "hero";
  animated?: boolean; // анимация карточек
  revealOnScroll?: boolean; // анимация при появлении в вьюпорте
  loading?: boolean; // показать скелеты
  skeletonCount?: number; // количество скелетов
  showEmptyState?: boolean; // рендер пустого состояния, если нет items
  emptyState?: React.ReactNode;
  // аналитика
  onImpression?: (id: string, meta?: Record<string, unknown>) => void;
  onClickItem?: (id: string, meta?: Record<string, unknown>) => void;
  // aria
  ariaLabel?: string;
  // тестовые id
  "data-testid"?: string;
};

// Безопасный utils для классов
function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

// Маппинг цветов и статусов
const EMPHASIS_STYLES: Record<
  NonNullable<FeatureItem["emphasis"]>,
  { ring: string; badge: string; icon: string }
> = {
  default: { ring: "ring-border", badge: "", icon: "" },
  primary: { ring: "ring-blue-500/20", badge: "bg-blue-600 text-white", icon: "text-blue-600" },
  success: { ring: "ring-emerald-500/20", badge: "bg-emerald-600 text-white", icon: "text-emerald-600" },
  warning: { ring: "ring-amber-500/20", badge: "bg-amber-600 text-white", icon: "text-amber-600" },
  danger:  { ring: "ring-rose-500/20", badge: "bg-rose-600 text-white", icon: "text-rose-600" },
};

// Варианты плотности
const VARIANT_CARD_CLASS: Record<
  NonNullable<FeatureCardsProps["variant"]>,
  { header: string; content: string; footer: string; title: string; description: string }
> = {
  default: {
    header: "p-6",
    content: "px-6 pb-4",
    footer: "px-6 pb-6",
    title: "text-lg",
    description: "text-sm text-muted-foreground",
  },
  compact: {
    header: "p-4",
    content: "px-4 pb-3",
    footer: "px-4 pb-4",
    title: "text-base",
    description: "text-sm text-muted-foreground",
  },
  hero: {
    header: "p-8",
    content: "px-8 pb-6",
    footer: "px-8 pb-8",
    title: "text-xl",
    description: "text-base text-muted-foreground",
  },
};

// Скелет-плейсхолдер
const Skeleton: React.FC<{ className?: string; "data-testid"?: string }> = ({
  className,
  ...rest
}) => (
  <div
    className={cx(
      "animate-pulse rounded-md bg-muted/50 dark:bg-muted/30",
      className
    )}
    {...rest}
  />
);

// Хук для «импрессий» карточки
const useImpression = (
  enabled: boolean,
  onImpression?: FeatureCardsProps["onImpression"],
  payload?: { id: string; meta?: Record<string, unknown> }
) => {
  const ref = useRef<HTMLDivElement | null>(null);
  const seenRef = useRef(false);

  useEffect(() => {
    if (!enabled || !onImpression || !ref.current || seenRef.current) return;

    const el = ref.current;
    const io = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        if (entry.isIntersecting && !seenRef.current) {
          seenRef.current = true;
          onImpression(payload?.id ?? "", payload?.meta);
          io.disconnect();
        }
      },
      { root: null, threshold: 0.35 }
    );

    io.observe(el);
    return () => io.disconnect();
  }, [enabled, onImpression, payload?.id, payload?.meta]);

  return ref;
};

// Рендер иконки с безопасностью типов
const FeatureIcon: React.FC<{
  icon?: FeatureItem["icon"];
  emphasis?: FeatureItem["emphasis"];
  size?: number;
  className?: string;
  "data-testid"?: string;
}> = ({ icon, emphasis = "default", size = 22, className, ...rest }) => {
  const style = EMPHASIS_STYLES[emphasis];
  if (!icon) return null;
  if (React.isValidElement(icon)) {
    return (
      <span className={cx("inline-flex", style.icon, className)} {...rest}>
        {icon}
      </span>
    );
  }
  const Icon = icon as LucideIcon;
  return (
    <Icon
      aria-hidden
      width={size}
      height={size}
      className={cx(style.icon, className)}
      {...rest}
    />
  );
};

// Плашка-тег
const TagBadge: React.FC<{
  label?: string;
  variant?: FeatureItem["tagVariant"];
  className?: string;
}> = ({ label, variant = "secondary", className }) => {
  if (!label) return null;
  return <Badge variant={variant} className={className}>{label}</Badge>;
};

const DEFAULT_ICONS: LucideIcon[] = [ShieldCheck, Zap, Cpu, Lock, Activity, BadgeCheck];

const EmptyState: React.FC<PropsWithChildren<{ title?: string; description?: string }>> = ({
  title = "Нет данных",
  description = "Элементы для отображения отсутствуют.",
  children,
}) => (
  <div
    role="status"
    aria-live="polite"
    className="w-full rounded-xl border bg-card text-card-foreground p-8 text-center"
  >
    <div className="mx-auto mb-3 h-10 w-10 rounded-full bg-muted flex items-center justify-center">
      <Lock className="h-5 w-5 text-muted-foreground" aria-hidden />
    </div>
    <h3 className="text-base font-semibold">{title}</h3>
    <p className="mt-1 text-sm text-muted-foreground">{description}</p>
    {children ? <div className="mt-4">{children}</div> : null}
  </div>
);

// Основной компонент
const FeatureCardsComponent: React.FC<FeatureCardsProps> = ({
  items,
  title,
  description,
  headerAside,
  columns,
  variant = "default",
  animated = true,
  revealOnScroll = true,
  loading = false,
  skeletonCount = 6,
  showEmptyState = true,
  emptyState,
  onImpression,
  onClickItem,
  ariaLabel,
  "data-testid": dataTestId = "feature-cards",
}) => {
  const sectionId = useId();

  // Нормализуем вход
  const normalizedItems = useMemo<FeatureItem[]>(() => {
    if (!Array.isArray(items)) return [];
    return items
      .filter(Boolean)
      .filter((it) => typeof it?.id === "string" && it.id.trim().length > 0)
      .map((it, idx) => ({
        // заполняем дефолты
        title: `Feature #${idx + 1}`,
        emphasis: "default",
        ...it,
      }));
  }, [items]);

  const isEmpty = !loading && normalizedItems.length === 0;

  // Классы для грид-сетки
  const cols = {
    base: columns?.base ?? 1,
    sm: columns?.sm ?? 2,
    md: columns?.md ?? 3,
    lg: columns?.lg ?? 3,
    xl: columns?.xl ?? 4,
  };

  const gridClass = useMemo(
    () =>
      cx(
        "grid gap-4",
        `grid-cols-${Math.min(Math.max(cols.base, 1), 6)}`,
        cols.sm ? `sm:grid-cols-${Math.min(cols.sm, 6)}` : "",
        cols.md ? `md:grid-cols-${Math.min(cols.md, 6)}` : "",
        cols.lg ? `lg:grid-cols-${Math.min(cols.lg, 6)}` : "",
        cols.xl ? `xl:grid-cols-${Math.min(cols.xl, 6)}` : ""
      ),
    [cols.base, cols.sm, cols.md, cols.lg, cols.xl]
  );

  // Варианты плотности
  const density = VARIANT_CARD_CLASS[variant];

  // Скелеты
  const skeletons = useMemo(
    () =>
      Array.from({ length: Math.max(1, Math.min(skeletonCount, 12)) }, (_, i) => i),
    [skeletonCount]
  );

  // Анимационные пресеты
  const animContainer = {
    hidden: {},
    visible: { transition: { staggerChildren: 0.06, delayChildren: 0.05 } },
  };

  const animItem = {
    hidden: { opacity: 0, y: revealOnScroll ? 16 : 0 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.28, ease: "easeOut" } },
  };

  return (
    <section
      id={sectionId}
      role="region"
      aria-label={ariaLabel ?? title ?? "Feature cards"}
      className="w-full"
      data-testid={dataTestId}
    >
      {(title || description || headerAside) && (
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            {title ? (
              <h2 className="text-xl font-semibold leading-7" data-testid="feature-cards-title">
                {title}
              </h2>
            ) : null}
            {description ? (
              <p
                className="mt-1 text-sm text-muted-foreground"
                data-testid="feature-cards-description"
              >
                {description}
              </p>
            ) : null}
          </div>
          {headerAside ? <div className="shrink-0">{headerAside}</div> : null}
        </div>
      )}

      {/* Скелеты загрузки */}
      {loading && (
        <div className={gridClass} aria-busy="true" aria-live="polite">
          {skeletons.map((i) => (
            <Card
              key={`sk-${i}`}
              className="overflow-hidden"
              data-testid="feature-card-skeleton"
            >
              <div className={density.header}>
                <Skeleton className="h-6 w-6 rounded-full" />
              </div>
              <div className={density.content}>
                <Skeleton className="h-5 w-2/3" />
                <Skeleton className="mt-2 h-4 w-11/12" />
                <Skeleton className="mt-1.5 h-4 w-8/12" />
              </div>
              <div className={density.footer}>
                <Skeleton className="h-9 w-28 rounded-md" />
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Пустое состояние */}
      {isEmpty && showEmptyState && (
        <div data-testid="feature-cards-empty">
          {emptyState ?? <EmptyState />}
        </div>
      )}

      {/* Сетка карточек */}
      {!loading && !isEmpty && (
        <AnimatePresence initial={false}>
          <motion.div
            className={gridClass}
            variants={animated ? animContainer : undefined}
            initial={animated ? "hidden" : undefined}
            animate={animated ? "visible" : undefined}
          >
            {normalizedItems.map((item, idx) => {
              const Icon =
                item.icon ??
                (DEFAULT_ICONS[idx % DEFAULT_ICONS.length] as LucideIcon);
              const emphasis = item.emphasis ?? "default";
              const styles = EMPHASIS_STYLES[emphasis];

              const impressionRef = useImpression(
                Boolean(revealOnScroll && animated),
                onImpression,
                { id: item.id, meta: item.analytics }
              );

              const clickable = !item.disabled && (item.href || item.onClick);
              const cta = item.ctaLabel ?? (item.href ? "Подробнее" : "Открыть");

              const content = (
                <>
                  <CardHeader className={cx(density.header, "flex flex-row items-center gap-3")}>
                    <div
                      className={cx(
                        "h-10 w-10 shrink-0 rounded-lg border bg-muted/40 flex items-center justify-center",
                        styles.ring
                      )}
                    >
                      <FeatureIcon icon={Icon} emphasis={emphasis} />
                    </div>
                    <div className="min-w-0">
                      <CardTitle className={cx("truncate", density.title)}>
                        {item.title}
                      </CardTitle>
                      {item.description ? (
                        <CardDescription className={cx("line-clamp-2", density.description)}>
                          {item.description}
                        </CardDescription>
                      ) : null}
                    </div>
                    <div className="ms-auto">
                      <TagBadge label={item.tag} variant={item.tagVariant} />
                    </div>
                  </CardHeader>

                  <CardContent className={density.content}>
                    {/* Дополнительный контент можно передать через description; для простоты описание уже показано */}
                  </CardContent>

                  <CardFooter className={cx(density.footer, "flex justify-between items-center gap-2")}>
                    <div className="text-xs text-muted-foreground" data-testid="feature-card-id">
                      {item.id}
                    </div>
                    <Button
                      size={variant === "compact" ? "sm" : "default"}
                      variant={clickable ? "default" : "secondary"}
                      disabled={!clickable}
                      onClick={() => {
                        if (item.onClick) item.onClick();
                        if (onClickItem) onClickItem(item.id, item.analytics);
                        // если есть href — оставляем переход на родительский <a> (если будет)
                      }}
                      data-testid="feature-card-cta"
                    >
                      {cta}
                      <ArrowRight className="ms-2 h-4 w-4" aria-hidden />
                    </Button>
                  </CardFooter>
                </>
              );

              // Обёртка: если есть href и не disabled — делаем ссылку
              const Wrapper: React.FC<PropsWithChildren> = ({ children }) =>
                item.href && !item.disabled ? (
                  <a
                    href={item.href}
                    className="group focus:outline-none"
                    aria-label={`${item.title} — перейти`}
                    onClick={(e) => {
                      // даём Button обработать onClickItem, но не ломаем переход
                      // здесь можно подключить router-link при необходимости
                      e.stopPropagation();
                    }}
                  >
                    {children}
                  </a>
                ) : (
                  <>{children}</>
                );

              return (
                <motion.div
                  key={item.id}
                  variants={animated ? animItem : undefined}
                  ref={impressionRef}
                  data-testid="feature-card"
                >
                  <Wrapper>
                    <Card
                      className={cx(
                        "h-full transition-colors",
                        item.disabled ? "opacity-60 pointer-events-none" : "hover:border-primary/50"
                      )}
                      role="article"
                      aria-disabled={item.disabled ? "true" : "false"}
                    >
                      {content}
                    </Card>
                  </Wrapper>
                </motion.div>
              );
            })}
          </motion.div>
        </AnimatePresence>
      )}
    </section>
  );
};

export const FeatureCards = memo(FeatureCardsComponent);
export default FeatureCards;

/**
 * Пример безопасного использования (для справки разработчику):
 *
 * <FeatureCards
 *   title="Ключевые возможности"
 *   description="Основные модули платформы"
 *   items={[
 *     { id: "sec", title: "Zero-Trust Security", description: "Политики нулевого доверия", icon: ShieldCheck, href: "/security", tag: "Core", emphasis: "primary" },
 *     { id: "ai", title: "AI Orchestration", description: "Оркестрация агентов и рабочих процессов", icon: Cpu, tag: "AI", emphasis: "success" },
 *     { id: "perf", title: "Ultra Performance", description: "Низкие задержки, высокий TPS", icon: Zap, tag: "Perf", emphasis: "warning" },
 *   ]}
 *   animated
 *   revealOnScroll
 *   onImpression={(id, meta) => console.debug("Impression:", id, meta)}
 *   onClickItem={(id, meta) => console.debug("Click:", id, meta)}
 * />
 */
