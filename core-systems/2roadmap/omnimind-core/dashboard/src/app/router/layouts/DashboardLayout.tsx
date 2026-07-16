import React, {
  PropsWithChildren,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  Suspense,
} from "react";

/**
 * DashboardLayout — промышленный макет для админ/аналитики.
 * Особенности:
 * - Адаптивный сайдбар (md+ фикс, <md — выезжающий), персист состояния в localStorage
 * - Клавиатурные хоткеи: Ctrl/Cmd+B — свернуть/развернуть сайдбар, Ctrl/Cmd+K — фокус в поиск
 * - ARIA: landmarks, skip-link, правильные label/aria-атрибуты, focus trapping в мобильном сайдбаре
 * - Хлебные крошки и слот под actions
 * - ErrorBoundary + Suspense fallback + тонкий прогресс-бар
 * - Безопасно для HMR, без внешних UI-зависимостей (использует utility-классы, совместимы с Tailwind)
 */

// ============================ Типы ============================

export type NavItem = {
  key: string;
  label: string;
  icon?: React.ReactNode;
  to?: string;
  active?: boolean;
  disabled?: boolean;
  children?: NavItem[];
};

export type BreadcrumbItem = {
  label: string;
  to?: string;
  current?: boolean;
};

export type UserInfo = {
  name: string;
  email?: string;
  avatarUrl?: string;
};

export type DashboardLayoutProps = PropsWithChildren<{
  nav: NavItem[];
  breadcrumbs?: BreadcrumbItem[];
  user?: UserInfo;
  appName?: string;
  headerActions?: React.ReactNode;
  footer?: React.ReactNode;
  onSignOut?: () => void;
  onNavClick?: (item: NavItem) => void;
  isBusy?: boolean; // внешний индикатор загрузки маршрута/данных
}>;

// ============================ Утилиты ============================

const LS_KEY = "dashboard.sidebar.collapsed";
const LS_MOBILE_OPEN = "dashboard.sidebar.mobileOpen";

function clsx(...xs: Array<string | false | null | undefined>) {
  return xs.filter(Boolean).join(" ");
}

// Безопасная работа с localStorage
const safeStorage = {
  get(key: string): string | null {
    try {
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  set(key: string, value: string) {
    try {
      window.localStorage.setItem(key, value);
    } catch {
      /* no-op */
    }
  },
};

// Фокус-трап для мобильного сайдбара
function useFocusTrap(active: boolean, containerRef: React.RefObject<HTMLElement>) {
  useEffect(() => {
    if (!active || !containerRef.current) return;
    const container = containerRef.current;
    const FOCUSABLE =
      'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

    const nodes = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
      (el) => !el.hasAttribute("disabled") && !el.getAttribute("aria-hidden")
    );
    if (nodes.length === 0) return;

    const first = nodes[0];
    const last = nodes[nodes.length - 1];

    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Tab") {
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
      if (e.key === "Escape") {
        // Закрытие по Esc — оставим обработчику выше (не здесь)
      }
    };

    document.addEventListener("keydown", handleKey, true);
    return () => document.removeEventListener("keydown", handleKey, true);
  }, [active, containerRef]);
}

// Простая шина событий для HMR-дружелюбного прогресс-бара
const ProgressBus = (() => {
  let listeners: Array<(v: boolean) => void> = [];
  return {
    subscribe(fn: (v: boolean) => void) {
      listeners.push(fn);
      return () => (listeners = listeners.filter((x) => x !== fn));
    },
    emit(v: boolean) {
      listeners.forEach((fn) => fn(v));
    },
  };
})();

// ============================ Прогресс-бар ============================

function TopProgress({ busy }: { busy: boolean }) {
  const [visible, setVisible] = useState(busy);
  const [width, setWidth] = useState(0);

  // Инертный прогресс: быстро стартуем до 85%, финиш по busy=false
  useEffect(() => {
    let raf = 0;
    let t: number | null = null;
    if (busy) {
      setVisible(true);
      const tick = (ts: number) => {
        if (t == null) t = ts;
        const dt = ts - t;
        setWidth((prev) => {
          const target = Math.min(85, prev + dt * 0.05);
          return target;
        });
        raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
    } else {
      // завершение
      setWidth(100);
      const end = setTimeout(() => {
        setVisible(false);
        setWidth(0);
      }, 200);
      return () => {
        cancelAnimationFrame(raf);
        clearTimeout(end);
      };
    }
    return () => cancelAnimationFrame(raf);
  }, [busy]);

  if (!visible) return null;
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-x-0 top-0 z-50 h-0.5 bg-transparent"
    >
      <div
        className="h-0.5 bg-blue-500 transition-[width] duration-150 ease-out"
        style={{ width: `${width}%` }}
      />
    </div>
  );
}

// ============================ Error Boundary ============================

class ErrorBoundary extends React.Component<
  { fallback?: React.ReactNode },
  { error: any }
> {
  constructor(props: any) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: any) {
    return { error };
  }
  componentDidCatch() {
    // здесь можно логировать в observability
  }
  render() {
    if (this.state.error) {
      return (
        this.props.fallback ?? (
          <section className="p-6">
            <h1 className="text-xl font-semibold">Произошла ошибка</h1>
            <p className="mt-2 text-sm text-neutral-600">
              Компонент страницы не смог отрендериться.
            </p>
          </section>
        )
      );
    }
    return this.props.children as React.ReactNode;
  }
}

// ============================ Элементы UI ============================

function Avatar({ user }: { user?: UserInfo }) {
  const initials = useMemo(() => {
    if (!user?.name) return "?";
    const parts = user.name.trim().split(/\s+/);
    const first = parts[0]?.[0] ?? "";
    const last = parts[1]?.[0] ?? "";
    return (first + last || first).toUpperCase();
  }, [user?.name]);

  return user?.avatarUrl ? (
    <img
      src={user.avatarUrl}
      alt={user.name}
      className="h-8 w-8 rounded-full object-cover"
      referrerPolicy="no-referrer"
    />
  ) : (
    <div
      aria-hidden
      className="flex h-8 w-8 items-center justify-center rounded-full bg-neutral-200 text-xs font-semibold text-neutral-700"
      title={user?.name}
    >
      {initials}
    </div>
  );
}

function Breadcrumbs({ items }: { items?: BreadcrumbItem[] }) {
  if (!items?.length) return null;
  return (
    <nav aria-label="Хлебные крошки" className="text-sm text-neutral-600">
      <ol className="flex items-center gap-2">
        {items.map((b, i) => {
          const content = b.to ? (
            <a className="hover:underline" href={b.to}>
              {b.label}
            </a>
          ) : (
            <span aria-current={b.current ? "page" : undefined}>{b.label}</span>
          );
          return (
            <li key={`${b.label}-${i}`} className="flex items-center gap-2">
              {content}
              {i < items.length - 1 && <span className="text-neutral-400">/</span>}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

function SearchBox({
  onFocusRef,
}: {
  onFocusRef?: React.RefObject<HTMLInputElement>;
}) {
  return (
    <div className="relative w-full max-w-md">
      <input
        ref={onFocusRef}
        type="search"
        placeholder="Поиск…"
        aria-label="Поиск"
        className="w-full rounded-md border border-neutral-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-neutral-400 dark:bg-neutral-900 dark:text-neutral-100 dark:border-neutral-700"
      />
      <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border bg-neutral-50 px-1.5 py-0.5 text-[10px] text-neutral-600 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-300">
        Ctrl K
      </kbd>
    </div>
  );
}

function NavTree({
  items,
  onClick,
}: {
  items: NavItem[];
  onClick?: (i: NavItem) => void;
}) {
  return (
    <ul role="list" className="space-y-1">
      {items.map((i) => {
        const base = clsx(
          "group flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
          i.disabled
            ? "cursor-not-allowed text-neutral-400"
            : i.active
            ? "bg-neutral-900 text-white dark:bg-neutral-100 dark:text-neutral-900"
            : "text-neutral-800 hover:bg-neutral-100 dark:text-neutral-200 dark:hover:bg-neutral-800"
        );
        const content = (
          <button
            type="button"
            disabled={i.disabled}
            className={base}
            aria-current={i.active ? "page" : undefined}
            onClick={() => onClick?.(i)}
          >
            {i.icon && <span aria-hidden>{i.icon}</span>}
            <span className="truncate">{i.label}</span>
          </button>
        );

        return (
          <li key={i.key}>
            {i.to ? <a href={i.to} className="block">{content}</a> : content}
            {i.children?.length ? (
              <div className="ml-4 mt-1 border-l border-neutral-200 pl-3 dark:border-neutral-700">
                <NavTree items={i.children} onClick={onClick} />
              </div>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

// ============================ Основной Layout ============================

export function DashboardLayout({
  nav,
  breadcrumbs,
  user,
  appName = "Dashboard",
  headerActions,
  footer,
  onSignOut,
  onNavClick,
  isBusy,
  children,
}: DashboardLayoutProps) {
  const [collapsed, setCollapsed] = useState<boolean>(() => safeStorage.get(LS_KEY) === "1");
  const [mobileOpen, setMobileOpen] = useState<boolean>(() => safeStorage.get(LS_MOBILE_OPEN) === "1");
  const mobilePanelRef = useRef<HTMLElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  useFocusTrap(mobileOpen, mobilePanelRef);

  // Прогресс: внешний isBusy или сигнал шины
  const [bus, setBus] = useState<boolean>(!!isBusy);
  useEffect(() => setBus(!!isBusy), [isBusy]);
  useEffect(() => ProgressBus.subscribe(setBus), []);

  // Хоткеи
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isMeta = e.ctrlKey || e.metaKey;
      if (isMeta && (e.key === "b" || e.key === "B")) {
        e.preventDefault();
        setCollapsed((v) => {
          safeStorage.set(LS_KEY, v ? "0" : "1");
          return !v;
        });
      }
      if (isMeta && (e.key.toLowerCase() === "k")) {
        e.preventDefault();
        searchRef.current?.focus();
      }
      if (e.key === "Escape" && mobileOpen) {
        setMobileOpen(false);
        safeStorage.set(LS_MOBILE_OPEN, "0");
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [mobileOpen]);

  const onToggleSidebar = useCallback(() => {
    setCollapsed((v) => {
      safeStorage.set(LS_KEY, v ? "0" : "1");
      return !v;
    });
  }, []);

  const onToggleMobile = useCallback(() => {
    setMobileOpen((v) => {
      const nv = !v;
      safeStorage.set(LS_MOBILE_OPEN, nv ? "1" : "0");
      return nv;
    });
  }, []);

  // Предпочтение reduced motion
  const prefersReducedMotion = useMemo(() => {
    if (typeof window === "undefined" || !window.matchMedia) return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }, []);

  return (
    <div className="min-h-dvh bg-neutral-50 text-neutral-900 antialiased dark:bg-neutral-950 dark:text-neutral-100">
      {/* Skip link */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-neutral-900 focus:px-3 focus:py-2 focus:text-white"
      >
        Перейти к основному контенту
      </a>

      <TopProgress busy={bus} />

      {/* Шапка */}
      <header
        role="banner"
        className="sticky top-0 z-40 border-b border-neutral-200 bg-white/80 backdrop-blur dark:border-neutral-800 dark:bg-neutral-950/80"
      >
        <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-3 px-3 md:h-16 md:px-4">
          {/* Mobile menu */}
          <button
            type="button"
            onClick={onToggleMobile}
            className="inline-flex items-center gap-2 rounded-md border border-neutral-200 bg-white px-2.5 py-1.5 text-sm hover:bg-neutral-100 focus:outline-none focus:ring-2 focus:ring-neutral-400 dark:border-neutral-800 dark:bg-neutral-900 dark:hover:bg-neutral-800 md:hidden"
            aria-controls="mobile-sidebar"
            aria-expanded={mobileOpen}
            aria-label="Открыть меню"
          >
            ☰
          </button>

          {/* Brand */}
          <a href="/" className="hidden select-none items-center gap-2 md:flex">
            <div className="h-6 w-6 rounded bg-neutral-900 dark:bg-neutral-100" aria-hidden />
            <span className="text-sm font-semibold">{appName}</span>
          </a>

          {/* Toggle sidebar (desktop) */}
          <button
            type="button"
            onClick={onToggleSidebar}
            className="ml-1 hidden items-center rounded-md border border-neutral-200 bg-white px-2 py-1 text-xs hover:bg-neutral-100 focus:outline-none focus:ring-2 focus:ring-neutral-400 dark:border-neutral-800 dark:bg-neutral-900 dark:hover:bg-neutral-800 md:inline-flex"
            aria-label={collapsed ? "Развернуть панель навигации" : "Свернуть панель навигации"}
            title="Ctrl/Cmd+B"
          >
            {collapsed ? "⤢" : "⤡"}
          </button>

          {/* Search */}
          <div className="ml-2 flex-1">
            <SearchBox onFocusRef={searchRef} />
          </div>

          {/* Actions */}
          {headerActions}

          {/* User */}
          <div className="ml-2 flex items-center gap-3">
            <div className="hidden text-right md:block">
              <div className="text-sm font-medium leading-tight">{user?.name ?? "Гость"}</div>
              {user?.email && (
                <div className="text-xs leading-tight text-neutral-500 dark:text-neutral-400">
                  {user.email}
                </div>
              )}
            </div>
            <Avatar user={user} />
            {onSignOut && (
              <button
                type="button"
                onClick={onSignOut}
                className="rounded-md border border-neutral-200 bg-white px-2 py-1 text-xs hover:bg-neutral-100 focus:outline-none focus:ring-2 focus:ring-neutral-400 dark:border-neutral-800 dark:bg-neutral-900 dark:hover:bg-neutral-800"
              >
                Выйти
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Контейнер */}
      <div className="mx-auto grid max-w-[1400px] grid-cols-1 gap-0 md:grid-cols-[auto,1fr]">
        {/* Desktop sidebar */}
        <aside
          className={clsx(
            "sticky top-14 hidden h-[calc(100dvh-56px)] border-r border-neutral-200 bg-white px-3 py-3 dark:border-neutral-800 dark:bg-neutral-900 md:block md:top-16",
            collapsed ? "w-[64px]" : "w-[260px]"
          )}
          aria-label="Основная навигация"
        >
          {/* Brand small when collapsed */}
          <div className={clsx("mb-3 hidden items-center gap-2 md:flex", collapsed && "justify-center")}>
            <a href="/" className="flex items-center gap-2">
              <div className="h-6 w-6 rounded bg-neutral-900 dark:bg-neutral-100" aria-hidden />
              {!collapsed && <span className="text-sm font-semibold">{appName}</span>}
            </a>
          </div>
          <nav className={clsx(collapsed ? "px-0" : "px-0")} aria-label="Разделы">
            <NavTree
              items={nav.map((n) =>
                collapsed
                  ? { ...n, label: n.label } // подписи скрываем визуально CSS-ом при необходимости
                  : n
              )}
              onClick={onNavClick}
            />
          </nav>
          {footer && <div className="mt-4 border-t border-neutral-200 pt-3 dark:border-neutral-800">{footer}</div>}
        </aside>

        {/* Mobile sidebar (dialog-like) */}
        <div
          className={clsx(
            "md:hidden",
            mobileOpen ? "fixed inset-0 z-50" : "hidden"
          )}
          role="dialog"
          aria-modal="true"
          aria-labelledby="mobile-sidebar-title"
        >
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/30"
            onClick={onToggleMobile}
            aria-hidden="true"
          />
          {/* Panel */}
          <section
            id="mobile-sidebar"
            ref={mobilePanelRef as any}
            className={clsx(
              "fixed inset-y-0 left-0 w-[88%] max-w-[320px] border-r border-neutral-200 bg-white p-3 shadow-xl outline-none dark:border-neutral-800 dark:bg-neutral-900",
              prefersReducedMotion ? "" : "transition-transform duration-200 ease-out"
            )}
          >
            <div className="mb-3 flex items-center justify-between">
              <h2 id="mobile-sidebar-title" className="text-sm font-semibold">
                {appName}
              </h2>
              <button
                type="button"
                onClick={onToggleMobile}
                className="rounded-md border border-neutral-200 bg-white px-2 py-1 text-xs hover:bg-neutral-100 focus:outline-none focus:ring-2 focus:ring-neutral-400 dark:border-neutral-800 dark:bg-neutral-900 dark:hover:bg-neutral-800"
              >
                Закрыть
              </button>
            </div>
            <nav aria-label="Разделы (мобильный)">
              <NavTree items={nav} onClick={(i) => { onNavClick?.(i); onToggleMobile(); }} />
            </nav>
          </section>
        </div>

        {/* Main */}
        <main id="main" role="main" className="min-w-0">
          {/* Header row */}
          <div className="flex items-center justify-between gap-3 border-b border-neutral-200 bg-neutral-50 px-3 py-3 dark:border-neutral-800 dark:bg-neutral-950 md:px-6">
            <div className="min-w-0">
              <Breadcrumbs items={breadcrumbs} />
              {/* Место под заголовок страницы может занимать первый элемент crumbs */}
              {breadcrumbs?.length ? (
                <h1 className="mt-1 truncate text-lg font-semibold leading-tight">
                  {breadcrumbs[breadcrumbs.length - 1]?.label}
                </h1>
              ) : null}
            </div>
            {/* Доп. actions можно также передать в headerActions, здесь оставим зазор */}
            <div className="hidden md:block">{/* right-side placeholders */}</div>
          </div>

          {/* Content */}
          <ErrorBoundary
            fallback={
              <section className="p-6">
                <h2 className="text-lg font-semibold">Ошибка рендера</h2>
                <p className="mt-1 text-sm text-neutral-600">
                  Попробуйте обновить страницу или вернуться назад.
                </p>
              </section>
            }
          >
            <Suspense
              fallback={
                <section className="p-6">
                  <div className="h-4 w-32 animate-pulse rounded bg-neutral-200 dark:bg-neutral-800" />
                  <div className="mt-4 space-y-2">
                    <div className="h-3 w-full animate-pulse rounded bg-neutral-200 dark:bg-neutral-800" />
                    <div className="h-3 w-5/6 animate-pulse rounded bg-neutral-200 dark:bg-neutral-800" />
                    <div className="h-3 w-4/6 animate-pulse rounded bg-neutral-200 dark:bg-neutral-800" />
                  </div>
                </section>
              }
            >
              <section className="min-h-[calc(100dvh-56px-48px)] px-3 py-4 md:min-h-[calc(100dvh-64px-57px)] md:px-6">
                {children}
              </section>
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

// ============================ Пример интеграции прогресса ============================

/**
 * В местах, где известны переходы маршрутов/загрузки, можно дергать:
 *  ProgressBus.emit(true)  // старт
 *  ProgressBus.emit(false) // стоп
 * или использовать проп isBusy в <DashboardLayout isBusy />
 */
export const RouteProgress = {
  start: () => ProgressBus.emit(true),
  stop: () => ProgressBus.emit(false),
};
