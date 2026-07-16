"use client";

import React, {
  PropsWithChildren,
  ReactNode,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { NavLink, Outlet, useLocation, useMatches, useNavigation } from "react-router-dom";
import { useTheme } from "../../providers/ThemeProvider";

/**
 * Вспомогательные типы/константы
 */
type ClassValue = string | number | false | null | undefined | ClassValue[] | { [k: string]: any };
function cx(...args: ClassValue[]): string {
  const acc: string[] = [];
  const push = (v: any) => {
    if (!v) return;
    if (typeof v === "string" || typeof v === "number") acc.push(String(v));
    else if (Array.isArray(v)) v.forEach(push);
    else if (typeof v === "object") Object.keys(v).forEach(k => v[k] && acc.push(k));
  };
  args.forEach(push);
  return acc.join(" ");
}

const SIDEBAR_STORAGE_KEY = "omnimind:sidebar:collapsed";

/**
 * Индикатор маршрутизации (без внешних зависимостей).
 * Показывается при навигации React Router.
 */
function TopProgressBar() {
  const nav = useNavigation();
  const [progress, setProgress] = useState(0);
  const raf = useRef<number | null>(null);

  useEffect(() => {
    const anim = () => {
      setProgress(p => Math.min(p + Math.max((100 - p) * 0.07, 0.5), 97));
      raf.current = requestAnimationFrame(anim);
    };
    if (nav.state === "loading") {
      setProgress(8);
      raf.current = requestAnimationFrame(anim);
    } else {
      setProgress(100);
      const t = setTimeout(() => setProgress(0), 200);
      if (raf.current) cancelAnimationFrame(raf.current);
      return () => clearTimeout(t);
    }
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current);
    };
  }, [nav.state]);

  return (
    <div
      aria-hidden
      className="fixed left-0 right-0 top-0 z-[9999] h-[2px] transition-[opacity,transform] duration-200"
      style={{
        background:
          "linear-gradient(90deg, rgba(99,102,241,1) 0%, rgba(147,51,234,1) 100%)",
        transform: `scaleX(${progress / 100})`,
        transformOrigin: "0% 50%",
        opacity: progress > 0 ? 1 : 0,
      }}
    />
  );
}

/**
 * Error Boundary для областей layout.
 */
class ShellErrorBoundary extends React.Component<
  PropsWithChildren,
  { hasError: boolean }
> {
  constructor(props: PropsWithChildren) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  override componentDidCatch(err: unknown) {
    // Здесь можно интегрировать Sentry/otel
    // console.error(err);
  }
  override render() {
    if (this.state.hasError) {
      return (
        <section
          role="alert"
          className="m-6 rounded-xl border border-red-400/40 bg-red-50 p-6 text-red-900 dark:border-red-900/40 dark:bg-red-950/40 dark:text-red-200"
        >
          <h2 className="mb-2 text-lg font-semibold">Ошибка интерфейса</h2>
          <p className="opacity-80">
            Что-то пошло не так. Обновите страницу или вернитесь на главную.
          </p>
        </section>
      );
    }
    return this.props.children as React.ReactElement;
  }
}

/**
 * Хлебные крошки из URL и метаданных маршрутов.
 * useMatches() отдает массив совпавших маршрутов, где в meta можно хранить title/breadcrumb.
 */
function useBreadcrumbs() {
  const matches = useMatches() as Array<any>;
  const crumbs = useMemo(() => {
    const items: Array<{ label: string; path?: string }> = [];
    for (const m of matches) {
      const label =
        typeof m?.meta?.breadcrumb === "function"
          ? m.meta.breadcrumb(m.params ?? {})
          : m?.meta?.breadcrumb ??
            m?.meta?.title ??
            (typeof m?.id === "string" ? m.id : "");
      if (!label) continue;
      const path = m.pathname ?? m?.path ?? undefined;
      items.push({ label, path });
    }
    // удаляем дубликаты подряд
    return items.filter((v, i, a) => i === 0 || v.label !== a[i - 1].label);
  }, [matches]);
  return crumbs;
}

/**
 * Синхронизация viewport-единицы --vh (устранение 100vh проблем на мобильных).
 */
function useViewportUnit() {
  const recalc = useCallback(() => {
    if (typeof window === "undefined") return;
    const vh = window.innerHeight * 0.01;
    document.documentElement.style.setProperty("--vh", `${vh}px`);
  }, []);
  useEffect(() => {
    recalc();
    window.addEventListener("resize", recalc);
    return () => window.removeEventListener("resize", recalc);
  }, [recalc]);
}

/**
 * Шорткаты:
 * - Ctrl/Cmd+J — переключение темы
 * - Ctrl/Cmd+B — свернуть/раскрыть боковую панель
 */
function useKeyboardShortcuts(toggleTheme: () => void, toggleSidebar: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (!mod) return;
      if (e.key.toLowerCase() === "j") {
        e.preventDefault();
        toggleTheme();
      }
      if (e.key.toLowerCase() === "b") {
        e.preventDefault();
        toggleSidebar();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleTheme, toggleSidebar]);
}

/**
 * Обновление document.title из активного маршрута (meta.title) + постфикс бренда.
 */
function useDocumentTitle(brandSuffix = "OmniMind") {
  const matches = useMatches() as Array<any>;
  useEffect(() => {
    const current = [...matches].reverse().find(m => m?.meta?.title)?.meta?.title;
    const title = current ? `${current} • ${brandSuffix}` : brandSuffix;
    if (typeof document !== "undefined") document.title = title;
  }, [matches, brandSuffix]);
}

/**
 * Header
 */
function Header({
  onToggleSidebar,
  rightSlot,
}: {
  onToggleSidebar: () => void;
  rightSlot?: ReactNode;
}) {
  const { resolvedTheme, toggleTheme } = useTheme();
  return (
    <header
      role="banner"
      className="sticky top-0 z-40 border-b border-black/5 bg-white/80 backdrop-blur supports-[backdrop-filter]:bg-white/60 dark:border-white/10 dark:bg-neutral-950/70"
    >
      <div className="mx-auto flex h-14 w-full max-w-[1400px] items-center gap-2 px-3 sm:px-4">
        <button
          type="button"
          onClick={onToggleSidebar}
          className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-black/10 bg-white text-neutral-700 hover:bg-neutral-100 focus:outline-none focus-visible:ring dark:border-white/10 dark:bg-neutral-900 dark:text-neutral-200 dark:hover:bg-neutral-800"
          aria-label="Toggle sidebar"
        >
          {/* Иконка бургер */}
          <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
            <path
              d="M4 6h16M4 12h16M4 18h16"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
            />
          </svg>
        </button>

        <a href="#content" className="sr-only focus:not-sr-only focus:ml-2">
          Skip to content
        </a>

        <div className="ml-1 mr-auto select-none text-sm font-semibold tracking-wide text-neutral-800 dark:text-neutral-100">
          OmniMind Core
        </div>

        <nav aria-label="Header actions" className="flex items-center gap-2">
          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex h-9 items-center gap-2 rounded-md border border-black/10 bg-white px-3 text-xs font-medium text-neutral-700 hover:bg-neutral-100 focus:outline-none focus-visible:ring dark:border-white/10 dark:bg-neutral-900 dark:text-neutral-200 dark:hover:bg-neutral-800"
            aria-pressed={resolvedTheme === "dark"}
            aria-label="Toggle theme"
            title="Toggle theme (Ctrl/Cmd+J)"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden>
              <path
                d="M12 3a9 9 0 0 0 0 18 9 9 0 0 1 0-18z"
                fill="currentColor"
              />
            </svg>
            {resolvedTheme === "dark" ? "Dark" : "Light"}
          </button>

          {rightSlot}
        </nav>
      </div>
    </header>
  );
}

/**
 * Sidebar
 */
function Sidebar({
  collapsed,
  onToggle,
}: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  const location = useLocation();
  const itemClass =
    "flex items-center gap-2 rounded-md px-3 py-2 text-sm text-neutral-700 hover:bg-neutral-100 aria-[current=page]:bg-neutral-200 dark:text-neutral-200 dark:hover:bg-neutral-800 dark:aria-[current=page]:bg-neutral-800/70";

  return (
    <aside
      aria-label="Primary"
      className={cx(
        "border-r border-black/5 bg-white dark:border-white/10 dark:bg-neutral-950",
        "transition-[width] duration-200 ease-out overflow-hidden",
        collapsed ? "w-[60px]" : "w-[260px]"
      )}
    >
      <div className="flex h-14 items-center justify-end px-3">
        <button
          type="button"
          onClick={onToggle}
          className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-black/10 bg-white text-neutral-700 hover:bg-neutral-100 focus:outline-none focus-visible:ring dark:border-white/10 dark:bg-neutral-900 dark:text-neutral-200 dark:hover:bg-neutral-800"
          aria-label="Collapse sidebar"
          aria-pressed={collapsed}
          title="Toggle sidebar (Ctrl/Cmd+B)"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden>
            <path
              d="M15 6l-6 6 6 6"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
      </div>

      <nav className="px-3 py-2">
        <ul className="space-y-1">
          <li>
            <NavLink to="/" end className={itemClass}>
              <span className="inline-block w-5">
                <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
                  <path
                    d="M3 11l9-8 9 8v9a2 2 0 0 1-2 2h-4V12H9v10H5a2 2 0 0 1-2-2z"
                    fill="currentColor"
                  />
                </svg>
              </span>
              <span className={cx("truncate", collapsed && "sr-only")}>Dashboard</span>
            </NavLink>
          </li>
          <li>
            <NavLink to="/analytics" className={itemClass}>
              <span className="inline-block w-5">
                <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
                  <path
                    d="M4 19h4V9H4v10zm6 0h4V5h-4v14zm6 0h4v-7h-4v7z"
                    fill="currentColor"
                  />
                </svg>
              </span>
              <span className={cx("truncate", collapsed && "sr-only")}>Analytics</span>
            </NavLink>
          </li>
          <li>
            <NavLink to="/settings" className={itemClass}>
              <span className="inline-block w-5">
                <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
                  <path
                    d="M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm9.4 4a7.4 7.4 0 0 0-.05-.86l2.1-1.64-2-3.46-2.5 1a7.5 7.5 0 0 0-1.5-.86l-.38-2.65h-4l-.39 2.65a7.5 7.5 0 0 0-1.49.86l-2.5-1-2 3.46 2.09 1.64a7.4 7.4 0 0 0 0 1.72L2.25 14.5l2 3.46 2.5-1c.47.35.97.64 1.5.86l.39 2.65h4l.39-2.65c.52-.22 1.02-.51 1.5-.86l2.5 1 2-3.46-2.09-1.64c.03-.28.05-.57.05-.86z"
                    fill="currentColor"
                  />
                </svg>
              </span>
              <span className={cx("truncate", collapsed && "sr-only")}>Settings</span>
            </NavLink>
          </li>
        </ul>
      </nav>
    </aside>
  );
}

/**
 * Хлебные крошки
 */
function Breadcrumbs() {
  const items = useBreadcrumbs();
  if (items.length <= 1) return null;

  return (
    <nav aria-label="Breadcrumb" className="mb-2 text-sm text-neutral-500 dark:text-neutral-400">
      <ol className="flex flex-wrap items-center gap-1">
        {items.map((c, i) => {
          const last = i === items.length - 1;
          return (
            <li key={`${c.label}-${i}`} aria-current={last ? "page" : undefined}>
              {!last && c.path ? (
                <>
                  <a
                    href={c.path}
                    className="hover:underline"
                  >
                    {c.label}
                  </a>
                  <span className="mx-1 opacity-60">/</span>
                </>
              ) : (
                <span className="font-medium text-neutral-700 dark:text-neutral-200">
                  {c.label}
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/**
 * Footer
 */
function Footer() {
  return (
    <footer
      role="contentinfo"
      className="border-t border-black/5 bg-white/60 px-4 py-3 text-xs text-neutral-500 backdrop-blur dark:border-white/10 dark:bg-neutral-950/60 dark:text-neutral-400"
    >
      <div className="mx-auto flex w-full max-w-[1400px] items-center justify-between">
        <div>© {new Date().getFullYear()} OmniMind Core</div>
        <div className="opacity-80">Build ID: <span id="build-id">dev</span></div>
      </div>
    </footer>
  );
}

/**
 * Корневой Layout приложения
 */
export default function RootLayout({ children }: PropsWithChildren) {
  useViewportUnit();
  useDocumentTitle("OmniMind");
  const location = useLocation();
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(SIDEBAR_STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const toggleSidebar = useCallback(() => {
    setCollapsed(prev => {
      const next = !prev;
      try {
        localStorage.setItem(SIDEBAR_STORAGE_KEY, next ? "1" : "0");
      } catch {
        // ignore
      }
      return next;
    });
  }, []);

  const { toggleTheme } = useTheme();
  useKeyboardShortcuts(toggleTheme, toggleSidebar);

  // Фокусируем основной контент после навигации для доступности
  const mainRef = useRef<HTMLElement | null>(null);
  useEffect(() => {
    mainRef.current?.focus();
  }, [location.pathname]);

  return (
    <div
      data-app-shell
      className="grid h-[calc(var(--vh,1vh)*100)] grid-rows-[auto,1fr,auto] bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100"
    >
      <TopProgressBar />
      <Header onToggleSidebar={toggleSidebar} />

      <div className="mx-auto grid w-full max-w-[1400px] grid-cols-[auto,1fr] gap-0 px-3 sm:px-4">
        <Sidebar collapsed={collapsed} onToggle={toggleSidebar} />

        <ShellErrorBoundary>
          <main
            id="content"
            ref={mainRef as any}
            tabIndex={-1}
            role="main"
            className="min-w-0 scroll-pt-16 px-3 py-4 outline-none sm:px-4"
          >
            <Breadcrumbs />
            <Suspense
              fallback={
                <div className="rounded-xl border border-black/5 bg-white/60 p-6 text-sm text-neutral-600 backdrop-blur dark:border-white/10 dark:bg-neutral-900/60 dark:text-neutral-300">
                  Загрузка…
                </div>
              }
            >
              {children ?? <Outlet />}
            </Suspense>
          </main>
        </ShellErrorBoundary>
      </div>

      <Footer />
    </div>
  );
}
