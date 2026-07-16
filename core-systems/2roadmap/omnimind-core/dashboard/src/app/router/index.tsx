// core-systems/omnimind-core/dashboard/src/app/router/index.tsx
import React, { lazy, Suspense, useEffect, useMemo } from "react";
import {
  createBrowserRouter,
  RouterProvider,
  Navigate,
  Outlet,
  useLocation,
} from "react-router-dom";
import type { RouteObject } from "react-router-dom";
import { useAuth } from "@/app/providers/AuthProvider";

/**
 * Базовая конфигурация окружения.
 * Поддерживает Vite (import.meta.env) и NODE_ENV переменные.
 */
const isBrowser = typeof window !== "undefined";
const BASENAME: string =
  (isBrowser && (import.meta as any)?.env?.VITE_ROUTER_BASENAME) ||
  process.env.VITE_ROUTER_BASENAME ||
  process.env.ROUTER_BASENAME ||
  "/";

/**
 * Ленивые страницы (реальные пути страниц — адаптируйте под проект).
 * Важно: имена файлов/путей должны существовать в вашем репозитории.
 */
const DashboardPage = lazy(() => import("@/pages/DashboardPage"));
const LoginPage = lazy(() => import("@/pages/auth/LoginPage"));
const ProfilePage = lazy(() => import("@/pages/account/ProfilePage"));
const SettingsPage = lazy(() => import("@/pages/settings/SettingsPage"));
const UsersPage = lazy(() => import("@/pages/admin/UsersPage"));
const AccessDeniedPage = lazy(() => import("@/pages/errors/AccessDeniedPage"));
const NotFoundPage = lazy(() => import("@/pages/errors/NotFoundPage"));

/**
 * Универсальная "раскраска" загрузки.
 * В проде имеет смысл заменить на скелетоны/лоадер из дизайн-системы.
 */
function Loading() {
  return (
    <div style={{ padding: 24 }}>
      <div>Loading…</div>
    </div>
  );
}

/**
 * Error Boundary для маршрутов/ленивых чанк-фейлов.
 */
class RouteErrorBoundary extends React.Component<
  React.PropsWithChildren<{}>,
  { error: Error | null }
> {
  constructor(props: React.PropsWithChildren<{}>) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error) {
    if (process.env.NODE_ENV !== "production") {
      // eslint-disable-next-line no-console
      console.error("Route boundary error:", error);
    }
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 24 }}>
          <h2>Unexpected error</h2>
          <pre style={{ whiteSpace: "pre-wrap" }}>{String(this.state.error.message || this.state.error)}</pre>
        </div>
      );
    }
    return this.props.children as React.ReactElement;
  }
}

/**
 * Scroll Restore + простейшая аналитика на смену маршрута.
 * Аналитику интегрируйте через ваш observer (например, posthog/gtag).
 */
function RouteEffects() {
  const location = useLocation();
  useEffect(() => {
    if (isBrowser) {
      window.scrollTo({ top: 0, left: 0, behavior: "instant" as ScrollBehavior });
      // Пример хука аналитики:
      // analytics.track("page_view", { path: location.pathname, search: location.search });
    }
  }, [location.pathname, location.search]);
  return null;
}

/**
 * Гостевой макет: страницы без авторизации (логин/регистрация и т.д.).
 */
function PublicLayout() {
  return (
    <Suspense fallback={<Loading />}>
      <RouteEffects />
      <Outlet />
    </Suspense>
  );
}

/**
 * Авторизованный макет: защищённые страницы.
 * Здесь можно подключить главный AppShell, хедер/сайдбар и т.д.
 */
function PrivateLayout() {
  return (
    <Suspense fallback={<Loading />}>
      <RouteEffects />
      <Outlet />
    </Suspense>
  );
}

/**
 * Guard: доступ только неавторизованным пользователям (например, логин).
 * Авторизованных редиректим на дефолтный приватный маршрут.
 */
function GuestOnly() {
  const { state } = useAuth();
  if (state.isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }
  return <Outlet />;
}

/**
 * Guard: доступ только авторизованным пользователям.
 * Неавторизованных — на /login, сохранив intended путь.
 */
function RequireAuth() {
  const { state } = useAuth();
  const location = useLocation();
  if (!state.isAuthenticated) {
    return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  }
  return <Outlet />;
}

/**
 * Guard: проверка роли (или хотя бы одной из списка).
 */
function RequireRoles(props: { anyOf: string[] }) {
  const { state } = useAuth();
  const roles = new Set(state.user?.roles ?? []);
  const allowed = props.anyOf.some((r) => roles.has(r));
  if (!allowed) {
    return <Navigate to="/access-denied" replace />;
  }
  return <Outlet />;
}

/**
 * Константы путей проекта (удобно использовать централизованно).
 */
export const ROUTES = {
  ROOT: "/",
  LOGIN: "/login",
  DASHBOARD: "/dashboard",
  PROFILE: "/account/profile",
  SETTINGS: "/settings",
  ADMIN_USERS: "/admin/users",
  ACCESS_DENIED: "/access-denied",
  NOT_FOUND: "*",
};

/**
 * Определение дерева маршрутов.
 * При необходимости добавьте лэйауты, nested routes и т.д.
 */
function useRouteObjects(): RouteObject[] {
  // Можно мемоизировать, чтобы не пересоздавать дерево.
  return useMemo<RouteObject[]>(
    () => [
      // Гостевые маршруты
      {
        element: <PublicLayout />,
        errorElement: (
          <RouteErrorBoundary>
            <Loading />
          </RouteErrorBoundary>
        ),
        children: [
          { path: ROUTES.ROOT, element: <Navigate to={ROUTES.DASHBOARD} replace /> },
          { path: ROUTES.LOGIN, element: <GuestOnly />, children: [{ index: true, element: <LoginPage /> }] },
          { path: ROUTES.ACCESS_DENIED, element: <AccessDeniedPage /> },
        ],
      },

      // Приватная зона (нужна авторизация)
      {
        element: <RequireAuth />,
        children: [
          {
            element: <PrivateLayout />,
            errorElement: (
              <RouteErrorBoundary>
                <Loading />
              </RouteErrorBoundary>
            ),
            children: [
              { path: ROUTES.DASHBOARD, element: <DashboardPage /> },
              { path: ROUTES.PROFILE, element: <ProfilePage /> },
              { path: ROUTES.SETTINGS, element: <SettingsPage /> },

              // Пример: только администраторы
              {
                element: <RequireRoles anyOf={["admin", "superadmin"]} />,
                children: [{ path: ROUTES.ADMIN_USERS, element: <UsersPage /> }],
              },
            ],
          },
        ],
      },

      // 404 в самом конце
      {
        path: ROUTES.NOT_FOUND,
        element: (
          <Suspense fallback={<Loading />}>
            <NotFoundPage />
          </Suspense>
        ),
      },
    ],
    []
  );
}

/**
 * Экспортируем корневой компонент маршрутизатора.
 * Включает RouterProvider с basename (для деплоя в подпуть).
 */
export function AppRouter() {
  const routes = useRouteObjects();

  // Создаём router один раз на жизненный цикл (basename — из env).
  const router = useMemo(() => createBrowserRouter(routes, { basename: BASENAME }), [routes]);

  return <RouterProvider router={router} fallbackElement={<Loading />} />;
}

export default AppRouter;
