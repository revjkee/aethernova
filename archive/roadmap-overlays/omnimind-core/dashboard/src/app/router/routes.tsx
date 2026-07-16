import React, { Component, PropsWithChildren, Suspense, useEffect } from "react";
import {
  createBrowserRouter,
  type RouteObject,
  Navigate,
  Outlet,
  useLocation,
} from "react-router-dom";

/**
 * Типы ролей и фич-флагов; адаптируйте под свою RBAC/FF систему.
 */
export type UserRole = "admin" | "analyst" | "operator" | "viewer";
export type FeatureFlag = "analytics" | "audit" | "billing" | "labs";

/**
 * Метаданные маршрута.
 */
export type RouteMeta = {
  title?: string;
  breadcrumb?: string | ((params: Record<string, string>) => string);
  requireAuth?: boolean;
  roles?: UserRole[];
  featureFlag?: FeatureFlag;
  telemetryName?: string;
};

/**
 * Обогащенный тип RouteObject с метаданными и id.
 */
export type AppRouteObject = RouteObject & {
  id: string;
  meta?: RouteMeta;
  children?: AppRouteObject[];
};

/**
 * Внешние контракты-провайдеры (замените на фактические импорты вашего приложения).
 * Здесь объявлены минимальные интерфейсы, чтобы routes.tsx оставался самодостаточным.
 */
export interface AuthContextValue {
  isAuthenticated: boolean;
  roles: Set<UserRole>;
}

export interface FeatureContextValue {
  has(flag: FeatureFlag): boolean;
}

export interface Telemetry {
  trackPageView(payload: { name: string; path: string; title?: string }): void;
}

/**
 * Функции-резолверы контекстов. Реальные реализации должны прийти из ваших провайдеров.
 * Здесь мы ожидаем, что на уровне приложения созданы React Context'ы и экспортируются хуки:
 *   useAuth(), useFeatures(), useTelemetry().
 * Чтобы избежать циклических зависимостей, принимаем их через DI во createAppRouter().
 */
export type RouterDeps = {
  useAuth: () => AuthContextValue;
  useFeatures: () => FeatureContextValue;
  useTelemetry?: () => Telemetry | null;
  /**
   * Опционально: глобальный layout для защищенной области.
   * Если не передан, используется <Outlet/> без обертки.
   */
  ProtectedLayout?: React.ComponentType<PropsWithChildren<unknown>>;
  /**
   * Опционально: публичный layout (для /signin и пр.)
   */
  PublicLayout?: React.ComponentType<PropsWithChildren<unknown>>;
};

/**
 * Унифицированный Error Boundary для маршрутов.
 */
class RouteErrorBoundary extends Component<PropsWithChildren> {
  override componentDidCatch(error: unknown) {
    // Место для интеграции с Sentry/otel
    // console.error(error);
  }
  override render() {
    return this.props.children;
  }
}

/**
 * Унифицированный Suspense wrapper.
 */
function WithSuspense({ children }: PropsWithChildren) {
  return <Suspense fallback={<div aria-busy="true">Loading…</div>}>{children}</Suspense>;
}

/**
 * Охранник аутентификации/ролей/фич.
 */
function makeGuard(deps: RouterDeps, meta?: RouteMeta) {
  const { useAuth, useFeatures } = deps;
  function Guard() {
    const auth = useAuth();
    const features = useFeatures();
    const location = useLocation();

    // Проверка feature flag
    if (meta?.featureFlag && !features.has(meta.featureFlag)) {
      return <Navigate to="/403" replace state={{ from: location }} />;
    }
    // Проверка аутентификации
    if (meta?.requireAuth && !auth.isAuthenticated) {
      return <Navigate to="/signin" replace state={{ from: location }} />;
    }
    // Проверка ролей
    if (meta?.roles && meta.roles.length > 0) {
      const allowed = meta.roles.some((r) => auth.roles.has(r));
      if (!allowed) return <Navigate to="/403" replace state={{ from: location }} />;
    }
    return <Outlet />;
  }
  return Guard;
}

/**
 * Трассировка просмотров страниц.
 */
function makePageViewTracker(deps: RouterDeps, route: AppRouteObject) {
  const { useTelemetry } = deps;
  const name = route.meta?.telemetryName ?? route.id;
  const title = route.meta?.title;
  function Tracker() {
    const telemetry = useTelemetry?.() ?? null;
    const location = useLocation();
    useEffect(() => {
      telemetry?.trackPageView({ name, path: location.pathname, title });
    }, [telemetry, name, title, location.pathname]);
    return <Outlet />;
  }
  return Tracker;
}

/**
 * Ленивые страницы (код-сплиттинг).
 * Обновите пути импорта на свои реальные страницы.
 */
const DashboardPage = React.lazy(() => import(/* webpackChunkName: "page-dashboard" */ "../pages/dashboard/DashboardPage"));
const AnalyticsOverviewPage = React.lazy(() => import(/* webpackChunkName: "page-analytics-overview" */ "../pages/analytics/OverviewPage"));
const AnalyticsReportPage = React.lazy(() => import(/* webpackChunkName: "page-analytics-report" */ "../pages/analytics/ReportPage"));
const SettingsGeneralPage = React.lazy(() => import(/* webpackChunkName: "page-settings-general" */ "../pages/settings/GeneralPage"));
const SettingsAccessPage = React.lazy(() => import(/* webpackChunkName: "page-settings-access" */ "../pages/settings/AccessPage"));
const SignInPage = React.lazy(() => import(/* webpackChunkName: "page-auth-signin" */ "../pages/auth/SignInPage"));
const NotFoundPage = React.lazy(() => import(/* webpackChunkName: "page-not-found" */ "../pages/system/NotFoundPage"));
const ForbiddenPage = React.lazy(() => import(/* webpackChunkName: "page-forbidden" */ "../pages/system/ForbiddenPage"));

/**
 * Фабрика маршрутизатора. Принимает зависимости (хуки/лейауты).
 */
export function createAppRouter(deps: RouterDeps) {
  const ProtectedLayout = deps.ProtectedLayout ?? ((p: PropsWithChildren) => <>{p.children}</>);
  const PublicLayout = deps.PublicLayout ?? ((p: PropsWithChildren) => <>{p.children}</>);

  // Корневой guard для защищенной области
  const ProtectedGuard = makeGuard(deps, { requireAuth: true });
  const PublicGuard = makeGuard(deps);

  // Трассировка
  const trackDashboard = makePageViewTracker(deps, { id: "dashboard", meta: { telemetryName: "Dashboard" } } as AppRouteObject);
  const trackAnalytics = makePageViewTracker(deps, { id: "analytics", meta: { telemetryName: "Analytics" } } as AppRouteObject);
  const trackSettings = makePageViewTracker(deps, { id: "settings", meta: { telemetryName: "Settings" } } as AppRouteObject);

  const routes: AppRouteObject[] = [
    {
      id: "root",
      path: "/",
      element: (
        <RouteErrorBoundary>
          <ProtectedLayout>
            <ProtectedGuard />
          </ProtectedLayout>
        </RouteErrorBoundary>
      ),
      children: [
        {
          id: "dashboard",
          index: true,
          meta: {
            title: "Dashboard",
            breadcrumb: "Dashboard",
            requireAuth: true,
          },
          element: (
            <WithSuspense>
              <trackDashboard />
              <DashboardPage />
            </WithSuspense>
          ),
        },
        {
          id: "analytics",
          path: "analytics",
          element: (
            <WithSuspense>
              <trackAnalytics />
              <Outlet />
            </WithSuspense>
          ),
          meta: {
            title: "Analytics",
            breadcrumb: "Analytics",
            requireAuth: true,
            roles: ["admin", "analyst"],
            featureFlag: "analytics",
          },
          children: [
            {
              id: "analytics-overview",
              index: true,
              meta: {
                title: "Overview",
                breadcrumb: "Overview",
                requireAuth: true,
                roles: ["admin", "analyst"],
                featureFlag: "analytics",
              },
              element: (
                <WithSuspense>
                  <AnalyticsOverviewPage />
                </WithSuspense>
              ),
            },
            {
              id: "analytics-report",
              path: "reports/:reportId",
              meta: {
                title: "Report",
                breadcrumb: ({ reportId }) => `Report #${reportId}`,
                requireAuth: true,
                roles: ["admin", "analyst"],
                featureFlag: "analytics",
              },
              element: (
                <WithSuspense>
                  <AnalyticsReportPage />
                </WithSuspense>
              ),
            },
          ],
        },
        {
          id: "settings",
          path: "settings",
          element: (
            <WithSuspense>
              <trackSettings />
              <Outlet />
            </WithSuspense>
          ),
          meta: {
            title: "Settings",
            breadcrumb: "Settings",
            requireAuth: true,
            roles: ["admin"],
          },
          children: [
            {
              id: "settings-general",
              index: true,
              meta: {
                title: "General",
                breadcrumb: "General",
                requireAuth: true,
                roles: ["admin"],
              },
              element: (
                <WithSuspense>
                  <SettingsGeneralPage />
                </WithSuspense>
              ),
            },
            {
              id: "settings-access",
              path: "access",
              meta: {
                title: "Access control",
                breadcrumb: "Access",
                requireAuth: true,
                roles: ["admin"],
              },
              element: (
                <WithSuspense>
                  <SettingsAccessPage />
                </WithSuspense>
              ),
            },
          ],
        },
      ],
    },

    // Публичные маршруты (без авторизации)
    {
      id: "public",
      path: "/",
      element: (
        <RouteErrorBoundary>
          <PublicLayout>
            <PublicGuard />
          </PublicLayout>
        </RouteErrorBoundary>
      ),
      children: [
        {
          id: "signin",
          path: "signin",
          meta: { title: "Sign in", breadcrumb: "Sign in" },
          element: (
            <WithSuspense>
              <SignInPage />
            </WithSuspense>
          ),
        },
        {
          id: "forbidden",
          path: "403",
          meta: { title: "Forbidden", breadcrumb: "Forbidden" },
          element: (
            <WithSuspense>
              <ForbiddenPage />
            </WithSuspense>
          ),
        },
      ],
    },

    // Fallback 404
    {
      id: "not-found",
      path: "*",
      element: (
        <WithSuspense>
          <NotFoundPage />
        </WithSuspense>
      ),
      meta: { title: "Not Found", breadcrumb: "Not Found" },
    },
  ];

  return {
    routes,
    router: createBrowserRouter(routes),
  };
}

/**
 * Хелперы для выборки метаданных (например, для заголовков и хлебных крошек).
 */
export function flattenRoutes(tree: AppRouteObject[]): AppRouteObject[] {
  const acc: AppRouteObject[] = [];
  const walk = (nodes: AppRouteObject[], parentPath = "") => {
    for (const r of nodes) {
      const fullPath =
        r.path
          ? (parentPath.endsWith("/") || !parentPath ? "" : `${parentPath}/`) +
            r.path
          : parentPath;
      acc.push({ ...r, path: fullPath });
      if (r.children) walk(r.children, fullPath ?? "");
    }
  };
  walk(tree);
  return acc;
}
