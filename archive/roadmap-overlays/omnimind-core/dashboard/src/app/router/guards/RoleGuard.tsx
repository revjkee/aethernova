import { ReactNode, useMemo } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { paths } from "../paths";
import type { Me, UserRole } from "../types";
import { useAuth } from "../../state/useAuth"; // адаптируйте к вашему стору

type AccessMode = "any" | "all";

export interface RoleGuardProps {
  children: ReactNode;

  // Роли, которые должны быть у пользователя (в зависимости от mode)
  need?: UserRole[];

  // Роли, которые запрещены (любой матч — отказ)
  deny?: UserRole[];

  // Необязательные строковые "permissions" (фичи/привилегии), проверяемые отдельно
  permissions?: string[];

  // Режим проверки ролей: "any" (хватает одной) или "all" (нужны все)
  mode?: AccessMode;

  // Режим проверки permissions: "any" | "all"
  permMode?: AccessMode;

  // Кастомная функция-предикат. Если задана — участвует в финальном И-условии.
  // Например: (ctx) => ctx.me?.id === ctx.resourceOwnerId
  check?: (ctx: {
    me: Me | null;
    roles: UserRole[];
    permissions: Set<string>;
  }) => boolean;

  // Поведение при отказе: рендерить fallback или делать редирект
  behavior?: "render" | "redirect";

  // Куда редиректить при отказе (по умолчанию — /dashboard)
  redirectTo?: string;

  // Что показать при проверке (когда auth.isLoading = true)
  loadingFallback?: ReactNode;

  // Что показать при отказе доступа, если behavior="render"
  deniedFallback?: ReactNode;
}

/**
 * Вспомогательные функции доступа. Можно реиспользовать в сторе/сервисах.
 */
export function hasAny<T>(userSet: Set<T>, required?: T[]): boolean {
  if (!required || required.length === 0) return true; // нечего требовать — считаем пройдено
  return required.some((r) => userSet.has(r));
}

export function hasAll<T>(userSet: Set<T>, required?: T[]): boolean {
  if (!required || required.length === 0) return true;
  return required.every((r) => userSet.has(r));
}

/**
 * Композиция правил доступа: deny, need (roles), permissions, кастомный check.
 */
function computeAccess(opts: {
  me: Me | null;
  rolesSet: Set<UserRole>;
  permsSet: Set<string>;
  need?: UserRole[];
  deny?: UserRole[];
  permissions?: string[];
  mode: AccessMode;
  permMode: AccessMode;
  check?: RoleGuardProps["check"];
}): boolean {
  const {
    me,
    rolesSet,
    permsSet,
    need,
    deny,
    permissions,
    mode,
    permMode,
    check,
  } = opts;

  // 1) Запрещённые роли: любая — отказ
  if (deny && deny.some((r) => rolesSet.has(r))) {
    return false;
  }

  // 2) Требуемые роли
  const rolesOk =
    mode === "all" ? hasAll(rolesSet, need) : hasAny(rolesSet, need);

  if (!rolesOk) return false;

  // 3) Доп. права/permissions (если есть)
  let permsOk = true;
  if (permissions && permissions.length > 0) {
    const checkFn = permMode === "all" ? hasAll<string> : hasAny<string>;
    permsOk = checkFn(permsSet, permissions);
    if (!permsOk) return false;
  }

  // 4) Кастомный предикат. Если задан — должен вернуть true
  if (typeof check === "function") {
    const ok = check({ me, roles: Array.from(rolesSet), permissions: permsSet });
    if (!ok) return false;
  }

  return true;
}

/**
 * RoleGuard — универсальный охранник маршрутов/компонентов.
 * Поддерживает:
 *  - any/all для ролей и прав
 *  - deny-список
 *  - собственный предикат
 *  - рендер fallback или редирект
 *  - корректная обработка isLoading / !isAuthenticated
 */
export function RoleGuard({
  children,
  need,
  deny,
  permissions,
  mode = "any",
  permMode = "any",
  check,
  behavior = "render",
  redirectTo = paths.dashboard.root,
  loadingFallback = <div>Checking access…</div>,
  deniedFallback = <div>Access denied</div>,
}: RoleGuardProps) {
  const { me, isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  // 0) Загрузка статуса сессии
  if (isLoading) {
    return <>{loadingFallback}</>;
  }

  // 1) Неавторизован — отправляем на логин, сохранив точку возврата
  if (!isAuthenticated) {
    return (
      <Navigate
        to={paths.auth.login}
        replace
        state={{ from: location, reason: "unauthenticated" }}
      />
    );
  }

  // 2) Приводим роль/права пользователя к сетам
  const { rolesSet, permsSet } = useMemo(() => {
    const r = new Set<UserRole>(me?.roles ?? []);
    // Если в системе есть явный список permissions у пользователя — подставьте здесь.
    // По умолчанию читаем из me как me.permissions?: string[]
    const p = new Set<string>(Array.isArray((me as any)?.permissions) ? (me as any).permissions : []);
    return { rolesSet: r, permsSet: p };
  }, [me]);

  // 3) Считаем доступ
  const allowed = useMemo(
    () =>
      computeAccess({
        me,
        rolesSet,
        permsSet,
        need,
        deny,
        permissions,
        mode,
        permMode,
        check,
      }),
    [me, rolesSet, permsSet, need, deny, permissions, mode, permMode, check]
  );

  if (!allowed) {
    if (behavior === "redirect") {
      return (
        <Navigate
          to={redirectTo}
          replace
          state={{ from: location, reason: "forbidden" }}
        />
      );
    }
    return <>{deniedFallback}</>;
  }

  return <>{children}</>;
}

export default RoleGuard;
