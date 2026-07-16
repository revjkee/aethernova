'use client';

import React, { ComponentType, useEffect, useMemo, useRef, useState, startTransition } from 'react';
import { usePathname, useRouter } from 'next/navigation';

/**
 * Контракт минимального хука аутентификации.
 * Ожидается, что в проекте существует совместимый хук `useAuth` и он возвращает текущее состояние.
 * Подключите свой реальный хук здесь.
 */
export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  roles?: string[]; // список ролей пользователя (например: ['admin','viewer'])
}

/**
 * Замените путь импорта на фактический хук вашего проекта.
 * Важно: useRouter/usePathname работают ТОЛЬКО в Client Components (нужна директива 'use client'). :contentReference[oaicite:1]{index=1}
 */
import { useAuth } from '@/app/hooks/useAuth';

export type RoleMode = 'any' | 'all';

export interface GuardOptions {
  /**
   * Требовать аутентификацию. Если false — маршрут публичный.
   */
  requireAuth?: boolean;
  /**
   * Запретить доступ, если пользователь уже аутентифицирован (например, /signin).
   */
  denyIfAuthenticated?: boolean;
  /**
   * Требуемые роли.
   */
  roles?: string[];
  /**
   * Логика сопоставления ролей:
   *  - 'any' (по умолчанию) — достаточно одной из требуемых ролей;
   *  - 'all' — требуются все роли из списка.
   */
  roleMode?: RoleMode;
  /**
   * Куда перенаправлять НЕаутентифицированного пользователя.
   */
  redirectTo?: string; // например: '/auth/signin'
  /**
   * Куда перенаправлять аутентифицированного пользователя при denyIfAuthenticated = true.
   */
  redirectIfAuthedTo?: string; // например: '/dashboard'
  /**
   * Куда отправлять при отсутствии нужных ролей.
   */
  forbiddenTo?: string; // например: '/403'
  /**
   * Fallback-секция при загрузке (skeleton/loader). Если не задан — компонент не рендерится до разруливания.
   */
  fallback?: React.ReactNode;
  /**
   * Ключ в localStorage для сохранения «намеренного пути» при редиректе на логин.
   */
  intendedKey?: string; // по умолчанию: 'omnimind:intended'
}

/**
 * Утилита сопоставления ролей.
 */
export function canAccess(
  userRoles: readonly string[] | undefined,
  required: readonly string[] | undefined,
  mode: RoleMode = 'any',
): boolean {
  if (!required || required.length === 0) return true; // ролей не требуется
  if (!userRoles || userRoles.length === 0) return false;
  const set = new Set(userRoles.map((r) => r.toLowerCase()));
  if (mode === 'all') {
    return required.every((r) => set.has(r.toLowerCase()));
  }
  // 'any'
  return required.some((r) => set.has(r.toLowerCase()));
}

/**
 * Высшего порядка компонент-защитник для клиентских страниц/виджетов App Router.
 * Использует useRouter для программной навигации в клиенте (поддерживается и задокументировано). :contentReference[oaicite:2]{index=2}
 */
export function withGuard<P extends object>(
  Wrapped: ComponentType<P>,
  options: GuardOptions,
) {
  const {
    requireAuth = false,
    denyIfAuthenticated = false,
    roles,
    roleMode = 'any',
    redirectTo = '/auth/signin',
    redirectIfAuthedTo = '/dashboard',
    forbiddenTo = '/403',
    fallback = null,
    intendedKey = 'omnimind:intended',
  } = options;

  const Guarded: React.FC<P> = (props) => {
    const { isAuthenticated, isLoading, roles: userRoles } = useAuth() as AuthState;
    const router = useRouter();
    const pathname = usePathname();

    // Блокировка повторных попыток редиректа при двойном рендере React 18
    const redirectingRef = useRef(false);

    // Помним последний результат доступа, чтобы избежать лишних эффектов
    const [allowed, setAllowed] = useState<boolean>(false);

    const needRolesCheck = roles && roles.length > 0;

    const roleOk = useMemo(
      () => canAccess(userRoles, roles, roleMode),
      [userRoles, roles, roleMode],
    );

    useEffect(() => {
      // Пока грузится состояние аутентификации — не решаем, можно показать fallback
      if (isLoading) {
        setAllowed(false);
        return;
      }

      // Предотвращаем циклический редирект (например, уже на странице логина)
      const isSame = (target: string) => {
        try {
          // нормализуем только путь без query/hash
          const t = new URL(target, globalThis.location?.origin ?? 'http://localhost').pathname;
          return t === pathname;
        } catch {
          return false;
        }
      };

      const saveIntended = () => {
        try {
          if (typeof window !== 'undefined') {
            window.localStorage.setItem(intendedKey, pathname ?? '/');
          }
        } catch {
          // no-op: localStorage может быть недоступен
        }
      };

      // Ветка «запретить, если уже аутентифицирован» (например, /signin, /signup)
      if (denyIfAuthenticated && isAuthenticated) {
        if (!redirectingRef.current && !isSame(redirectIfAuthedTo)) {
          redirectingRef.current = true;
          startTransition(() => {
            router.replace(redirectIfAuthedTo);
          });
        }
        setAllowed(false);
        return;
      }

      // Ветка «нужна аутентификация»
      if (requireAuth && !isAuthenticated) {
        if (!redirectingRef.current && !isSame(redirectTo)) {
          saveIntended();
          redirectingRef.current = true;
          startTransition(() => {
            router.replace(redirectTo);
          });
        }
        setAllowed(false);
        return;
      }

      // Ролевая проверка
      if (needRolesCheck && !roleOk) {
        if (!redirectingRef.current && !isSame(forbiddenTo)) {
          redirectingRef.current = true;
          startTransition(() => {
            router.replace(forbiddenTo);
          });
        }
        setAllowed(false);
        return;
      }

      // Доступ разрешён
      setAllowed(true);
    }, [
      denyIfAuthenticated,
      forbiddenTo,
      intendedKey,
      isAuthenticated,
      isLoading,
      needRolesCheck,
      pathname,
      redirectIfAuthedTo,
      redirectTo,
      roleOk,
      router,
      requireAuth,
    ]);

    if (isLoading && fallback) {
      return <>{fallback}</>;
    }

    return allowed ? <Wrapped {...(props as P)} /> : null;
  };

  Guarded.displayName = `WithGuard(${Wrapped.displayName || Wrapped.name || 'Component'})`;

  return Guarded;
}

/**
 * Лёгкий компонент-защитник для JSX-дерева без HOC.
 *
 * Пример:
 *   <Guard requireAuth roles={['admin']} fallback={<Spinner/>}>
 *     <AdminPanel/>
 *   </Guard>
 */
export const Guard: React.FC<React.PropsWithChildren<GuardOptions>> = ({
  children,
  ...opts
}) => {
  const Guarded = useMemo(() => withGuard(() => <>{children}</>, opts), [children, opts]);
  return <Guarded />;
};

/**
 * Хелпер извлечения и очистки «намеренного пути» после успешного логина.
 * Вы можете вызвать его в логин-потоке и затем сделать router.replace(returnTo).
 * Клиентская навигация и рекомендации по навигации в App Router описаны в официальных гайдах. :contentReference[oaicite:3]{index=3}
 */
export function consumeIntendedPath(key = 'omnimind:intended', fallback = '/'): string {
  try {
    if (typeof window === 'undefined') return fallback;
    const value = window.localStorage.getItem(key);
    if (value) {
      window.localStorage.removeItem(key);
      return value;
    }
  } catch {
    /* no-op */
  }
  return fallback;
}
