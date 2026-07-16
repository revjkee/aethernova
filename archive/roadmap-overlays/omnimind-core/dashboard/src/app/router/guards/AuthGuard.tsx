'use client';

import React, { ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';

/**
 * Тип описывает минимальный снимок аутентификации, который должен вернуть резолвер.
 */
export type AuthSnapshot = {
  isAuthenticated: boolean;
  /** Сырый JWT access token (необязательно, но нужен для проверки exp/nbf). */
  accessToken?: string | null;
  /** Роли/скоупы текущего пользователя (из токена или профиля). */
  roles?: string[] | null;
  /** Идентификатор организации/тенанта (при мультиарендности). */
  tenantId?: string | null;
  /** Свободная форма профиля — если нужно. */
  user?: Record<string, unknown> | null;
  /** Индикатор «ещё идёт загрузка состояния» — опционально. */
  loading?: boolean;
};

/**
 * Опции проверки ролей и условий.
 */
export type RoleCheckMode = 'all' | 'any';

export type AuthGuardProps = {
  children: ReactNode;

  /** Куда редиректить при отсутствии доступа. */
  redirectTo?: string;

  /** Разрешить ли анонимный доступ (если нет критичных условий). */
  allowAnonymous?: boolean;

  /** Требуемые роли/скоупы для доступа. Пусто — без проверки ролей. */
  requiredRoles?: string[];

  /** Режим проверки ролей: все (AND) или любые (OR). По умолчанию — 'all'. */
  roleMode?: RoleCheckMode;

  /** Требуемый tenant/organization. Если указан — должен совпасть. */
  requiredTenantId?: string;

  /** Допустимая расхождение часов при проверке exp/nbf, сек. По умолчанию 60. */
  clockSkewSec?: number;

  /** Компонент/узел-заглушка на период проверки. */
  loadingFallback?: ReactNode;

  /**
   * Резолвер состояния аутентификации.
   * Если не передан — используется «умный» дефолт:
   *  1) window.__AUTH__ (если установлен вашим провайдером)
   *  2) localStorage["access_token"] или cookie "access_token"
   */
  resolveAuth?: () => Promise<AuthSnapshot> | AuthSnapshot;
};

/* ========================= УТИЛИТЫ ========================= */

/** Безопасная Base64URL декодировка без зависимостей. */
function base64UrlDecode(input: string): string {
  try {
    const pad = (s: string) => s + '==='.slice((s.length + 3) % 4);
    const b64 = pad(input.replace(/-/g, '+').replace(/_/g, '/'));
    if (typeof atob !== 'undefined') {
      return decodeURIComponent(
        Array.prototype.map
          .call(atob(b64), (c: string) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
    }
    // Node polyfill (на всякий случай; в браузере путь выше)
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const buf = Buffer.from(b64, 'base64').toString('utf8');
    return buf;
  } catch {
    return '';
  }
}

/** Декодирование полезной нагрузки JWT без верификации подписи (только парсинг). */
function decodeJwtPayload<T = Record<string, unknown>>(token?: string | null): T | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const json = base64UrlDecode(parts[1] ?? '');
  try {
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}

/** Проверка exp/nbf c допуском по времени. */
function isJwtTimeWindowValid(token?: string | null, skewSec = 60): boolean {
  if (!token) return false;
  const payload = decodeJwtPayload<{ exp?: number; nbf?: number }>(token);
  if (!payload) return false;
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.nbf === 'number' && now + skewSec < payload.nbf) return false;
  if (typeof payload.exp === 'number' && now - skewSec >= payload.exp) return false;
  return true;
}

/** Нормализация строки роли: trim + toLowerCase. */
function normRole(s: string): string {
  return s.trim().toLowerCase();
}

/** Проверка набора ролей по режиму all/any. */
function checkRoles(
  userRoles: string[] | null | undefined,
  required: string[] | null | undefined,
  mode: RoleCheckMode
): boolean {
  if (!required || required.length === 0) return true; // Ничего не требуем
  const have = new Set((userRoles ?? []).map(normRole));
  if (mode === 'all') return required.every((r) => have.has(normRole(r)));
  return required.some((r) => have.has(normRole(r)));
}

/** Попытка вытащить токен из localStorage/cookie как резервный источник. */
function getTokenFromBrowserStorage(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    const fromLs = window.localStorage?.getItem('access_token');
    if (fromLs) return fromLs;
  } catch {
    /* ignore */
  }
  try {
    const m = document.cookie.match(/(?:^|;\s*)access_token=([^;]*)/);
    if (m && m[1]) return decodeURIComponent(m[1]);
  } catch {
    /* ignore */
  }
  return null;
}

/** Дефолтный резолвер аутентификации (без внешних зависимостей). */
async function defaultResolveAuth(): Promise<AuthSnapshot> {
  // 1) Попробуем глобальный снимок, который мог положить ваш AuthProvider
  const anyWin = typeof window !== 'undefined' ? (window as any) : undefined;
  const fromGlobal: AuthSnapshot | undefined = anyWin?.__AUTH__;
  if (fromGlobal && typeof fromGlobal === 'object') {
    return {
      isAuthenticated: !!fromGlobal.isAuthenticated,
      accessToken: fromGlobal.accessToken ?? null,
      roles: fromGlobal.roles ?? null,
      tenantId: fromGlobal.tenantId ?? null,
      user: fromGlobal.user ?? null,
      loading: !!fromGlobal.loading,
    };
  }

  // 2) Резерв — токен из браузерного стора
  const token = getTokenFromBrowserStorage();
  const payload = decodeJwtPayload<Record<string, unknown>>(token ?? undefined);
  const roles =
    (Array.isArray((payload as any)?.roles) && ((payload as any).roles as string[])) ||
    (typeof (payload as any)?.scope === 'string'
      ? String((payload as any).scope)
          .split(' ')
          .filter(Boolean)
      : null);

  return {
    isAuthenticated: !!token && isJwtTimeWindowValid(token),
    accessToken: token,
    roles: roles ?? null,
    tenantId: (payload as any)?.tenant_id ?? (payload as any)?.org_id ?? null,
    user: payload ?? null,
    loading: false,
  };
}

/* ========================= КОМПОНЕНТ ========================= */

export function AuthGuard(props: AuthGuardProps) {
  const {
    children,
    redirectTo = '/login',
    allowAnonymous = false,
    requiredRoles,
    roleMode = 'all',
    requiredTenantId,
    clockSkewSec = 60,
    loadingFallback = (
      <div className="flex h-dvh w-full items-center justify-center">
        <div className="animate-pulse rounded-xl border px-6 py-4 text-sm text-muted-foreground bg-card">
          Проверка доступа…
        </div>
      </div>
    ),
    resolveAuth,
  } = props;

  const router = useRouter();
  const mounted = useRef(false);

  const [snapshot, setSnapshot] = useState<AuthSnapshot>({ isAuthenticated: false, loading: true });

  const doResolve = useCallback(async () => {
    const resolver = resolveAuth ?? defaultResolveAuth;
    const s = await resolver();
    setSnapshot({
      isAuthenticated: !!s.isAuthenticated,
      accessToken: s.accessToken ?? null,
      roles: s.roles ?? null,
      tenantId: s.tenantId ?? null,
      user: s.user ?? null,
      loading: !!s.loading,
    });
  }, [resolveAuth]);

  useEffect(() => {
    mounted.current = true;
    void doResolve();
    return () => {
      mounted.current = false;
    };
  }, [doResolve]);

  const verdict = useMemo(() => {
    // Пока идёт явная загрузка — отображаем лоадер
    if (snapshot.loading) return 'loading' as const;

    // Если анонимный доступ разрешён и не требуются роли/тенант — впускаем
    const rolesRequired = Array.isArray(requiredRoles) && requiredRoles.length > 0;
    const tenantRequired = typeof requiredTenantId === 'string' && requiredTenantId.length > 0;

    if (allowAnonymous && !rolesRequired && !tenantRequired) {
      return 'allow' as const;
    }

    // Проверяем валидность токена (если есть)
    const tokenOk = isJwtTimeWindowValid(snapshot.accessToken, clockSkewSec);

    const basicAuth = snapshot.isAuthenticated && tokenOk;

    if (!basicAuth) return 'deny' as const;

    // Роли
    if (rolesRequired) {
      const ok = checkRoles(snapshot.roles, requiredRoles, roleMode);
      if (!ok) return 'deny' as const;
    }

    // Тенант
    if (tenantRequired) {
      const match = snapshot.tenantId && snapshot.tenantId === requiredTenantId;
      if (!match) return 'deny' as const;
    }

    return 'allow' as const;
  }, [
    snapshot.loading,
    snapshot.isAuthenticated,
    snapshot.accessToken,
    snapshot.roles,
    snapshot.tenantId,
    allowAnonymous,
    requiredRoles,
    roleMode,
    requiredTenantId,
    clockSkewSec,
  ]);

  useEffect(() => {
    if (verdict === 'deny') {
      // Защищённый, без истории «назад», чтобы избежать петли
      router.replace(redirectTo);
    }
  }, [verdict, redirectTo, router]);

  if (verdict === 'loading') return <>{loadingFallback}</>;
  if (verdict === 'deny') return null;
  return <>{children}</>;
}

export default AuthGuard;
