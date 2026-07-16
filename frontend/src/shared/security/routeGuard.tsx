export const routeGuard = (
  isAuthenticated: boolean,
  roles: string[],
  allowedRoles: string[],
): boolean => {
  if (!isAuthenticated) return false
  if (allowedRoles.length === 0) return true
  return allowedRoles.some((role) => roles.includes(role))
}
