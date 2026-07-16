export interface AuthState {
  user: null
  isAuthenticated: boolean
  roles: string[]
}

export function useAuth(): AuthState {
  return { user: null, isAuthenticated: false, roles: [] }
}
