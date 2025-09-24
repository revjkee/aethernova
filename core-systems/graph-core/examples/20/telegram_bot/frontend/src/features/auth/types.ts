export interface User {
  id: number;
  username: string;
  email: string;
  avatarUrl?: string;
  roles: string[];
}

export interface LoginPayload {
  username: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  error: string | null;
}
