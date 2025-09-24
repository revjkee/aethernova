import { useState, useEffect } from 'react';
import * as authAPI from '../services/authAPI';

export const useAuth = () => {
  const [user, setUser] = useState<AuthResponse['user'] | null>(null);

  const login = async (email: string, password: string) => {
    const data = await authAPI.login({ email, password });
    setUser(data.user);
    localStorage.setItem('accessToken', data.accessToken);
  };

  const logout = async () => {
    await authAPI.logout();
    setUser(null);
    localStorage.removeItem('accessToken');
  };

  useEffect(() => {
    // Логика для проверки и обновления токенов
  }, []);

  return { user, login, logout };
};
