// entities/user/user.model.ts

export interface User {
  id: string;
  username: string;
  email: string;
  roles: UserRole[];
  isActive: boolean;
  createdAt: string;  // ISO date string
  updatedAt: string;  // ISO date string
}

export type UserRole = 'admin' | 'user' | 'moderator';

// Дополнительные утилиты для работы с пользователем:
export const isAdmin = (user: User): boolean => user.roles.includes('admin');

export const createEmptyUser = (): User => ({
  id: '',
  username: '',
  email: '',
  roles: ['user'],
  isActive: true,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
});
