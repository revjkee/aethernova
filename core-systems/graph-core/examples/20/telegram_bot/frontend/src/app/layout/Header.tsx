// src/app/router/header.tsx
import { useTelegram } from '@/telegram/useTelegram'
import { useLocation, useNavigate } from 'react-router-dom'
import { cn } from '@/shared/utils/classNames'

const routes = [
  { name: 'Главная', path: '/' },
  { name: 'Товары', path: '/products' },
  { name: 'Отзывы', path: '/reviews' },
  { name: 'Профиль', path: '/profile' }
]

export const Header = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const { WebApp } = useTelegram()

  return (
    <nav className="w-full flex items-center justify-between px-4 py-2 bg-white dark:bg-[#1c1c1e] border-b dark:border-gray-700 shadow-sm">
      <div className="text-lg font-bold text-black dark:text-white">
        TapTrade
      </div>
      <div className="flex gap-3">
        {routes.map(({ name, path }) => (
          <button
            key={path}
            onClick={() => navigate(path)}
            className={cn(
              'text-sm font-medium',
              location.pathname === path
                ? 'text-blue-600 underline underline-offset-4'
                : 'text-gray-600 dark:text-gray-300'
            )}
          >
            {name}
          </button>
        ))}
      </div>
    </nav>
  )
}
