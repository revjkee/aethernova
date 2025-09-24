// src/app/router/footer.tsx
import { Home, ShoppingBag, Star, User } from 'lucide-react'
import { useLocation, useNavigate } from 'react-router-dom'
import { cn } from '@/shared/utils/classNames'

const routes = [
  { icon: <Home size={20} />, path: '/', label: 'Главная' },
  { icon: <ShoppingBag size={20} />, path: '/products', label: 'Товары' },
  { icon: <Star size={20} />, path: '/reviews', label: 'Отзывы' },
  { icon: <User size={20} />, path: '/profile', label: 'Профиль' }
]

export const Footer = () => {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <footer className="fixed bottom-0 left-0 w-full bg-white dark:bg-[#1c1c1e] border-t dark:border-gray-700 z-50">
      <div className="flex justify-around items-center h-14">
        {routes.map(({ icon, path, label }) => (
          <button
            key={path}
            onClick={() => navigate(path)}
            className="flex flex-col items-center justify-center"
          >
            <span
              className={cn(
                'transition-colors',
                location.pathname === path
                  ? 'text-blue-600'
                  : 'text-gray-500 dark:text-gray-300'
              )}
            >
              {icon}
            </span>
            <span className="text-xs mt-1">{label}</span>
          </button>
        ))}
      </div>
    </footer>
  )
}
