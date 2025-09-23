import React, { useState } from 'react'
import { cn } from '@/shared/utils/classNames'
import { useRouter } from 'next/router'
import {
  Home,
  Search,
  ShoppingCart,
  User,
  Settings,
  Bell,
  Menu,
} from 'lucide-react'
import { motion } from 'framer-motion'
import { useMarketplaceContext } from '@/context/MarketplaceContext'
import { useUnreadNotifications } from '@/hooks/notifications/useUnreadNotifications'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'

type ToolbarTab = 'home' | 'search' | 'cart' | 'profile' | 'menu'

export const MobileMarketplaceToolbar: React.FC = () => {
  const router = useRouter()
  const { cartItemsCount } = useMarketplaceContext()
  const { unreadCount } = useUnreadNotifications()
  const [activeTab, setActiveTab] = useState<ToolbarTab>('home')

  const navigate = (tab: ToolbarTab, path: string) => {
    setActiveTab(tab)
    router.push(path)
  }

  const iconProps = 'w-5 h-5'

  return (
    <motion.nav
      className="fixed z-50 bottom-0 left-0 right-0 border-t border-border bg-background flex justify-between items-center h-16 px-4 shadow-sm"
      initial={{ y: 100 }}
      animate={{ y: 0 }}
      transition={{ type: 'spring', stiffness: 300, damping: 25 }}
    >
      <TabButton
        label="Главная"
        icon={<Home className={iconProps} />}
        active={activeTab === 'home'}
        onClick={() => navigate('home', '/')}
      />

      <TabButton
        label="Поиск"
        icon={<Search className={iconProps} />}
        active={activeTab === 'search'}
        onClick={() => navigate('search', '/search')}
      />

      <TabButton
        label="Корзина"
        icon={<ShoppingCart className={iconProps} />}
        badge={cartItemsCount}
        active={activeTab === 'cart'}
        onClick={() => navigate('cart', '/cart')}
      />

      <TabButton
        label="Профиль"
        icon={<User className={iconProps} />}
        active={activeTab === 'profile'}
        onClick={() => navigate('profile', '/profile')}
      />

      <Sheet>
        <SheetTrigger asChild>
          <TabButton
            label="Меню"
            icon={<Menu className={iconProps} />}
            badge={unreadCount}
            active={activeTab === 'menu'}
            onClick={() => setActiveTab('menu')}
          />
        </SheetTrigger>
        <SheetContent side="bottom" className="p-4">
          <div className="flex flex-col gap-3">
            <Button
              variant="ghost"
              className="w-full justify-start"
              onClick={() => router.push('/notifications')}
            >
              <Bell className="w-4 h-4 mr-2" /> Уведомления
            </Button>
            <Button
              variant="ghost"
              className="w-full justify-start"
              onClick={() => router.push('/settings')}
            >
              <Settings className="w-4 h-4 mr-2" /> Настройки
            </Button>
          </div>
        </SheetContent>
      </Sheet>
    </motion.nav>
  )
}

type TabButtonProps = {
  label: string
  icon: React.ReactNode
  badge?: number
  active: boolean
  onClick: () => void
}

const TabButton: React.FC<TabButtonProps> = ({ label, icon, badge, active, onClick }) => {
  return (
    <button
      className={cn(
        'relative flex flex-col items-center justify-center text-xs transition-all',
        active ? 'text-primary' : 'text-muted-foreground'
      )}
      onClick={onClick}
      aria-label={label}
    >
      {icon}
      {badge && badge > 0 && (
        <span className="absolute top-0 right-0 bg-red-600 text-white rounded-full text-[10px] px-1 leading-none">
          {badge > 99 ? '99+' : badge}
        </span>
      )}
      <span className="mt-0.5">{label}</span>
    </button>
  )
}

export default MobileMarketplaceToolbar
