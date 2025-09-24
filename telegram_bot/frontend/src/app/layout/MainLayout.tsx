// src/app/layout/MainLayout.tsx
import { ReactNode, useEffect } from 'react'
import { useTelegram } from '@/telegram/useTelegram'
import { useWebAppTheme } from '@/telegram/useWebAppTheme'
import { cn } from '@/shared/utils/classNames'

interface MainLayoutProps {
  children: ReactNode
}

export const MainLayout = ({ children }: MainLayoutProps) => {
  const { WebApp } = useTelegram()
  const theme = useWebAppTheme()

  useEffect(() => {
    WebApp.ready()
    WebApp.expand()
  }, [WebApp])

  return (
    <div
      className={cn(
        'min-h-screen flex flex-col items-stretch bg-white text-black',
        theme === 'dark' && 'bg-[#1c1c1e] text-white',
        'transition-colors duration-300 ease-in-out'
      )}
    >
      <header className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h1 className="text-xl font-semibold">TapTrade</h1>
      </header>

      <main className="flex-1 p-4 overflow-y-auto">
        {children}
      </main>

      <footer className="p-4 border-t border-gray-200 dark:border-gray-700 text-sm text-center">
        &copy; {new Date().getFullYear()} TapTrade
      </footer>
    </div>
  )
}

export default MainLayout
