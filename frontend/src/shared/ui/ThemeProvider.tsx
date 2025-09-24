import React, { createContext, useContext, useState, ReactNode } from 'react'

type Theme = 'light' | 'dark'

type ThemeContextValue = {
  currentTheme: Theme
  setTheme: (t: Theme) => void
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined)

export const ThemeProvider: React.FC<{ children?: ReactNode }> = ({ children }) => {
  const [currentTheme, setCurrentTheme] = useState<Theme>('light')

  return <ThemeContext.Provider value={{ currentTheme, setTheme: setCurrentTheme }}>{children}</ThemeContext.Provider>
}

export const useThemeContext = (): ThemeContextValue => {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useThemeContext must be used within ThemeProvider')
  return ctx
}

export default ThemeProvider

