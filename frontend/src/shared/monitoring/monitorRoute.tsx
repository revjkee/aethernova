import { useEffect, type ReactElement } from 'react'

interface MonitoredRouteProps {
  children: ReactElement
  routeName: string
}

const MonitoredRoute = ({ children, routeName }: MonitoredRouteProps) => {
  useEffect(() => {
    performance.mark(`route:${routeName}:mounted`)
  }, [routeName])

  return children
}

export const monitorRoute = (element: ReactElement, routeName: string): ReactElement => (
  <MonitoredRoute routeName={routeName}>{element}</MonitoredRoute>
)
