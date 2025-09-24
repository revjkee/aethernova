import React, { useEffect, useMemo, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useSLAStore } from '@/state/sla'
import { useWebSocket } from '@/shared/hooks/useSocket'
import { AnimatePresence, motion } from 'framer-motion'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/shared/hooks/useThemeSwitcher'
import { Gauge } from '@/components/ui/gauge'

const getColorForCompliance = (value: number): string => {
  if (value >= 99.9) return 'text-green-600'
  if (value >= 98.0) return 'text-yellow-500'
  if (value >= 95.0) return 'text-orange-500'
  return 'text-red-600'
}

const getLabelForCompliance = (value: number): string => {
  if (value >= 99.9) return 'Идеально'
  if (value >= 98.0) return 'Хорошо'
  if (value >= 95.0) return 'Удовлетворительно'
  return 'Нарушение SLA'
}

const animationVariants = {
  hidden: { opacity: 0, scale: 0.95 },
  visible: { opacity: 1, scale: 1 },
}

export const SLAComplianceGauge = () => {
  const { theme } = useTheme()
  const [loading, setLoading] = useState(true)
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)

  const {
    currentSLA,
    fetchSLACompliance,
    updateCompliance,
  } = useSLAStore()

  const socket = useWebSocket('/ws/sla', {
    onMessage: (msg) => {
      const payload = JSON.parse(msg)
      if (typeof payload?.value === 'number') {
        updateCompliance(payload.value)
        setLastUpdate(new Date())
      }
    },
    reconnectInterval: 12000,
  })

  useEffect(() => {
    fetchSLACompliance().finally(() => setLoading(false))
    return () => socket.disconnect()
  }, [])

  const displayValue = useMemo(() => {
    return typeof currentSLA === 'number' ? currentSLA.toFixed(2) : '–'
  }, [currentSLA])

  const color = useMemo(() => getColorForCompliance(currentSLA), [currentSLA])
  const label = useMemo(() => getLabelForCompliance(currentSLA), [currentSLA])

  return (
    <Card className="h-full shadow-lg flex flex-col justify-between">
      <CardContent className="flex flex-col items-center justify-center p-6 h-full">
        {loading ? (
          <Skeleton className="w-48 h-48 rounded-full" />
        ) : (
          <AnimatePresence>
            <motion.div
              key={displayValue}
              variants={animationVariants}
              initial="hidden"
              animate="visible"
              exit="hidden"
              transition={{ duration: 0.3 }}
              className="relative flex flex-col items-center"
            >
              <Gauge
                value={currentSLA}
                max={100}
                size={220}
                strokeWidth={18}
                colorClass={color}
                backgroundClass="bg-muted"
                animate
              />
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-[55%] text-center">
                <div className={cn('text-4xl font-bold', color)}>
                  {displayValue}%
                </div>
                <div className="text-sm text-muted-foreground mt-1">
                  {label}
                </div>
                {lastUpdate && (
                  <div className="text-[11px] text-muted-foreground mt-2">
                    Обновлено: {lastUpdate.toLocaleTimeString()}
                  </div>
                )}
              </div>
            </motion.div>
          </AnimatePresence>
        )}
      </CardContent>
    </Card>
  )
}

export default SLAComplianceGauge
