import React, { useState, useEffect, useCallback } from 'react'
import { Switch } from '@/components/ui/switch'
import { usePrivacySettings } from '@/services/privacy/usePrivacySettings'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { motion } from 'framer-motion'
import { Lock, LockOpen, ShieldCheck, AlertTriangle, EyeOff } from 'lucide-react'
import { useAuditTrail } from '@/services/logging/useAuditTrail'
import { cn } from '@/shared/utils/classNames'
import { toast } from '@/components/ui/use-toast'
import { Card, CardHeader, CardContent, CardTitle } from '@/components/ui/card'

export const PrivacySandboxToggle: React.FC = () => {
  const { sandboxEnabled, toggleSandbox, isLoading, lastUpdated } = usePrivacySettings()
  const { logEvent } = useAuditTrail()
  const [internalState, setInternalState] = useState<boolean>(sandboxEnabled ?? false)
  const [transitioning, setTransitioning] = useState<boolean>(false)

  useEffect(() => {
    if (sandboxEnabled !== undefined) {
      setInternalState(sandboxEnabled)
    }
  }, [sandboxEnabled])

  const handleToggle = useCallback(async () => {
    try {
      setTransitioning(true)
      const newValue = !internalState
      await toggleSandbox(newValue)
      await logEvent({
        action: newValue ? 'SANDBOX_ENABLED' : 'SANDBOX_DISABLED',
        context: 'UI_PRIVACY_SANDBOX',
        metadata: { from: internalState, to: newValue }
      })
      toast({
        title: 'Приватная песочница обновлена',
        description: newValue
          ? 'Изолированный режим активирован.'
          : 'Изолированный режим отключён.'
      })
      setInternalState(newValue)
    } catch (e) {
      toast({
        title: 'Ошибка переключения режима',
        description: 'Не удалось изменить состояние песочницы.',
        variant: 'destructive'
      })
    } finally {
      setTransitioning(false)
    }
  }, [internalState, toggleSandbox, logEvent])

  return (
    <motion.div
      className="w-full"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <Card className="bg-muted/30 border border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg font-semibold">
            <ShieldCheck className="w-5 h-5 text-green-600" />
            Режим изолированной песочницы
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div className="flex flex-col">
              <span className="text-sm text-muted-foreground font-medium">
                Защитный режим запуска
              </span>
              <span className="text-xs text-muted-foreground">
                Исключает все внешние вызовы, включая аналитику, WebRTC, сокеты.
              </span>
            </div>
            <TooltipProvider delayDuration={200}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Switch
                    disabled={isLoading || transitioning}
                    checked={internalState}
                    onCheckedChange={handleToggle}
                    className={cn(
                      'data-[state=checked]:bg-green-600',
                      'data-[state=unchecked]:bg-gray-300'
                    )}
                  />
                </TooltipTrigger>
                <TooltipContent side="top" align="center">
                  {internalState ? 'Песочница активна' : 'Песочница отключена'}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>

          {internalState && (
            <Alert variant="default" className="bg-green-50 border-green-400">
              <Lock className="w-5 h-5 text-green-600" />
              <AlertTitle className="text-green-800 font-semibold">
                Изолированный режим активен
              </AlertTitle>
              <AlertDescription className="text-green-700 text-sm">
                Все внешние соединения отключены. Внутренние модули работают в sandbox-контексте.
              </AlertDescription>
            </Alert>
          )}

          {!internalState && (
            <Alert variant="warning" className="bg-yellow-50 border-yellow-400">
              <AlertTriangle className="w-5 h-5 text-yellow-600" />
              <AlertTitle className="text-yellow-800 font-semibold">
                Песочница отключена
              </AlertTitle>
              <AlertDescription className="text-yellow-700 text-sm">
                Ваши действия могут быть отслежены внешними сервисами. Рекомендуется активировать песочницу.
              </AlertDescription>
            </Alert>
          )}

          <div className="text-right text-xs text-muted-foreground font-mono">
            Последнее изменение: {lastUpdated ? new Date(lastUpdated).toLocaleString() : '—'}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  )
}

export default PrivacySandboxToggle
