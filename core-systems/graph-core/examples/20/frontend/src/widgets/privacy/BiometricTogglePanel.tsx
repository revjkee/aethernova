import React, { useEffect, useState } from 'react'
import { Fingerprint, Lock, ShieldX, Check, Loader2 } from 'lucide-react'
import { useBiometricStore } from '@/store/privacy/biometricStore'
import { Switch } from '@/components/ui/switch'
import { Tooltip } from '@/components/ui/tooltip'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { motion } from 'framer-motion'
import { toast } from '@/shared/hooks/useToast'
import { BiometricStatus } from '@/types/privacy'
import { cn } from '@/shared/utils/classNames'

interface BiometricTogglePanelProps {
  className?: string
}

export const BiometricTogglePanel: React.FC<BiometricTogglePanelProps> = ({ className }) => {
  const {
    biometricEnabled,
    status,
    toggleBiometrics,
    deviceSupport,
    consentGiven,
    updateConsent,
    fingerprintHash,
    loading,
  } = useBiometricStore()

  const [localToggle, setLocalToggle] = useState(biometricEnabled)

  useEffect(() => {
    setLocalToggle(biometricEnabled)
  }, [biometricEnabled])

  const handleToggle = async (enabled: boolean) => {
    setLocalToggle(enabled)
    try {
      await toggleBiometrics(enabled)
      toast({
        title: enabled ? 'Биометрия включена' : 'Биометрия отключена',
        description: `Fingerprint Hash: ${fingerprintHash?.slice(0, 16)}...`,
      })
    } catch (err) {
      toast({
        title: 'Ошибка при переключении',
        description: (err as Error)?.message || 'Неизвестная ошибка',
        variant: 'destructive',
      })
      setLocalToggle(!enabled)
    }
  }

  return (
    <motion.div
      className={cn(
        'rounded-xl border bg-white dark:bg-neutral-900 shadow-lg p-6 space-y-5',
        className
      )}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center gap-4">
        <Fingerprint className="w-8 h-8 text-blue-600 dark:text-blue-400" />
        <div className="flex flex-col">
          <span className="text-lg font-semibold">Биометрическая аутентификация</span>
          <span className="text-sm text-muted-foreground">
            Использует WebAuthn / ZK-Biometric pipeline для повышения безопасности
          </span>
        </div>
        <div className="ml-auto">
          <Switch
            checked={localToggle}
            onCheckedChange={handleToggle}
            disabled={!deviceSupport || loading}
          />
        </div>
      </div>

      {!deviceSupport && (
        <Alert variant="warning">
          <ShieldX className="h-4 w-4" />
          <AlertTitle>Устройство не поддерживает биометрию</AlertTitle>
          <AlertDescription>
            Включение невозможно. Необходимо устройство с поддержкой WebAuthn.
          </AlertDescription>
        </Alert>
      )}

      {status === BiometricStatus.Unverified && (
        <Alert variant="info">
          <Lock className="h-4 w-4" />
          <AlertTitle>Сессия не подтверждена</AlertTitle>
          <AlertDescription>
            Биометрическая проверка не пройдена. Обновите fingerprint.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">Текущий статус</span>
          <div className="flex items-center gap-2">
            {loading ? (
              <Loader2 className="animate-spin w-4 h-4" />
            ) : biometricEnabled ? (
              <Check className="w-4 h-4 text-green-500" />
            ) : (
              <ShieldX className="w-4 h-4 text-red-500" />
            )}
            {status}
          </div>
        </div>
        <div>
          <span className="text-muted-foreground">Hash отпечатка</span>
          <div className="font-mono text-xs truncate">{fingerprintHash || '—'}</div>
        </div>
      </div>

      <div className="flex items-center gap-2 pt-2">
        <input
          id="consent"
          type="checkbox"
          checked={consentGiven}
          onChange={(e) => updateConsent(e.target.checked)}
          className="accent-blue-600 w-4 h-4"
        />
        <label htmlFor="consent" className="text-sm text-muted-foreground">
          Даю согласие на биометрическую обработку (ZK-анонимизация включена)
        </label>
      </div>
    </motion.div>
  )
}

export default BiometricTogglePanel
