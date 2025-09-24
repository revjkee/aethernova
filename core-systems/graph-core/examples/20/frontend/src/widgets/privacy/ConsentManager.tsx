import React, { useState, useEffect, useCallback } from 'react'
import { Switch } from '@/components/ui/switch'
import { Button } from '@/components/ui/button'
import { useUserConsentStore } from '@/store/privacy/consentStore'
import { useToast } from '@/shared/hooks/useToast'
import { cn } from '@/shared/utils/classNames'
import { ShieldCheck, Settings2 } from 'lucide-react'
import { motion } from 'framer-motion'

interface ConsentManagerProps {
  className?: string
  compact?: boolean
}

interface ConsentItem {
  id: string
  label: string
  description: string
  required?: boolean
  defaultValue?: boolean
}

const DEFAULT_CONSENTS: ConsentItem[] = [
  {
    id: 'essential',
    label: 'Базовая функциональность',
    description: 'Необходимые файлы cookie и разрешения для работы платформы.',
    required: true,
    defaultValue: true,
  },
  {
    id: 'analytics',
    label: 'Аналитика и производительность',
    description: 'Сбор анонимных метрик использования для улучшения системы.',
  },
  {
    id: 'ai-personalization',
    label: 'ИИ-персонализация',
    description: 'Разрешение использовать ваши действия для улучшения рекомендаций.',
  },
  {
    id: 'data-sharing',
    label: 'Обмен данными с партнерами',
    description: 'Разрешение передавать обезличенные данные в рамках соглашений.',
  },
]

export const ConsentManager: React.FC<ConsentManagerProps> = ({
  className,
  compact = false,
}) => {
  const { toast } = useToast()
  const {
    consents,
    updateConsent,
    resetConsents,
    saveConsents,
    loadInitialConsents,
  } = useUserConsentStore()

  const [localConsents, setLocalConsents] = useState<Record<string, boolean>>({})

  useEffect(() => {
    loadInitialConsents()
    setLocalConsents(consents)
  }, [consents, loadInitialConsents])

  const handleChange = useCallback((id: string, value: boolean) => {
    setLocalConsents(prev => ({ ...prev, [id]: value }))
  }, [])

  const handleSave = useCallback(() => {
    saveConsents(localConsents)
    toast.success('Настройки согласий успешно сохранены.')
  }, [localConsents, saveConsents, toast])

  const handleReset = useCallback(() => {
    resetConsents()
    toast.info('Согласия сброшены до значений по умолчанию.')
  }, [resetConsents, toast])

  return (
    <motion.div
      className={cn('w-full rounded-xl border p-6 shadow-md bg-white dark:bg-neutral-900', className)}
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="flex items-center gap-3 mb-4">
        <ShieldCheck className="h-6 w-6 text-primary" />
        <h2 className="text-lg font-bold">Управление пользовательскими согласиями</h2>
      </div>
      <div className="space-y-4">
        {DEFAULT_CONSENTS.map(({ id, label, description, required }) => (
          <div
            key={id}
            className="flex items-start justify-between border-b pb-3 last:border-b-0 last:pb-0"
          >
            <div className="flex flex-col">
              <span className="font-semibold">{label}</span>
              <span className="text-sm text-muted-foreground">{description}</span>
            </div>
            <Switch
              checked={localConsents[id] ?? false}
              onCheckedChange={(v) => handleChange(id, v)}
              disabled={required}
            />
          </div>
        ))}
      </div>

      {!compact && (
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="ghost" onClick={handleReset}>
            Сбросить
          </Button>
          <Button variant="default" onClick={handleSave}>
            Сохранить
          </Button>
        </div>
      )}
    </motion.div>
  )
}

export default ConsentManager
