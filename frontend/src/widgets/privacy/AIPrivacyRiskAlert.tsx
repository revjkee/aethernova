import React, { useMemo } from 'react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { usePrivacyRiskAssessment } from '@/hooks/privacy/usePrivacyRiskAssessment'
import { LockWarning, AlertTriangle, ShieldX, Info } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'
import { useTheme } from '@/hooks/theme/useTheme'

type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

interface AIPrivacyRiskAlertProps {
  className?: string
  compact?: boolean
}

const riskColorMap: Record<RiskLevel, string> = {
  low: 'border-green-600 bg-green-100 text-green-800',
  medium: 'border-yellow-600 bg-yellow-100 text-yellow-900',
  high: 'border-orange-600 bg-orange-100 text-orange-900',
  critical: 'border-red-600 bg-red-100 text-red-900',
}

const riskIconMap: Record<RiskLevel, JSX.Element> = {
  low: <Info className="h-5 w-5" />,
  medium: <AlertTriangle className="h-5 w-5" />,
  high: <LockWarning className="h-5 w-5" />,
  critical: <ShieldX className="h-5 w-5" />,
}

const riskTitleMap: Record<RiskLevel, string> = {
  low: 'Низкий риск утечки',
  medium: 'Средний риск конфиденциальности',
  high: 'Высокий риск ИИ-утечки',
  critical: 'Критический риск: утечка данных возможна',
}

export const AIPrivacyRiskAlert: React.FC<AIPrivacyRiskAlertProps> = ({
  className,
  compact = false,
}) => {
  const { theme } = useTheme()
  const { currentRisk, mitigationTips, affectedModules } = usePrivacyRiskAssessment()

  const riskClass = useMemo(() => cn(
    'border-l-4 rounded-lg p-4 shadow-sm transition-all duration-300',
    riskColorMap[currentRisk],
    className
  ), [currentRisk, className])

  const riskIcon = riskIconMap[currentRisk]
  const title = riskTitleMap[currentRisk]

  if (currentRisk === 'low') return null

  return (
    <Alert className={riskClass}>
      <div className="flex items-start gap-3">
        <div className="mt-1">{riskIcon}</div>
        <div className="flex flex-col gap-1">
          <AlertTitle className="text-base font-bold">{title}</AlertTitle>
          {!compact && (
            <AlertDescription className="text-sm leading-relaxed">
              <p>Обнаружены потенциальные уязвимости в работе ИИ:</p>
              <ul className="list-disc list-inside mt-1">
                {affectedModules.map((mod, idx) => (
                  <li key={idx}>{mod}</li>
                ))}
              </ul>
              {mitigationTips.length > 0 && (
                <div className="mt-2">
                  <p className="font-semibold">Рекомендуемые действия:</p>
                  <ul className="list-disc list-inside">
                    {mitigationTips.map((tip, i) => (
                      <li key={i}>{tip}</li>
                    ))}
                  </ul>
                </div>
              )}
            </AlertDescription>
          )}
        </div>
      </div>
    </Alert>
  )
}

export default AIPrivacyRiskAlert
