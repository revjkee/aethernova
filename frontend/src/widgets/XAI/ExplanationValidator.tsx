import React, { useState, useEffect } from 'react'
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert'
import { Switch } from '@/components/ui/switch'
import { Button } from '@/components/ui/button'
import { Loader, ShieldCheck, XCircle, Eye } from 'lucide-react'
import clsx from 'clsx'

type ExplanationRule = {
  id: string
  title: string
  description: string
  severity: 'info' | 'warning' | 'critical'
  validate: (explanation: string) => boolean
  zkVerified?: boolean
}

interface ExplanationValidatorProps {
  explanation: string
  rules: ExplanationRule[]
  zkEnabled?: boolean
  onPass?: () => void
  onFail?: (failedRules: ExplanationRule[]) => void
}

export const ExplanationValidator: React.FC<ExplanationValidatorProps> = ({
  explanation,
  rules,
  zkEnabled = true,
  onPass,
  onFail
}) => {
  const [checked, setChecked] = useState(false)
  const [loading, setLoading] = useState(false)
  const [failedRules, setFailedRules] = useState<ExplanationRule[]>([])
  const [passed, setPassed] = useState<boolean | null>(null)

  useEffect(() => {
    setPassed(null)
    setFailedRules([])
    setChecked(false)
  }, [explanation])

  const runValidation = async () => {
    setLoading(true)
    await new Promise((r) => setTimeout(r, 500)) // simulate latency

    const failed = rules.filter((rule) => !rule.validate(explanation))
    setFailedRules(failed)
    setPassed(failed.length === 0)

    if (failed.length === 0) onPass?.()
    else onFail?.(failed)

    setChecked(true)
    setLoading(false)
  }

  const badgeBySeverity = (severity: ExplanationRule['severity']) => {
    switch (severity) {
      case 'info': return <Badge variant="outline">Info</Badge>
      case 'warning': return <Badge variant="warning">Warning</Badge>
      case 'critical': return <Badge variant="destructive">Critical</Badge>
    }
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>Валидация XAI объяснения</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">Включить ZK-подтверждение</span>
          <Switch checked={zkEnabled} disabled />
        </div>

        <Button onClick={runValidation} disabled={loading || checked} className="w-full">
          {loading ? <Loader className="animate-spin" /> : 'Проверить'}
        </Button>

        {checked && passed !== null && (
          <Alert variant={passed ? 'success' : 'destructive'}>
            <AlertTitle className="flex items-center gap-2">
              {passed ? <ShieldCheck className="text-green-500" /> : <XCircle className="text-red-500" />}
              {passed ? 'Проверка пройдена' : 'Нарушения обнаружены'}
            </AlertTitle>
            <AlertDescription>
              {passed
                ? 'Объяснение соответствует всем установленным правилам.'
                : `Обнаружено ${failedRules.length} нарушений.`}
            </AlertDescription>
          </Alert>
        )}

        {failedRules.length > 0 && (
          <div className="space-y-2">
            {failedRules.map((rule) => (
              <div
                key={rule.id}
                className={clsx(
                  'border p-3 rounded-md text-sm',
                  rule.severity === 'critical' && 'border-red-500 bg-red-50',
                  rule.severity === 'warning' && 'border-yellow-500 bg-yellow-50',
                  rule.severity === 'info' && 'border-gray-300 bg-gray-50'
                )}
              >
                <div className="flex justify-between">
                  <span className="font-medium">{rule.title}</span>
                  {badgeBySeverity(rule.severity)}
                </div>
                <div className="text-muted-foreground">{rule.description}</div>
                {zkEnabled && rule.zkVerified && (
                  <span className="text-xs text-blue-500 mt-1 block">ZK-подтверждено</span>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
      <CardFooter className="text-xs text-muted-foreground">
        Все проверки производятся локально. Ни один фрагмент объяснения не покидает систему.
      </CardFooter>
    </Card>
  )
}
