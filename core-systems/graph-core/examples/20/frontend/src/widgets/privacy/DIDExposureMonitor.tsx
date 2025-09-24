import React, { useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { ExposureRiskChart } from './charts/ExposureRiskChart'
import { useDIDActivityLog } from '@/services/identity/useDIDActivityLog'
import { useTrustZone } from '@/shared/hooks/useTrustZone'
import { useExposureAnalysis } from '@/shared/hooks/useExposureAnalysis'
import { ShieldAlert, EyeOff, KeyRound, Satellite } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'
import { Badge } from '@/components/ui/badge'
import { motion } from 'framer-motion'

export const DIDExposureMonitor: React.FC = () => {
  const [did, setDID] = useState<string | null>(null)
  const { logs, fetchLogs } = useDIDActivityLog()
  const { riskLevel, trustZones, exposureVector, anomalyScore } = useExposureAnalysis(logs)
  const { currentZone } = useTrustZone()

  useEffect(() => {
    void fetchLogs()
  }, [])

  useEffect(() => {
    if (logs.length > 0) {
      setDID(logs[0].did)
    }
  }, [logs])

  return (
    <motion.div
      className="w-full space-y-6"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <Card className="bg-muted/40 border border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg font-semibold">
            <Satellite className="w-5 h-5 text-blue-600" />
            Мониторинг публичной активности DID
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {did ? (
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <div className="text-sm text-muted-foreground font-mono truncate">
                  DID: {did}
                </div>
                <Badge variant="secondary">Зона: {currentZone}</Badge>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <span className="text-sm text-muted-foreground">Риск экспозиции</span>
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-warning" />
                    <span className={cn(
                      'font-medium',
                      riskLevel === 'HIGH' && 'text-red-500',
                      riskLevel === 'MEDIUM' && 'text-yellow-500',
                      riskLevel === 'LOW' && 'text-green-600'
                    )}>
                      {riskLevel}
                    </span>
                  </div>
                </div>
                <div className="space-y-2">
                  <span className="text-sm text-muted-foreground">Аномалия поведения</span>
                  <div className="text-xs font-mono text-muted-foreground">
                    {anomalyScore.toFixed(2)} / 1.0
                  </div>
                </div>
              </div>
              <div>
                <ExposureRiskChart data={exposureVector} />
              </div>
            </div>
          ) : (
            <Alert variant="warning">
              <EyeOff className="h-5 w-5" />
              <AlertTitle>Активность DID не обнаружена</AlertTitle>
              <AlertDescription>
                Нет публичных действий, связанных с текущей идентичностью.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </motion.div>
  )
}

export default DIDExposureMonitor
