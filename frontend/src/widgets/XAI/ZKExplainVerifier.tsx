// src/widgets/XAI/ZKExplainVerifier.tsx

import React, { useEffect, useState, useCallback } from 'react'
import { Panel } from '@/shared/ui/Panel'
import { zkVerifyExplanation } from '@/services/zk/zkVerifierService'
import { ExplanationPayload } from '@/types/xai/ExplanationTypes'
import { ZKProofBadge } from './ZKProofBadge'
import { Alert } from '@/shared/ui/Alert'
import { Spinner } from '@/shared/ui/Spinner'
import { useXAIContext } from '@/shared/context/XAIContext'
import './ZKExplainVerifier.css'

interface Props {
  explanation: ExplanationPayload
  onVerified?: (result: boolean) => void
}

export const ZKExplainVerifier: React.FC<Props> = ({ explanation, onVerified }) => {
  const [loading, setLoading] = useState(false)
  const [verified, setVerified] = useState<boolean | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { selectedModel } = useXAIContext()

  const verifyProof = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await zkVerifyExplanation({
        modelId: selectedModel?.id || '',
        explanation,
      })
      setVerified(response.isValid)
      onVerified?.(response.isValid)
    } catch (err) {
      setError('Ошибка при верификации ZK-доказательства.')
      setVerified(null)
    } finally {
      setLoading(false)
    }
  }, [explanation, selectedModel, onVerified])

  useEffect(() => {
    if (explanation && selectedModel) {
      verifyProof()
    }
  }, [verifyProof, explanation, selectedModel])

  return (
    <Panel title="Zero-Knowledge Proof Verifier (ZK-XAI)">
      <div className="zk-verifier-container">
        {loading && <Spinner label="Проверка ZK-доказательства..." />}
        {error && <Alert type="error">{error}</Alert>}

        {!loading && verified !== null && (
          <ZKProofBadge verified={verified} />
        )}

        {!loading && verified === false && (
          <Alert type="warning">Объяснение не подтверждено ZK-доказательством.</Alert>
        )}
        {!loading && verified === true && (
          <Alert type="success">Объяснение подтверждено: доказуемо корректно.</Alert>
        )}
      </div>
    </Panel>
  )
}
