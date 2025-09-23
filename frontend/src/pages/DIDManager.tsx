// src/pages/DIDManager.tsx

import React, { useEffect, useState, useCallback } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { useDID } from "@/features/auth/hooks/useDID"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { DIDCard } from "@/widgets/Identity/DIDCard"
import { DIDIssuer } from "@/widgets/Identity/DIDIssuer"
import { CredentialList } from "@/widgets/Identity/CredentialList"
import { VCVerifier } from "@/widgets/Identity/VCVerifier"
import { DIDActivityLog } from "@/widgets/Identity/DIDActivityLog"
import { useNotification } from "@/shared/hooks/useNotification"
import { motion } from "framer-motion"
import { Spinner } from "@/shared/ui/Spinner"
import { Divider } from "@/shared/ui/Divider"
import { Button } from "@/shared/ui/Button"

export const DIDManager: React.FC = () => {
  const { t } = useTranslation()
  const notify = useNotification()
  const {
    did,
    fetchDID,
    credentials,
    issueVC,
    revokeVC,
    verifyVC,
    activityLog,
    fetchActivity,
    loading,
    resetDID,
    generateNewDID
  } = useDID()

  const [selectedVC, setSelectedVC] = useState<string | null>(null)
  const [showVerification, setShowVerification] = useState(false)

  useEffect(() => {
    fetchDID()
    fetchActivity()
  }, [fetchDID, fetchActivity])

  const handleIssueVC = useCallback(
    async (payload: Record<string, any>) => {
      try {
        await issueVC(payload)
        notify.success(t("did.issue_success"))
        fetchActivity()
      } catch {
        notify.error(t("did.issue_error"))
      }
    },
    [issueVC, notify, fetchActivity, t]
  )

  const handleRevokeVC = useCallback(
    async (vcId: string) => {
      try {
        await revokeVC(vcId)
        notify.success(t("did.revoke_success"))
        fetchActivity()
      } catch {
        notify.error(t("did.revoke_error"))
      }
    },
    [revokeVC, notify, fetchActivity, t]
  )

  const handleVerifyVC = useCallback(
    async (vcJwt: string) => {
      try {
        const result = await verifyVC(vcJwt)
        if (result.verified) {
          notify.success(t("did.verified"))
        } else {
          notify.error(t("did.not_verified"))
        }
      } catch {
        notify.error(t("did.verify_error"))
      }
    },
    [verifyVC, notify, t]
  )

  const handleReset = useCallback(() => {
    resetDID()
    fetchDID()
    fetchActivity()
  }, [resetDID, fetchDID, fetchActivity])

  const handleGenerate = useCallback(() => {
    generateNewDID()
    fetchDID()
    fetchActivity()
  }, [generateNewDID, fetchDID, fetchActivity])

  return (
    <>
      <Helmet>
        <title>{t("did.title")}</title>
        <meta name="description" content={t("did.meta")} />
      </Helmet>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3 }}
      >
        <Container>
          <PageHeader
            title={t("did.header")}
            subtitle={t("did.subheader")}
            actions={[
              {
                label: t("did.reset"),
                onClick: handleReset
              },
              {
                label: t("did.generate"),
                onClick: handleGenerate
              }
            ]}
          />

          {loading ? (
            <div className="flex justify-center my-10">
              <Spinner />
            </div>
          ) : (
            <>
              <DIDCard did={did} />

              <Divider label={t("did.issuer")} />
              <DIDIssuer onIssue={handleIssueVC} />

              <Divider label={t("did.credentials")} />
              <CredentialList
                credentials={credentials}
                onRevoke={handleRevokeVC}
                onSelect={setSelectedVC}
                onVerify={setShowVerification}
              />

              {showVerification && selectedVC && (
                <VCVerifier
                  vcId={selectedVC}
                  onVerify={handleVerifyVC}
                  onClose={() => setShowVerification(false)}
                />
              )}

              <Divider label={t("did.activity")} />
              <DIDActivityLog logs={activityLog} />
            </>
          )}
        </Container>
      </motion.div>
    </>
  )
}

export default DIDManager
