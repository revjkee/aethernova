// src/pages/ZKVoteInterface.tsx

import React, { useEffect, useState, useCallback, Suspense } from "react"
import { useTranslation } from "react-i18next"
import { Helmet } from "react-helmet-async"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { VoteResultsChart } from "@/widgets/Voting/VoteResultsChart"
import { VoteForm } from "@/widgets/Voting/VoteForm"
import { ProposalList } from "@/widgets/Voting/ProposalList"
import { ZKProofVerifier } from "@/widgets/Voting/ZKProofVerifier"
import { useZKVote } from "@/features/voting/hooks/useZKVote"
import { useIdentity } from "@/features/auth/hooks/useIdentity"
import { useNotification } from "@/shared/hooks/useNotification"
import { EventBus } from "@/shared/utils/EventBus"
import { motion } from "framer-motion"

export const ZKVoteInterface: React.FC = () => {
  const { t } = useTranslation()
  const { user } = useIdentity()
  const notify = useNotification()
  const {
    fetchProposals,
    proposals,
    currentVoteStatus,
    submitZKVote,
    fetchVoteStats,
    zkStats,
    proofPending
  } = useZKVote()

  const [selectedProposalId, setSelectedProposalId] = useState<string | null>(null)
  const [voteSubmitted, setVoteSubmitted] = useState(false)

  useEffect(() => {
    fetchProposals()
    fetchVoteStats()
    EventBus.emit("UI_RENDERED", { page: "ZKVoteInterface" })
  }, [fetchProposals, fetchVoteStats])

  const handleVote = useCallback(async (voteData: { proof: string; signal: string }) => {
    if (!selectedProposalId || !user?.did) {
      notify.error(t("zk_vote.errors.no_proposal_or_identity"))
      return
    }

    try {
      await submitZKVote({
        proposalId: selectedProposalId,
        signal: voteData.signal,
        zkProof: voteData.proof,
        voterDID: user.did
      })
      setVoteSubmitted(true)
      notify.success(t("zk_vote.success"))
      fetchVoteStats()
    } catch (e: any) {
      notify.error(t("zk_vote.errors.submit_failed"))
    }
  }, [submitZKVote, selectedProposalId, user?.did, t, notify, fetchVoteStats])

  return (
    <>
      <Helmet>
        <title>{t("zk_vote.title")}</title>
        <meta name="description" content={t("zk_vote.meta_description")} />
      </Helmet>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3 }}
      >
        <Container>
          <PageHeader
            title={t("zk_vote.header")}
            subtitle={t("zk_vote.subheader")}
            actions={[
              {
                label: t("zk_vote.refresh"),
                onClick: () => {
                  fetchProposals()
                  fetchVoteStats()
                }
              }
            ]}
          />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">
            <ProposalList
              proposals={proposals}
              selected={selectedProposalId}
              onSelect={setSelectedProposalId}
            />

            <div className="flex flex-col gap-6">
              <ZKProofVerifier
                disabled={!selectedProposalId}
                onVerify={handleVote}
                pending={proofPending}
              />

              <VoteForm
                proposalId={selectedProposalId}
                disabled={!selectedProposalId || voteSubmitted}
                onSubmit={handleVote}
                submitting={proofPending}
              />

              <VoteResultsChart stats={zkStats} />
            </div>
          </div>
        </Container>
      </motion.div>
    </>
  )
}

export default ZKVoteInterface
