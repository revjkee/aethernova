// src/pages/GovernancePanel.tsx

import React, { useMemo, useState, useEffect, Suspense } from "react"
import { useTranslation } from "react-i18next"
import { Helmet } from "react-helmet-async"
import { Container } from "@/shared/ui/Container"
import { Breadcrumbs } from "@/shared/components/Breadcrumbs"
import { PageHeader } from "@/shared/ui/PageHeader"
import { GovernanceStats } from "@/widgets/Governance/GovernanceStats"
import { ProposalTimeline } from "@/widgets/Governance/ProposalTimeline"
import { VotingActivityGraph } from "@/widgets/Voting/VotingActivityGraph"
import { RuleEditor } from "@/widgets/Governance/RuleEditor"
import { PolicyMatrix } from "@/widgets/Governance/PolicyMatrix"
import { RiskGovernanceChart } from "@/widgets/Security/RiskGovernanceChart"
import { useGovernance } from "@/features/governance/hooks/useGovernance"
import { useVoting } from "@/features/voting/hooks/useVoting"
import { useTelemetry } from "@/features/monitoring/hooks/useTelemetry"
import { EventBus } from "@/shared/utils/EventBus"
import { motion } from "framer-motion"

export const GovernancePanel: React.FC = () => {
  const { t } = useTranslation()
  const telemetry = useTelemetry()
  const { fetchGovernanceData, governanceData } = useGovernance()
  const { proposals, fetchProposals } = useVoting()
  const [activeTab, setActiveTab] = useState<"overview" | "rules" | "policies">("overview")

  useEffect(() => {
    fetchGovernanceData()
    fetchProposals()
    telemetry.trackPage("GovernancePanel")
    EventBus.emit("UI_RENDERED", { page: "GovernancePanel" })
  }, [fetchGovernanceData, fetchProposals, telemetry])

  const breadcrumbs = useMemo(() => [
    { label: t("nav.home"), to: "/" },
    { label: t("nav.governance"), to: "/governance" }
  ], [t])

  return (
    <>
      <Helmet>
        <title>{t("governance_panel.title")}</title>
        <meta name="description" content={t("governance_panel.meta")} />
      </Helmet>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
      >
        <Container>
          <Breadcrumbs items={breadcrumbs} />
          <PageHeader
            title={t("governance_panel.header")}
            subtitle={t("governance_panel.description")}
            actions={[
              {
                label: t("governance_panel.actions.submit_proposal"),
                onClick: () => EventBus.emit("OPEN_MODAL", { type: "SUBMIT_PROPOSAL" })
              },
              {
                label: t("governance_panel.actions.view_logs"),
                onClick: () => EventBus.emit("OPEN_PANEL", { panel: "GovernanceLogs" })
              }
            ]}
            tabs={[
              { id: "overview", label: t("governance_panel.tabs.overview") },
              { id: "rules", label: t("governance_panel.tabs.rules") },
              { id: "policies", label: t("governance_panel.tabs.policies") }
            ]}
            activeTab={activeTab}
            onTabChange={setActiveTab}
          />

          {activeTab === "overview" && (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 mt-6">
              <GovernanceStats data={governanceData.stats} />
              <VotingActivityGraph data={governanceData.votingActivity} />
              <ProposalTimeline proposals={proposals} />
              <RiskGovernanceChart risks={governanceData.riskProfile} />
            </div>
          )}

          {activeTab === "rules" && (
            <div className="mt-6">
              <RuleEditor rules={governanceData.rules} />
            </div>
          )}

          {activeTab === "policies" && (
            <div className="mt-6">
              <PolicyMatrix policies={governanceData.policies} />
            </div>
          )}
        </Container>
      </motion.div>
    </>
  )
}

export default GovernancePanel
