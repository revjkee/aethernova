// src/pages/HRDashboard.tsx

import React, { useEffect, useMemo } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { Breadcrumbs } from "@/shared/components/Breadcrumbs"
import { useAuth } from "@/features/auth/hooks/useAuth"
import { useHRMetrics } from "@/features/governance/hooks/useHRMetrics"
import { DiversityTracker } from "@/widgets/HR/DiversityTracker"
import { FunnelView } from "@/widgets/HR/FunnelView"
import { FeedbackCollector } from "@/widgets/HR/FeedbackCollector"
import { AuditLogTimeline } from "@/widgets/Monitoring/AuditLogTimeline"
import { BiasAuditor } from "@/widgets/AI_Ethics/BiasAuditor"
import { ComplianceRadar } from "@/widgets/Privacy/ComplianceRadar"
import { LiveAnalytics } from "@/widgets/Monitoring/LiveAnalytics"
import { RiskHeatmap } from "@/widgets/Security/RiskHeatmap"
import { DecisionExplainer } from "@/widgets/XAI/DecisionExplainer"
import { motion } from "framer-motion"
import { HRControlPanel } from "@/widgets/HR/HRControlPanel"
import { GitCommitHash } from "@/widgets/CI_CD/GitCommitHash"
import { TokenEconomyPreview } from "@/widgets/Marketplace/TokenEconomyPreview"
import { useTelemetry } from "@/features/monitoring/hooks/useTelemetry"
import { EventBus } from "@/shared/utils/EventBus"

export const HRDashboard: React.FC = () => {
  const { t } = useTranslation()
  const { user } = useAuth()
  const navigate = useNavigate()
  const telemetry = useTelemetry()
  const { stats, isLoading } = useHRMetrics()

  const breadcrumbItems = useMemo(() => [
    { label: t("nav.home"), to: "/" },
    { label: t("nav.hr_dashboard"), to: "/hr" }
  ], [t])

  useEffect(() => {
    telemetry.trackPage("HRDashboard")
    EventBus.emit("UI_RENDERED", { page: "HRDashboard", user })
  }, [telemetry, user])

  return (
    <>
      <Helmet>
        <title>{t("hr_dashboard.title")}</title>
        <meta name="description" content={t("hr_dashboard.meta_description") ?? ""} />
      </Helmet>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2, duration: 0.4 }}
      >
        <Container>
          <Breadcrumbs items={breadcrumbItems} />
          <PageHeader
            title={t("hr_dashboard.header")}
            subtitle={t("hr_dashboard.subtitle")}
            actions={[
              {
                label: t("hr_dashboard.actions.view_audit"),
                onClick: () => navigate("/audit")
              }
            ]}
          />

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mt-8">
            <div className="col-span-2 flex flex-col gap-6">
              <DiversityTracker />
              <FunnelView />
              <FeedbackCollector />
              <LiveAnalytics />
              <DecisionExplainer />
              <TokenEconomyPreview />
            </div>

            <div className="col-span-1 flex flex-col gap-6">
              <HRControlPanel stats={stats} loading={isLoading} />
              <BiasAuditor />
              <RiskHeatmap />
              <ComplianceRadar />
              <AuditLogTimeline limit={10} />
              <GitCommitHash hash={process.env.REACT_APP_COMMIT_HASH ?? "N/A"} />
            </div>
          </div>
        </Container>
      </motion.div>
    </>
  )
}

export default HRDashboard
