// src/pages/AgentControl.tsx

import React, { useEffect, useMemo, useState, Suspense } from "react"
import { useTranslation } from "react-i18next"
import { Helmet } from "react-helmet-async"
import { useNavigate } from "react-router-dom"
import { Container } from "@/shared/ui/Container"
import { Breadcrumbs } from "@/shared/components/Breadcrumbs"
import { PageHeader } from "@/shared/ui/PageHeader"
import { AgentOverview } from "@/widgets/Agents/AgentOverview"
import { AgentMetricsPanel } from "@/widgets/Agents/AgentMetricsPanel"
import { IntentControlPanel } from "@/widgets/Agents/IntentControlPanel"
import { AgentPerformanceGraph } from "@/widgets/Agents/AgentPerformanceGraph"
import { ResourceUtilization } from "@/widgets/Monitoring/ResourceUtilization"
import { LatencyChart } from "@/widgets/Monitoring/LatencyChart"
import { RiskProfilePanel } from "@/widgets/Security/RiskProfilePanel"
import { IntentDebugger } from "@/widgets/XAI/IntentDebugger"
import { TokenSpending } from "@/widgets/Marketplace/TokenSpending"
import { AgentLogsViewer } from "@/widgets/Agents/AgentLogsViewer"
import { AIIncidentTimeline } from "@/widgets/Security/AIIncidentTimeline"
import { useAgents } from "@/features/agents/hooks/useAgents"
import { useTelemetry } from "@/features/monitoring/hooks/useTelemetry"
import { EventBus } from "@/shared/utils/EventBus"
import { motion } from "framer-motion"

export const AgentControl: React.FC = () => {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const telemetry = useTelemetry()
  const { agents, refreshAgents } = useAgents()
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null)

  const selectedAgent = useMemo(
    () => agents.find((a) => a.id === selectedAgentId) || agents[0],
    [selectedAgentId, agents]
  )

  const breadcrumbs = useMemo(() => [
    { label: t("nav.home"), to: "/" },
    { label: t("nav.agents"), to: "/agents" }
  ], [t])

  useEffect(() => {
    telemetry.trackPage("AgentControl")
    EventBus.emit("UI_RENDERED", { page: "AgentControl" })
    const interval = setInterval(refreshAgents, 30000)
    return () => clearInterval(interval)
  }, [telemetry, refreshAgents])

  return (
    <>
      <Helmet>
        <title>{t("agent_control.title")}</title>
        <meta name="description" content={t("agent_control.description") ?? ""} />
      </Helmet>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
      >
        <Container>
          <Breadcrumbs items={breadcrumbs} />
          <PageHeader
            title={t("agent_control.header")}
            subtitle={t("agent_control.subtitle")}
            actions={[
              {
                label: t("agent_control.actions.manage_registry"),
                onClick: () => navigate("/agents/registry")
              },
              {
                label: t("agent_control.actions.create_agent"),
                onClick: () => navigate("/agents/new")
              }
            ]}
          />

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mt-8">
            <div className="col-span-2 flex flex-col gap-6">
              <AgentOverview agents={agents} selectedAgent={selectedAgent} onSelect={setSelectedAgentId} />
              <IntentControlPanel agent={selectedAgent} />
              <AgentPerformanceGraph agentId={selectedAgent?.id} />
              <LatencyChart agentId={selectedAgent?.id} />
              <TokenSpending agentId={selectedAgent?.id} />
              <IntentDebugger agentId={selectedAgent?.id} />
              <AgentLogsViewer agentId={selectedAgent?.id} limit={15} />
            </div>

            <div className="col-span-1 flex flex-col gap-6">
              <AgentMetricsPanel agent={selectedAgent} />
              <ResourceUtilization agentId={selectedAgent?.id} />
              <RiskProfilePanel agentId={selectedAgent?.id} />
              <AIIncidentTimeline agentId={selectedAgent?.id} />
            </div>
          </div>
        </Container>
      </motion.div>
    </>
  )
}

export default AgentControl
