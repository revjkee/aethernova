// src/pages/SystemMonitor.tsx

import React, { useEffect, useState, useCallback } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { HealthStatusGrid } from "@/widgets/Monitoring/HealthStatusGrid"
import { ResourceUsagePanel } from "@/widgets/Monitoring/ResourceUsagePanel"
import { ServiceHeartbeatTracker } from "@/widgets/Monitoring/ServiceHeartbeatTracker"
import { MetricsOverview } from "@/widgets/Monitoring/MetricsOverview"
import { RealtimeLogPanel } from "@/widgets/Monitoring/RealtimeLogPanel"
import { IncidentAlertList } from "@/widgets/Monitoring/IncidentAlertList"
import { useSystemMonitor } from "@/features/monitoring/hooks/useSystemMonitor"
import { RefreshButton } from "@/shared/ui/RefreshButton"
import { Divider } from "@/shared/ui/Divider"
import { motion } from "framer-motion"
import { Spinner } from "@/shared/ui/Spinner"
import { useNotification } from "@/shared/hooks/useNotification"

export const SystemMonitor: React.FC = () => {
  const { t } = useTranslation()
  const notify = useNotification()

  const {
    loadData,
    systemStatus,
    usageMetrics,
    incidents,
    logs,
    loading,
    refresh
  } = useSystemMonitor()

  useEffect(() => {
    loadData()
  }, [loadData])

  const handleRefresh = useCallback(() => {
    refresh()
    notify.success(t("system_monitor.refreshed"))
  }, [refresh, notify, t])

  return (
    <>
      <Helmet>
        <title>{t("system_monitor.title")}</title>
        <meta name="description" content={t("system_monitor.meta_description")} />
      </Helmet>

      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2 }}>
        <Container>
          <PageHeader
            title={t("system_monitor.header")}
            subtitle={t("system_monitor.subtitle")}
            action={<RefreshButton onClick={handleRefresh} />}
          />

          {loading ? (
            <div className="flex justify-center py-24">
              <Spinner />
            </div>
          ) : (
            <>
              <Divider label={t("system_monitor.health_status")} />
              <HealthStatusGrid status={systemStatus} />

              <Divider label={t("system_monitor.metrics_overview")} />
              <MetricsOverview metrics={usageMetrics} />

              <Divider label={t("system_monitor.resource_usage")} />
              <ResourceUsagePanel metrics={usageMetrics} />

              <Divider label={t("system_monitor.heartbeat_tracker")} />
              <ServiceHeartbeatTracker status={systemStatus} />

              <Divider label={t("system_monitor.realtime_logs")} />
              <RealtimeLogPanel logs={logs} />

              <Divider label={t("system_monitor.incidents")} />
              <IncidentAlertList incidents={incidents} />
            </>
          )}
        </Container>
      </motion.div>
    </>
  )
}

export default SystemMonitor
