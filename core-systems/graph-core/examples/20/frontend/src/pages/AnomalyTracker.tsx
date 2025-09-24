// src/pages/AnomalyTracker.tsx

import React, { useEffect, useState, useCallback, useMemo } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { AnomalyTable } from "@/widgets/Monitoring/AnomalyTable"
import { AnomalyDetailDrawer } from "@/widgets/Monitoring/AnomalyDetailDrawer"
import { useAnomalyDetection } from "@/features/monitoring/hooks/useAnomalyDetection"
import { AnomalyFilters } from "@/widgets/Monitoring/AnomalyFilters"
import { AnomalyHeatmap } from "@/widgets/Monitoring/AnomalyHeatmap"
import { AnomalySeverityChart } from "@/widgets/Monitoring/AnomalySeverityChart"
import { Spinner } from "@/shared/ui/Spinner"
import { Divider } from "@/shared/ui/Divider"
import { Button } from "@/shared/ui/Button"
import { useNotification } from "@/shared/hooks/useNotification"
import { motion } from "framer-motion"

export const AnomalyTracker: React.FC = () => {
  const { t } = useTranslation()
  const notify = useNotification()

  const {
    fetchAnomalies,
    anomalies,
    loading,
    refresh,
    filters,
    setFilters,
    selectedAnomaly,
    selectAnomaly,
    closeDrawer,
    markResolved
  } = useAnomalyDetection()

  useEffect(() => {
    fetchAnomalies()
  }, [fetchAnomalies])

  const handleMarkResolved = useCallback(async (id: string) => {
    try {
      await markResolved(id)
      notify.success(t("anomaly.resolved"))
      refresh()
    } catch {
      notify.error(t("anomaly.resolve_error"))
    }
  }, [markResolved, notify, refresh, t])

  const highSeverityCount = useMemo(() => {
    return anomalies.filter(a => a.severity === "critical").length
  }, [anomalies])

  return (
    <>
      <Helmet>
        <title>{t("anomaly.title")}</title>
        <meta name="description" content={t("anomaly.description")} />
      </Helmet>

      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.25 }}>
        <Container>
          <PageHeader
            title={t("anomaly.header")}
            subtitle={`${t("anomaly.high_impact")}: ${highSeverityCount}`}
            actions={[
              {
                label: t("anomaly.refresh"),
                onClick: refresh
              }
            ]}
          />

          {loading ? (
            <div className="flex justify-center py-12">
              <Spinner />
            </div>
          ) : (
            <>
              <Divider label={t("anomaly.filters")} />
              <AnomalyFilters filters={filters} setFilters={setFilters} />

              <Divider label={t("anomaly.heatmap")} />
              <AnomalyHeatmap data={anomalies} />

              <Divider label={t("anomaly.trends")} />
              <AnomalySeverityChart data={anomalies} />

              <Divider label={t("anomaly.list")} />
              <AnomalyTable
                anomalies={anomalies}
                onSelect={selectAnomaly}
                onResolve={handleMarkResolved}
              />
            </>
          )}

          <AnomalyDetailDrawer
            anomaly={selectedAnomaly}
            onClose={closeDrawer}
            onResolve={handleMarkResolved}
          />
        </Container>
      </motion.div>
    </>
  )
}

export default AnomalyTracker
