// path: src/pages/IntelDashboard.tsx

import { useEffect, useState, useMemo } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useIntelSignalsQuery, useThreatSourcesQuery, useStreamIntel } from "@/features/intel/intelAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Spinner } from "@/shared/components/Spinner";
import { Helmet } from "react-helmet";
import { toast } from "react-toastify";
import { Button } from "@/shared/components/Button";
import { IntelRadarChart } from "@/features/intel/components/IntelRadarChart";
import { ThreatTable } from "@/features/intel/components/ThreatTable";
import { SignalStreamPanel } from "@/features/intel/components/SignalStreamPanel";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { SourceMapPanel } from "@/features/intel/components/SourceMapPanel";
import { IntelFilterPanel } from "@/features/intel/components/IntelFilterPanel";
import { RiskIndicator } from "@/features/intel/components/RiskIndicator";
import { ReportModal } from "@/features/intel/components/ReportModal";
import { useDebounce } from "@/shared/hooks/useDebounce";

const IntelDashboard = () => {
  const { user } = useAuth();
  const [filter, setFilter] = useState({ source: "all", level: "all", tag: "" });
  const [modalOpen, setModalOpen] = useState(false);
  const debouncedTag = useDebounce(filter.tag, 300);

  const { data: signals, isLoading: loadingSignals } = useIntelSignalsQuery({
    source: filter.source,
    level: filter.level,
    tag: debouncedTag,
  });

  const { data: sources, isLoading: loadingSources } = useThreatSourcesQuery();
  const { stream, connect, disconnect } = useStreamIntel();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const riskSummary = useMemo(() => {
    if (!signals?.length) return { high: 0, medium: 0, low: 0 };
    const counts = { high: 0, medium: 0, low: 0 };
    for (const sig of signals) {
      if (sig.level === "high") counts.high++;
      else if (sig.level === "medium") counts.medium++;
      else counts.low++;
    }
    return counts;
  }, [signals]);

  const handleReportOpen = () => setModalOpen(true);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.INTEL, ROLE.GOVERNANCE]}>
      <Helmet>
        <title>Разведпанель | NeuroCity</title>
        <meta name="description" content="AI-панель разведки: сигналы угроз, анализ источников, карты и отчёты" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Intel Dashboard</h1>
          <Button onClick={handleReportOpen}>Сформировать отчёт</Button>
        </div>

        <div className="mb-8">
          <IntelFilterPanel filters={filter} onChange={setFilter} sourceOptions={sources ?? []} />
        </div>

        {loadingSignals || loadingSources ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Карта источников</h3>
                <SourceMapPanel sources={sources ?? []} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Потоковые сигналы</h3>
                <SignalStreamPanel signals={stream.live} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Анализ AI-рисков</h3>
                <IntelRadarChart summary={riskSummary} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Обнаруженные угрозы</h2>
              <ThreatTable items={signals ?? []} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Индикатор общей угрозы</h2>
              <RiskIndicator summary={riskSummary} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">ZK-верификация агентской сети</h2>
              <ZKProofBadge verified={stream.zkValid} />
            </section>
          </>
        )}

        <ReportModal open={modalOpen} onClose={() => setModalOpen(false)} signals={signals ?? []} />
      </div>
    </AccessGuard>
  );
};

export default IntelDashboard;
