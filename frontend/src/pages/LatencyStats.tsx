// path: src/pages/LatencyStats.tsx

import { useEffect, useMemo, useState } from "react";
import { useLatencyMetricsQuery, useLatencyStream } from "@/features/latency/latencyAPI";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { toast } from "react-toastify";
import { LatencyChart } from "@/features/latency/components/LatencyChart";
import { LatencyFilterPanel } from "@/features/latency/components/LatencyFilterPanel";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { Modal } from "@/shared/components/Modal";
import { LatencyDetailsView } from "@/features/latency/components/LatencyDetailsView";
import { LatencySummaryPanel } from "@/features/latency/components/LatencySummaryPanel";
import { LatencyTable } from "@/features/latency/components/LatencyTable";

const LatencyStats = () => {
  const [selectedMetricId, setSelectedMetricId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const [filters, setFilters] = useState({
    component: "all",
    severity: "all",
    model: "all",
    tag: "",
  });

  const debouncedFilters = useDebounce(filters, 400);
  const { data: metrics, isLoading, refetch } = useLatencyMetricsQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useLatencyStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelectMetric = (id: string) => {
    setSelectedMetricId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(metrics, null, 2));
      toast.success("Экспортировано в буфер обмена");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const statsSummary = useMemo(() => {
    if (!metrics) return { critical: 0, warning: 0, normal: 0 };
    return metrics.reduce(
      (acc, m) => {
        if (m.level === "critical") acc.critical += 1;
        else if (m.level === "warning") acc.warning += 1;
        else acc.normal += 1;
        return acc;
      },
      { critical: 0, warning: 0, normal: 0 }
    );
  }, [metrics]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.DEVOPS, ROLE.MONITOR]}>
      <Helmet>
        <title>Latency Stats | TeslaAI NeuroCity</title>
        <meta name="description" content="Анализ задержек компонентов системы в реальном времени и с архивами" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-3xl font-bold">Latency Dashboard</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт</Button>
          </div>
        </div>

        <div className="mb-6">
          <LatencyFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Общая статистика</h3>
                <LatencySummaryPanel summary={statsSummary} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Live Поток Метрик</h3>
                <LatencyTable items={stream.live} onClick={handleSelectMetric} isLive />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Подпись Достоверности</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">График Средней Задержки</h2>
              <LatencyChart data={metrics ?? []} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Все Метрики</h2>
              <LatencyTable items={metrics ?? []} onClick={handleSelectMetric} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedMetricId && <LatencyDetailsView metricId={selectedMetricId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default LatencyStats;
