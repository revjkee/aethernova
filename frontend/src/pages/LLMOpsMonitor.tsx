// path: src/pages/LLMOpsMonitor.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { useLLMMetricsQuery, useLLMStream } from "@/features/llmops/llmAPI";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { Helmet } from "react-helmet";
import { Button } from "@/shared/components/Button";
import { Spinner } from "@/shared/components/Spinner";
import { toast } from "react-toastify";
import { Modal } from "@/shared/components/Modal";
import { LLMFilterPanel } from "@/features/llmops/components/LLMFilterPanel";
import { LLMStatusChart } from "@/features/llmops/components/LLMStatusChart";
import { LLMStreamPanel } from "@/features/llmops/components/LLMStreamPanel";
import { LLMDetailModal } from "@/features/llmops/components/LLMDetailModal";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { LLMCrashTable } from "@/features/llmops/components/LLMCrashTable";
import { LLMUsageStats } from "@/features/llmops/components/LLMUsageStats";

const LLMOpsMonitor = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    model: "all",
    version: "all",
    agent: "",
    client: "",
    anomaly: false,
  });

  const debouncedFilters = useDebounce(filters, 400);
  const { data: metrics, isLoading, refetch } = useLLMMetricsQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useLLMStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const anomalyStats = useMemo(() => {
    if (!metrics) return { total: 0, anomalies: 0, stable: 0 };
    let anomalies = 0;
    for (const m of metrics) if (m.anomaly) anomalies++;
    return {
      total: metrics.length,
      anomalies,
      stable: metrics.length - anomalies,
    };
  }, [metrics]);

  const handleSelect = (id: string) => {
    setSelectedId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(metrics, null, 2));
      toast.success("Экспортировано");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.MONITOR, ROLE.LLMOPS]}>
      <Helmet>
        <title>LLMOps Мониторинг | NeuroCity</title>
        <meta name="description" content="Слежение за производительностью, отказами и отклонениями LLM-агентов." />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-3xl font-bold">LLM Operations Monitor</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт</Button>
          </div>
        </div>

        <div className="mb-6">
          <LLMFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Валидация Интеграции</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Состояние Потока</h3>
                <LLMStreamPanel stream={stream.live} onSelect={handleSelect} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Аномалии и Статистика</h3>
                <LLMUsageStats stats={anomalyStats} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">График Загрузки LLM</h2>
              <LLMStatusChart data={metrics ?? []} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Список отказов и отклонений</h2>
              <LLMCrashTable items={metrics ?? []} onSelect={handleSelect} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedId && <LLMDetailModal metricId={selectedId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default LLMOpsMonitor;
