// path: src/pages/QuantumLabPanel.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useQuantumJobsQuery, useQuantumStream } from "@/features/quantum/quantumAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { toast } from "react-toastify";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { QuantumJobTable } from "@/features/quantum/components/QuantumJobTable";
import { QuantumFilterPanel } from "@/features/quantum/components/QuantumFilterPanel";
import { QuantumUsageStats } from "@/features/quantum/components/QuantumUsageStats";
import { QuantumStreamPanel } from "@/features/quantum/components/QuantumStreamPanel";
import { QuantumJobDetailModal } from "@/features/quantum/components/QuantumJobDetailModal";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { Modal } from "@/shared/components/Modal";

const QuantumLabPanel = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    backend: "all",
    user: "all",
    status: "all",
    program: "",
  });

  const debouncedFilters = useDebounce(filters, 400);
  const { data: jobs, isLoading, refetch } = useQuantumJobsQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useQuantumStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelectJob = (id: string) => {
    setSelectedJobId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(jobs, null, 2));
      toast.success("Данные экспортированы в буфер");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const usageStats = useMemo(() => {
    if (!jobs) return { completed: 0, failed: 0, running: 0 };
    return jobs.reduce(
      (acc, job) => {
        if (job.status === "COMPLETED") acc.completed++;
        else if (job.status === "FAILED") acc.failed++;
        else acc.running++;
        return acc;
      },
      { completed: 0, failed: 0, running: 0 }
    );
  }, [jobs]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.QUANTUM, ROLE.RESEARCHER]}>
      <Helmet>
        <title>Quantum Lab Panel | TeslaAI NeuroCity</title>
        <meta name="description" content="Мониторинг и управление квантовыми задачами и QPU-интеграцией в реальном времени" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Quantum Lab Panel</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
          </div>
        </div>

        <div className="mb-6">
          <QuantumFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Доказательство QPU-выполнения</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Live Поток Задач</h3>
                <QuantumStreamPanel stream={stream.live} onSelect={handleSelectJob} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Статистика Использования</h3>
                <QuantumUsageStats stats={usageStats} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">История Задач</h2>
              <QuantumJobTable jobs={jobs ?? []} onSelect={handleSelectJob} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedJobId && <QuantumJobDetailModal jobId={selectedJobId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default QuantumLabPanel;
