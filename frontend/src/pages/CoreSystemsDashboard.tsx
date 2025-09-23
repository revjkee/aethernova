// path: src/pages/CoreSystemsDashboard.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useCoreStatusQuery, useCoreStream } from "@/features/core-systems/coreAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Button } from "@/shared/components/Button";
import { Spinner } from "@/shared/components/Spinner";
import { toast } from "react-toastify";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { Modal } from "@/shared/components/Modal";
import { CoreSystemsTable } from "@/features/core-systems/components/CoreSystemsTable";
import { CoreSystemRadar } from "@/features/core-systems/components/CoreSystemRadar";
import { CoreAnomalyPanel } from "@/features/core-systems/components/CoreAnomalyPanel";
import { CoreConflictHeatmap } from "@/features/core-systems/components/CoreConflictHeatmap";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { CoreSystemDetailModal } from "@/features/core-systems/components/CoreSystemDetailModal";

const CoreSystemsDashboard = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedCoreId, setSelectedCoreId] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    module: "all",
    status: "all",
    anomaly: false,
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: cores, isLoading, refetch } = useCoreStatusQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useCoreStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelect = (id: string) => {
    setSelectedCoreId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(cores, null, 2));
      toast.success("Экспортировано в буфер");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const statusSummary = useMemo(() => {
    if (!cores) return { active: 0, degraded: 0, down: 0 };
    return cores.reduce(
      (acc, m) => {
        if (m.status === "ACTIVE") acc.active++;
        else if (m.status === "DEGRADED") acc.degraded++;
        else acc.down++;
        return acc;
      },
      { active: 0, degraded: 0, down: 0 }
    );
  }, [cores]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.ENGINEER, ROLE.MONITOR]}>
      <Helmet>
        <title>Core Systems Dashboard | TeslaAI NeuroCity</title>
        <meta name="description" content="Мониторинг ядерных систем: статус, конфликты, аномалии, интеграции" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-3xl font-bold">Core Systems Dashboard</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
          </div>
        </div>

        <div className="mb-6">
          <CoreAnomalyPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Верификация Ядер</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Сводка по Статусам</h3>
                <CoreSystemRadar summary={statusSummary} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Конфликты Ядер</h3>
                <CoreConflictHeatmap matrix={stream.conflictMatrix} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Системы и Модули</h2>
              <CoreSystemsTable systems={cores ?? []} onSelect={handleSelect} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedCoreId && <CoreSystemDetailModal coreId={selectedCoreId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default CoreSystemsDashboard;
