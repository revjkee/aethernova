// path: src/pages/CapletController.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useCapletQuery, useCapletStream } from "@/features/caplets/capletAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { toast } from "react-toastify";
import { Modal } from "@/shared/components/Modal";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { CapletTable } from "@/features/caplets/components/CapletTable";
import { CapletFilterPanel } from "@/features/caplets/components/CapletFilterPanel";
import { CapletDetailModal } from "@/features/caplets/components/CapletDetailModal";
import { CapletAuditLog } from "@/features/caplets/components/CapletAuditLog";
import { CapletStatusRadar } from "@/features/caplets/components/CapletStatusRadar";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { CapletCreateModal } from "@/features/caplets/components/CapletCreateModal";
import { CapletIsolationMap } from "@/features/caplets/components/CapletIsolationMap";

const CapletController = () => {
  const { user } = useAuth();
  const [selectedCapletId, setSelectedCapletId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);

  const [filters, setFilters] = useState({
    type: "all",
    status: "all",
    owner: "",
    tag: "",
  });

  const debouncedFilters = useDebounce(filters, 400);
  const { data: caplets, isLoading, refetch } = useCapletQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useCapletStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelectCaplet = (id: string) => {
    setSelectedCapletId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(caplets, null, 2));
      toast.success("Данные каплетов экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const capletStats = useMemo(() => {
    if (!caplets) return { active: 0, stopped: 0, error: 0 };
    return caplets.reduce(
      (acc, caplet) => {
        if (caplet.status === "ACTIVE") acc.active++;
        else if (caplet.status === "STOPPED") acc.stopped++;
        else acc.error++;
        return acc;
      },
      { active: 0, stopped: 0, error: 0 }
    );
  }, [caplets]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.SYSENGINEER, ROLE.CAPLET_MANAGER]}>
      <Helmet>
        <title>Caplet Controller | TeslaAI NeuroCity</title>
        <meta name="description" content="Интерфейс управления каплетами: процессы, изоляция, статусы, ZK-верификация, аудит." />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Caplet Controller</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
            <Button onClick={() => setCreateOpen(true)}>Создать каплет</Button>
          </div>
        </div>

        <div className="mb-6">
          <CapletFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Проверка целостности</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Изоляция каплетов</h3>
                <CapletIsolationMap isolationMatrix={stream.isolation} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Сводка статусов</h3>
                <CapletStatusRadar stats={capletStats} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Журнал активности</h2>
              <CapletAuditLog events={stream.auditLog} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Зарегистрированные каплеты</h2>
              <CapletTable items={caplets ?? []} onSelect={handleSelectCaplet} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedCapletId && <CapletDetailModal capletId={selectedCapletId} />}
        </Modal>

        <Modal open={createOpen} onClose={() => setCreateOpen(false)}>
          <CapletCreateModal onCreated={refetch} />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default CapletController;
