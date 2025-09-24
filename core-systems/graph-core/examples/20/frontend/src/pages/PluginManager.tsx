// path: src/pages/PluginManager.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { usePluginQuery, usePluginStream } from "@/features/plugins/pluginAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { toast } from "react-toastify";
import { Modal } from "@/shared/components/Modal";
import { PluginTable } from "@/features/plugins/components/PluginTable";
import { PluginFilterPanel } from "@/features/plugins/components/PluginFilterPanel";
import { PluginDetailModal } from "@/features/plugins/components/PluginDetailModal";
import { PluginStatusRadar } from "@/features/plugins/components/PluginStatusRadar";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { PluginUploadPanel } from "@/features/plugins/components/PluginUploadPanel";
import { PluginEventLog } from "@/features/plugins/components/PluginEventLog";

const PluginManager = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selectedPluginId, setSelectedPluginId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    namespace: "all",
    type: "all",
    status: "all",
    tag: "",
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: plugins, isLoading, refetch } = usePluginQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = usePluginStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelect = (id: string) => {
    setSelectedPluginId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(plugins, null, 2));
      toast.success("Список плагинов экспортирован");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const statusStats = useMemo(() => {
    if (!plugins) return { active: 0, disabled: 0, error: 0 };
    return plugins.reduce(
      (acc, p) => {
        if (p.status === "ACTIVE") acc.active++;
        else if (p.status === "DISABLED") acc.disabled++;
        else acc.error++;
        return acc;
      },
      { active: 0, disabled: 0, error: 0 }
    );
  }, [plugins]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.DEVOPS, ROLE.PLUGIN_MANAGER]}>
      <Helmet>
        <title>Plugin Manager | TeslaAI / NeuroCity</title>
        <meta name="description" content="Промышленное управление плагинами и расширениями ядра системы TeslaAI / NeuroCity" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Управление плагинами</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
            <Button onClick={() => setUploadOpen(true)}>Загрузить плагин</Button>
          </div>
        </div>

        <div className="mb-6">
          <PluginFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Подтверждение целостности</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Статистика по статусам</h3>
                <PluginStatusRadar stats={statusStats} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Журнал активности</h3>
                <PluginEventLog events={stream.events} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Зарегистрированные плагины</h2>
              <PluginTable plugins={plugins ?? []} onSelect={handleSelect} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedPluginId && <PluginDetailModal pluginId={selectedPluginId} />}
        </Modal>

        <Modal open={uploadOpen} onClose={() => setUploadOpen(false)}>
          <PluginUploadPanel onUploaded={refetch} />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default PluginManager;
