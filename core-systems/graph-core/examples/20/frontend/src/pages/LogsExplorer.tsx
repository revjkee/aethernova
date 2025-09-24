// path: src/pages/LogsExplorer.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useLogsQuery, useLogStream } from "@/features/logs/logAPI";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { LogsTable } from "@/features/logs/components/LogsTable";
import { LogFilterPanel } from "@/features/logs/components/LogFilterPanel";
import { LogStatsPanel } from "@/features/logs/components/LogStatsPanel";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { Modal } from "@/shared/components/Modal";
import { LogDetailView } from "@/features/logs/components/LogDetailView";
import { toast } from "react-toastify";

const LogsExplorer = () => {
  const { user } = useAuth();
  const [selectedLogId, setSelectedLogId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const [filters, setFilters] = useState({
    level: "all",
    source: "all",
    agent: "",
    contains: "",
  });

  const debouncedFilters = useDebounce(filters, 400);

  const { data: logs, isLoading, refetch } = useLogsQuery(debouncedFilters);
  const { stream, connect, disconnect } = useLogStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleLogClick = (id: string) => {
    setSelectedLogId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(logs, null, 2));
      toast.success("Логи скопированы в буфер обмена");
    } catch {
      toast.error("Ошибка экспорта логов");
    }
  };

  const levelSummary = useMemo(() => {
    const summary = { error: 0, warn: 0, info: 0, debug: 0 };
    if (!logs) return summary;
    for (const log of logs) {
      summary[log.level] = (summary[log.level] ?? 0) + 1;
    }
    return summary;
  }, [logs]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.AUDITOR, ROLE.SECURITY]}>
      <Helmet>
        <title>Логи | TeslaAI NeuroCity</title>
        <meta name="description" content="Интерфейс анализа логов: потоки, фильтры, ZK-доказательства, экспорт" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Logs Explorer</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
          </div>
        </div>

        <div className="mb-6">
          <LogFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Статистика по уровням</h3>
                <LogStatsPanel summary={levelSummary} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Поток логов в реальном времени</h3>
                <LogsTable logs={stream.live} onClick={handleLogClick} isLive />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK-доказательства логов</h3>
                <ZKProofBadge verified={stream.zkVerified} />
              </div>
            </div>

            <div className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Исторические логи</h2>
              <LogsTable logs={logs ?? []} onClick={handleLogClick} />
            </div>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedLogId && <LogDetailView logId={selectedLogId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default LogsExplorer;
