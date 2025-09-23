// path: src/pages/DeploymentHub.tsx

import { useEffect, useMemo, useState } from "react";
import { Helmet } from "react-helmet";
import { toast } from "react-toastify";

import { useAuth } from "@/features/auth/hooks/useAuth";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Button } from "@/shared/components/Button";
import { Spinner } from "@/shared/components/Spinner";
import { Modal } from "@/shared/components/Modal";
import { useDebounce } from "@/shared/hooks/useDebounce";

import { useDeploymentsQuery, useDeploymentStream } from "@/features/deployment/deploymentAPI";
import { DeploymentTable } from "@/features/deployment/components/DeploymentTable";
import { DeploymentFilterPanel } from "@/features/deployment/components/DeploymentFilterPanel";
import { DeploymentLiveLogs } from "@/features/deployment/components/DeploymentLiveLogs";
import { DeploymentOverviewPanel } from "@/features/deployment/components/DeploymentOverviewPanel";
import { DeploymentRollbackModal } from "@/features/deployment/components/DeploymentRollbackModal";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";

const DeploymentHub = () => {
  const { user } = useAuth();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [rollbackModalOpen, setRollbackModalOpen] = useState(false);

  const [filters, setFilters] = useState({
    environment: "all",
    status: "all",
    version: "",
    author: "",
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: deployments, isLoading, refetch } = useDeploymentsQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useDeploymentStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(deployments, null, 2));
      toast.success("Деплойменты экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const deploymentStats = useMemo(() => {
    if (!deployments) return { success: 0, failed: 0, inProgress: 0 };
    return deployments.reduce(
      (acc, d) => {
        if (d.status === "SUCCESS") acc.success++;
        else if (d.status === "FAILED") acc.failed++;
        else acc.inProgress++;
        return acc;
      },
      { success: 0, failed: 0, inProgress: 0 }
    );
  }, [deployments]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.DEVOPS, ROLE.RELEASE_MANAGER]}>
      <Helmet>
        <title>Deployment Hub | TeslaAI NeuroCity</title>
        <meta name="description" content="Централизованное управление деплойментами, ZK-аудит, rollback, CI/CD, журналы, версии" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Deployment Hub</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
            <Button onClick={() => setRollbackModalOpen(true)}>Rollback</Button>
          </div>
        </div>

        <div className="mb-6">
          <DeploymentFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Проверка CI/CD цепочки</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Обзор активных окружений</h3>
                <DeploymentOverviewPanel stats={deploymentStats} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Live журналы развертываний</h3>
                <DeploymentLiveLogs logs={stream.logs} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">История деплойментов</h2>
              <DeploymentTable deployments={deployments ?? []} onSelect={setSelectedId} />
            </section>
          </>
        )}

        <Modal open={rollbackModalOpen} onClose={() => setRollbackModalOpen(false)}>
          <DeploymentRollbackModal deployments={deployments ?? []} onRollbackComplete={refetch} />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default DeploymentHub;
