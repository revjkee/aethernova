// path: src/pages/DAOGovernance.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useProposalStream, useProposalListQuery } from "@/features/dao/daoAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { Spinner } from "@/shared/components/Spinner";
import { Helmet } from "react-helmet";
import { Button } from "@/shared/components/Button";
import { toast } from "react-toastify";
import { DAOVotingChart } from "@/features/dao/components/DAOVotingChart";
import { DAOProposalTable } from "@/features/dao/components/DAOProposalTable";
import { DAOFilterPanel } from "@/features/dao/components/DAOFilterPanel";
import { DAODetailModal } from "@/features/dao/components/DAODetailModal";
import { Modal } from "@/shared/components/Modal";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { QuorumStatusPanel } from "@/features/dao/components/QuorumStatusPanel";
import { ConflictHeatmap } from "@/features/dao/components/ConflictHeatmap";

const DAOGovernance = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedProposalId, setSelectedProposalId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    status: "all",
    type: "all",
    initiator: "",
    tag: "",
  });

  const debouncedFilters = useDebounce(filters, 400);
  const { data: proposals, isLoading, refetch } = useProposalListQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useProposalStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const voteStats = useMemo(() => {
    const result = { approved: 0, rejected: 0, pending: 0 };
    if (!proposals) return result;
    for (const p of proposals) {
      if (p.status === "APPROVED") result.approved++;
      else if (p.status === "REJECTED") result.rejected++;
      else result.pending++;
    }
    return result;
  }, [proposals]);

  const handleSelect = (id: string) => {
    setSelectedProposalId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(proposals, null, 2));
      toast.success("Предложения экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.DAO, ROLE.GOVERNANCE]}>
      <Helmet>
        <title>DAO Governance | TeslaAI / NeuroCity</title>
        <meta name="description" content="Децентрализованное управление через DAO: предложения, голоса, консенсус" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">DAO Governance Panel</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт</Button>
          </div>
        </div>

        <div className="mb-6">
          <DAOFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Доказательство DAO-подписей</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Кворум и делегаты</h3>
                <QuorumStatusPanel data={proposals ?? []} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Конфликты по голосованию</h3>
                <ConflictHeatmap matrix={stream.conflictMatrix} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Статистика голосов</h2>
              <DAOVotingChart summary={voteStats} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Предложения DAO</h2>
              <DAOProposalTable items={proposals ?? []} onSelect={handleSelect} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedProposalId && <DAODetailModal proposalId={selectedProposalId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default DAOGovernance;
