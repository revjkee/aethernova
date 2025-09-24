// path: src/pages/CTFConsole.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useCTFQuery, useCTFStream } from "@/features/ctf/ctfAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { toast } from "react-toastify";
import { Modal } from "@/shared/components/Modal";
import { CTFChallengeTable } from "@/features/ctf/components/CTFChallengeTable";
import { CTFConsolePanel } from "@/features/ctf/components/CTFConsolePanel";
import { CTFLeaderboard } from "@/features/ctf/components/CTFLeaderboard";
import { CTFLogStream } from "@/features/ctf/components/CTFLogStream";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { CTFUploadChallenge } from "@/features/ctf/components/CTFUploadChallenge";
import { ChallengeDetailModal } from "@/features/ctf/components/ChallengeDetailModal";
import { ChallengeFilterPanel } from "@/features/ctf/components/ChallengeFilterPanel";

const CTFConsole = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selectedChallengeId, setSelectedChallengeId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    category: "all",
    status: "all",
    team: "",
    tag: "",
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: challenges, isLoading, refetch } = useCTFQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useCTFStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelectChallenge = (id: string) => {
    setSelectedChallengeId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(challenges, null, 2));
      toast.success("Задания экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const categoryStats = useMemo(() => {
    if (!challenges) return {};
    return challenges.reduce((acc, ch) => {
      acc[ch.category] = (acc[ch.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }, [challenges]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.CTF_ORG, ROLE.SECURITY]}>
      <Helmet>
        <title>CTF Console | TeslaAI Labs</title>
        <meta name="description" content="Центральная панель управления CTF-инфраструктурой, заданиями и участниками." />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">CTF Console</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
            <Button onClick={() => setUploadOpen(true)}>Загрузить задание</Button>
          </div>
        </div>

        <div className="mb-6">
          <ChallengeFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Доказательство подлинности флагов</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Консоль админа</h3>
                <CTFConsolePanel challenges={challenges ?? []} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Лог активности команд</h3>
                <CTFLogStream logs={stream.logs} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Зарегистрированные задания</h2>
              <CTFChallengeTable items={challenges ?? []} onSelect={handleSelectChallenge} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Рейтинг команд</h2>
              <CTFLeaderboard leaderboard={stream.leaderboard} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedChallengeId && <ChallengeDetailModal challengeId={selectedChallengeId} />}
        </Modal>

        <Modal open={uploadOpen} onClose={() => setUploadOpen(false)}>
          <CTFUploadChallenge onUploaded={refetch} />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default CTFConsole;
