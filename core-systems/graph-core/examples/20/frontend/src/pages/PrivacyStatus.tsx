// path: src/pages/PrivacyStatus.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { usePrivacyStatusQuery } from "@/features/privacy/privacyAPI";
import { usePrivacyTelemetry } from "@/features/privacy/hooks/usePrivacyTelemetry";
import { Modal } from "@/shared/components/Modal";
import { Spinner } from "@/shared/components/Spinner";
import { toast } from "react-toastify";
import { Helmet } from "react-helmet";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { PrivacyScoreChart } from "@/features/privacy/components/PrivacyScoreChart";
import { AnonymityGraph } from "@/features/privacy/components/AnonymityGraph";
import { VPNStatus } from "@/features/privacy/components/VPNStatus";
import { ZKPrivacyBadge } from "@/shared/components/ZKPrivacyBadge";
import { PrivacyViolationLog } from "@/features/privacy/components/PrivacyViolationLog";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { useAnonymityAudit } from "@/features/privacy/hooks/useAnonymityAudit";
import { Button } from "@/shared/components/Button";

const PrivacyStatus = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 300);

  const { data: status, isLoading, refetch } = usePrivacyStatusQuery({ userId: user?.id, filter: debouncedSearch });
  const telemetry = usePrivacyTelemetry();
  const audit = useAnonymityAudit();

  useEffect(() => {
    telemetry.init(user?.id);
    audit.startAudit(user?.id);
    return () => {
      telemetry.shutdown();
      audit.stopAudit();
    };
  }, [user]);

  const riskLevel = useMemo(() => {
    if (!status) return "unknown";
    const score = status.privacyScore;
    if (score > 90) return "Низкий";
    if (score > 60) return "Средний";
    return "Высокий";
  }, [status]);

  const renderStatusBlock = () => {
    if (!status) return null;
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-white dark:bg-zinc-900 rounded-lg p-5 shadow">
          <h3 className="text-lg font-semibold mb-2">ZK-анонимизация</h3>
          <ZKPrivacyBadge verified={status.zkValid} />
        </div>
        <div className="bg-white dark:bg-zinc-900 rounded-lg p-5 shadow">
          <h3 className="text-lg font-semibold mb-2">VPN / TOR</h3>
          <VPNStatus status={status.vpn} tor={status.tor} />
        </div>
        <div className="bg-white dark:bg-zinc-900 rounded-lg p-5 shadow">
          <h3 className="text-lg font-semibold mb-2">Cookie & Fingerprint</h3>
          <ul className="text-sm text-gray-700 dark:text-gray-300">
            <li>Cookies: {status.cookies.length}</li>
            <li>Fingerprint Hash: {status.fingerprint.hash}</li>
            <li>Entropy Score: {status.fingerprint.entropy}</li>
          </ul>
        </div>
      </div>
    );
  };

  const handleClearCookies = async () => {
    try {
      await telemetry.clearCookies();
      toast.success("Cookies удалены");
      refetch();
    } catch {
      toast.error("Не удалось удалить cookies");
    }
  };

  return (
    <AccessGuard roles={[ROLE.USER, ROLE.ADMIN, ROLE.SECURITY]}>
      <Helmet>
        <title>Приватность | TeslaAI NeuroCity</title>
        <meta name="description" content="Анализ приватности, анонимности и следов пользователя" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Статус Приватности</h1>
          <Button onClick={handleClearCookies}>Удалить Cookies</Button>
        </div>

        <div className="mb-6">
          <input
            type="text"
            placeholder="Фильтр логов..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full max-w-lg px-4 py-2 border rounded-md"
          />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <div className="mb-10">
              <PrivacyScoreChart score={status?.privacyScore ?? 0} />
            </div>

            <div className="mb-10">{renderStatusBlock()}</div>

            <div className="mb-10">
              <AnonymityGraph streams={telemetry.anonymitySignals} />
            </div>

            <div className="mb-10">
              <PrivacyViolationLog logs={status?.violations ?? []} search={debouncedSearch} />
            </div>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          <div className="p-4">
            <h2 className="text-lg font-bold mb-4">Детальный аудит</h2>
            <ul className="text-sm text-gray-700 dark:text-gray-300">
              {audit.logs.map((entry, index) => (
                <li key={index} className="border-b py-2">{entry}</li>
              ))}
            </ul>
          </div>
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default PrivacyStatus;
