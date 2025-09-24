// path: src/pages/KeyVaultDashboard.tsx

import { useEffect, useState, useMemo, useCallback } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useVaultKeysQuery, useRevokeKey, useRestoreKey, useAuditLogQuery } from "@/features/keyvault/keyAPI";
import { KeyRow } from "@/features/keyvault/components/KeyRow";
import { Modal } from "@/shared/components/Modal";
import { Button } from "@/shared/components/Button";
import { Spinner } from "@/shared/components/Spinner";
import { toast } from "react-toastify";
import { Helmet } from "react-helmet";
import { AnimatePresence, motion } from "framer-motion";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { VaultAuditPanel } from "@/features/keyvault/components/VaultAuditPanel";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { KeyDetailsPanel } from "@/features/keyvault/components/KeyDetailsPanel";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { useTelemetryStream } from "@/features/keyvault/hooks/useTelemetryStream";

const KeyVaultDashboard = () => {
  const { user } = useAuth();
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);

  const [selectedKeyId, setSelectedKeyId] = useState<string | null>(null);
  const [detailsModalOpen, setDetailsModalOpen] = useState(false);
  const [auditOpen, setAuditOpen] = useState(false);

  const { data: keys, isLoading, refetch } = useVaultKeysQuery({ query: debouncedSearch });
  const { data: auditLogs } = useAuditLogQuery();
  const revokeKey = useRevokeKey();
  const restoreKey = useRestoreKey();
  const { telemetry, subscribe, unsubscribe } = useTelemetryStream();

  useEffect(() => {
    telemetry.initStream();
    return () => telemetry.shutdown();
  }, []);

  const filteredKeys = useMemo(() => {
    if (!keys) return [];
    return keys.filter((k) => k.label.toLowerCase().includes(debouncedSearch.toLowerCase()));
  }, [keys, debouncedSearch]);

  const handleDetails = useCallback((id: string) => {
    setSelectedKeyId(id);
    setDetailsModalOpen(true);
  }, []);

  const handleRevoke = async (id: string) => {
    try {
      await revokeKey.mutateAsync(id);
      toast.success("Ключ отозван");
      refetch();
    } catch {
      toast.error("Ошибка при отзыве");
    }
  };

  const handleRestore = async (id: string) => {
    try {
      await restoreKey.mutateAsync(id);
      toast.success("Ключ восстановлен");
      refetch();
    } catch {
      toast.error("Ошибка восстановления");
    }
  };

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.SECURITY]}>
      <Helmet>
        <title>Хранилище ключей | TeslaAI NeuroCity</title>
        <meta name="description" content="Контроль ключей, управление доступом, Zero Trust, анонимность, аудит" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-3xl font-bold">Key Vault Dashboard</h1>
          <Button onClick={() => setAuditOpen(true)}>Аудит</Button>
        </div>

        <input
          type="text"
          className="w-full mb-6 px-4 py-2 border rounded-md"
          placeholder="Поиск по названию ключа..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="flex justify-center items-center h-[200px]">
              <Spinner />
            </div>
          ) : (
            <table className="w-full table-auto border border-gray-200">
              <thead>
                <tr className="bg-gray-100 text-left text-sm font-semibold">
                  <th className="px-4 py-2">Label</th>
                  <th className="px-4 py-2">Status</th>
                  <th className="px-4 py-2">ZK Proof</th>
                  <th className="px-4 py-2">Telemetry</th>
                  <th className="px-4 py-2">Действия</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {filteredKeys.map((key) => (
                    <motion.tr
                      key={key.id}
                      layout
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      <KeyRow
                        keyData={key}
                        onDetails={() => handleDetails(key.id)}
                        onRevoke={() => handleRevoke(key.id)}
                        onRestore={() => handleRestore(key.id)}
                        telemetry={telemetry.get(key.id)}
                        zk={<ZKProofBadge verified={key.verified} />}
                      />
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          )}
        </div>

        <AnimatePresence>
          {detailsModalOpen && selectedKeyId && (
            <Modal onClose={() => setDetailsModalOpen(false)}>
              <KeyDetailsPanel keyId={selectedKeyId} />
            </Modal>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {auditOpen && (
            <Modal onClose={() => setAuditOpen(false)}>
              <VaultAuditPanel logs={auditLogs} />
            </Modal>
          )}
        </AnimatePresence>
      </div>
    </AccessGuard>
  );
};

export default KeyVaultDashboard;
