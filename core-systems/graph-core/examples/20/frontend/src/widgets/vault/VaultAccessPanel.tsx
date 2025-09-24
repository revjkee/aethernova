import React, { useEffect, useState, useMemo } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { useSession } from '@/core/hooks/useSession';
import { useVault } from '@/services/vault/useVault';
import { LogAccess } from '@/services/logging/logAccess';
import { AccessLevel, VaultRecord } from '@/types/vault';
import { ShieldCheck, Lock, KeyRound, FolderSearch } from 'lucide-react';

interface VaultAccessPanelProps {
  vaultId: string;
}

export const VaultAccessPanel: React.FC<VaultAccessPanelProps> = ({ vaultId }) => {
  const { user, role } = useSession();
  const {
    fetchVaultMetadata,
    getAccessLogs,
    decryptRecord,
    grantTemporaryAccess,
    revokeAccess,
    isLoading,
  } = useVault(vaultId);

  const [records, setRecords] = useState<VaultRecord[]>([]);
  const [accessLevel, setAccessLevel] = useState<AccessLevel | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<VaultRecord | null>(null);
  const [search, setSearch] = useState('');
  const [loadingRecordId, setLoadingRecordId] = useState<string | null>(null);

  useEffect(() => {
    fetchVaultMetadata().then((meta) => {
      setAccessLevel(meta.accessLevel);
      setRecords(meta.records);
    });
    LogAccess('vault_opened', { vaultId, userId: user.id });
  }, [vaultId]);

  const filteredRecords = useMemo(() => {
    return records.filter((rec) =>
      rec.name.toLowerCase().includes(search.toLowerCase())
    );
  }, [records, search]);

  const handleViewRecord = async (record: VaultRecord) => {
    if (!accessLevel || accessLevel < record.requiredLevel) return;
    setLoadingRecordId(record.id);
    const decrypted = await decryptRecord(record.id);
    setSelectedRecord({ ...record, decryptedContent: decrypted });
    setLoadingRecordId(null);
    LogAccess('record_viewed', {
      vaultId,
      recordId: record.id,
      userId: user.id,
    });
  };

  const handleGrantAccess = async () => {
    await grantTemporaryAccess(user.id);
    LogAccess('temporary_access_granted', { vaultId, userId: user.id });
  };

  const handleRevokeAccess = async () => {
    await revokeAccess(user.id);
    LogAccess('access_revoked', { vaultId, userId: user.id });
  };

  return (
    <Card className="w-full shadow-xl border border-muted bg-background/80 backdrop-blur-xl">
      <CardHeader className="flex justify-between items-center px-4 pt-4 pb-2">
        <div className="flex items-center gap-2">
          <FolderSearch className="w-5 h-5 text-primary" />
          <span className="text-xl font-semibold">Vault Access Panel</span>
        </div>
        <Badge variant="outline" className="text-xs">
          Access: {AccessLevel[accessLevel ?? 0]}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-4 px-4 pb-4">
        <div className="flex items-center gap-2">
          <Input
            type="text"
            placeholder="Search record..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1"
          />
          {role === 'admin' && (
            <>
              <Button size="sm" variant="ghost" onClick={handleGrantAccess}>
                <KeyRound className="w-4 h-4 mr-1" /> Grant Access
              </Button>
              <Button size="sm" variant="destructive" onClick={handleRevokeAccess}>
                <Lock className="w-4 h-4 mr-1" /> Revoke
              </Button>
            </>
          )}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {isLoading ? (
            Array.from({ length: 4 }).map((_, idx) => (
              <Skeleton key={idx} className="h-[60px] w-full rounded-xl" />
            ))
          ) : (
            filteredRecords.map((record) => (
              <div
                key={record.id}
                onClick={() => handleViewRecord(record)}
                className={`cursor-pointer rounded-xl border p-3 transition hover:bg-accent/40 ${
                  loadingRecordId === record.id ? 'opacity-50 pointer-events-none' : ''
                }`}
              >
                <div className="font-medium text-sm flex justify-between">
                  {record.name}
                  <Badge variant="secondary">
                    {AccessLevel[record.requiredLevel]}
                  </Badge>
                </div>
                <div className="text-xs text-muted-foreground truncate">
                  {record.description}
                </div>
              </div>
            ))
          )}
        </div>
        {selectedRecord && (
          <div className="mt-6 p-4 rounded-xl bg-secondary/60 border text-sm space-y-2">
            <div className="font-semibold flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              {selectedRecord.name}
            </div>
            <div className="whitespace-pre-wrap">{selectedRecord.decryptedContent}</div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
