import React, { useEffect, useState, useMemo } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select, SelectTrigger, SelectContent, SelectItem } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { useKeyVault } from '@/services/vault/useKeyVault';
import { useSession } from '@/core/hooks/useSession';
import { KeyIcon, EyeOff, Eye, Lock, ShieldAlert } from 'lucide-react';
import { KeyData, KeyRole, KeyStatus } from '@/types/keys';
import { formatDate } from '@/lib/utils/format';

export const KeyListView: React.FC = () => {
  const { user } = useSession();
  const { listKeys, revokeKey, rotateKey, isLoading } = useKeyVault();

  const [keys, setKeys] = useState<KeyData[]>([]);
  const [filterRole, setFilterRole] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [revealMap, setRevealMap] = useState<Record<string, boolean>>({});

  useEffect(() => {
    listKeys().then(setKeys);
  }, []);

  const filteredKeys = useMemo(() => {
    return keys.filter((key) => {
      const matchesRole = filterRole === 'all' || key.role === filterRole;
      const matchesStatus = filterStatus === 'all' || key.status === filterStatus;
      const matchesSearch = key.name.toLowerCase().includes(search.toLowerCase()) || key.id.includes(search);
      return matchesRole && matchesStatus && matchesSearch;
    });
  }, [keys, filterRole, filterStatus, search]);

  const toggleReveal = (keyId: string) => {
    setRevealMap((prev) => ({ ...prev, [keyId]: !prev[keyId] }));
  };

  const handleRevoke = async (keyId: string) => {
    await revokeKey(keyId);
    setKeys(await listKeys());
  };

  const handleRotate = async (keyId: string) => {
    await rotateKey(keyId);
    setKeys(await listKeys());
  };

  return (
    <Card className="w-full border bg-background/80 backdrop-blur-xl shadow-xl">
      <CardHeader className="flex flex-col md:flex-row justify-between gap-4 p-4">
        <div className="flex items-center gap-2">
          <KeyIcon className="w-5 h-5 text-primary" />
          <span className="text-lg font-semibold">Key Registry</span>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Input
            placeholder="Search by name or ID"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-48"
          />
          <Select value={filterRole} onValueChange={setFilterRole}>
            <SelectTrigger className="w-32">Role</SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="admin">Admin</SelectItem>
              <SelectItem value="operator">Operator</SelectItem>
              <SelectItem value="readonly">Readonly</SelectItem>
            </SelectContent>
          </Select>
          <Select value={filterStatus} onValueChange={setFilterStatus}>
            <SelectTrigger className="w-32">Status</SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="revoked">Revoked</SelectItem>
              <SelectItem value="expired">Expired</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>

      <CardContent className="space-y-4 px-4 pb-4">
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Array.from({ length: 6 }).map((_, idx) => (
              <Skeleton key={idx} className="h-[80px] w-full rounded-xl" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredKeys.map((key) => (
              <div
                key={key.id}
                className={`p-4 rounded-xl border bg-muted/30 hover:bg-accent/30 transition relative ${
                  key.status === 'revoked' ? 'opacity-60 pointer-events-none' : ''
                }`}
              >
                <div className="flex justify-between items-center">
                  <div className="font-medium text-sm">{key.name}</div>
                  <Badge variant="outline">{KeyRole[key.role]}</Badge>
                </div>
                <div className="text-xs mt-1 text-muted-foreground">
                  ID: {key.id.slice(0, 8)}...
                </div>
                <div className="text-xs mt-1 text-muted-foreground">
                  Created: {formatDate(key.createdAt)}
                </div>
                <div className="text-xs mt-1 text-muted-foreground">
                  Expires: {formatDate(key.expiresAt)}
                </div>
                <div className="mt-2 flex items-center justify-between gap-2">
                  <Button
                    size="xs"
                    variant="secondary"
                    onClick={() => toggleReveal(key.id)}
                  >
                    {revealMap[key.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </Button>
                  <Button
                    size="xs"
                    variant="outline"
                    onClick={() => handleRotate(key.id)}
                    disabled={key.status !== 'active'}
                  >
                    Rotate
                  </Button>
                  <Button
                    size="xs"
                    variant="destructive"
                    onClick={() => handleRevoke(key.id)}
                    disabled={key.status !== 'active'}
                  >
                    Revoke
                  </Button>
                </div>
                {revealMap[key.id] && (
                  <div className="mt-2 p-2 rounded-md bg-background text-xs break-all border border-dashed">
                    {key.secret}
                  </div>
                )}
                {key.flags?.includes('suspicious') && (
                  <div className="absolute top-2 right-2 text-red-500" title="Suspicious activity">
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
