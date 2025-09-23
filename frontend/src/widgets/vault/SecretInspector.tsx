import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Select, SelectTrigger, SelectContent, SelectItem } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { ShieldCheck, Lock, Eye, EyeOff, KeyRound, AlertTriangle } from 'lucide-react';

import { useVaultAccess } from '@/services/vault/useVaultAccess';
import { useSession } from '@/core/hooks/useSession';
import { formatDate } from '@/lib/utils/format';
import { decryptSecret } from '@/lib/security/decryptor';
import { SecretData } from '@/types/secrets';

export const SecretInspector: React.FC = () => {
  const { user } = useSession();
  const { fetchSecrets, logAccess } = useVaultAccess();

  const [secrets, setSecrets] = useState<SecretData[]>([]);
  const [filteredSecrets, setFilteredSecrets] = useState<SecretData[]>([]);
  const [search, setSearch] = useState('');
  const [filterScope, setFilterScope] = useState('all');
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [decrypted, setDecrypted] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadSecrets();
  }, []);

  const loadSecrets = async () => {
    setLoading(true);
    const data = await fetchSecrets();
    setSecrets(data);
    setLoading(false);
  };

  useEffect(() => {
    const filtered = secrets.filter((secret) => {
      const matchesSearch =
        secret.label.toLowerCase().includes(search.toLowerCase()) ||
        secret.id.includes(search) ||
        secret.metadata?.origin?.toLowerCase()?.includes(search.toLowerCase());
      const matchesScope = filterScope === 'all' || secret.scope === filterScope;
      return matchesSearch && matchesScope;
    });
    setFilteredSecrets(filtered);
  }, [search, secrets, filterScope]);

  const toggleReveal = async (id: string, encrypted: string) => {
    if (!revealed[id]) {
      try {
        const plaintext = await decryptSecret(encrypted);
        setDecrypted((prev) => ({ ...prev, [id]: plaintext }));
        logAccess({ userId: user.id, secretId: id, action: 'view' });
      } catch {
        setDecrypted((prev) => ({ ...prev, [id]: '[Decryption Failed]' }));
      }
    }
    setRevealed((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <Card className="w-full bg-background/80 backdrop-blur-lg border shadow-xl">
      <CardHeader className="flex flex-col md:flex-row justify-between items-center gap-4 p-4">
        <div className="flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-primary" />
          <span className="text-lg font-semibold">Secret Inspector</span>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Input
            placeholder="Search label or origin"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-60"
          />
          <Select value={filterScope} onValueChange={setFilterScope}>
            <SelectTrigger className="w-40">Scope</SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="env">Environment</SelectItem>
              <SelectItem value="user">User-Specific</SelectItem>
              <SelectItem value="system">System</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>

      <CardContent className="space-y-4 px-4 pb-6">
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[...Array(6)].map((_, i) => (
              <Skeleton key={i} className="h-[90px] w-full rounded-xl" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredSecrets.map((secret) => (
              <div
                key={secret.id}
                className="p-4 border rounded-xl bg-muted/40 hover:bg-muted/30 transition relative"
              >
                <div className="flex justify-between items-center">
                  <div className="text-sm font-medium">{secret.label}</div>
                  <Badge variant="outline">{secret.scope}</Badge>
                </div>
                <div className="text-xs text-muted-foreground mt-1">ID: {secret.id.slice(0, 10)}...</div>
                <div className="text-xs text-muted-foreground mt-1">
                  Origin: {secret.metadata?.origin || 'N/A'}
                </div>
                <div className="text-xs mt-1 text-muted-foreground">
                  Last Updated: {formatDate(secret.updatedAt)}
                </div>
                <div className="mt-3 flex items-center justify-between">
                  <Button
                    size="xs"
                    variant="secondary"
                    onClick={() => toggleReveal(secret.id, secret.encrypted)}
                  >
                    {revealed[secret.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </Button>
                  <Badge
                    variant={secret.flags?.includes('sensitive') ? 'destructive' : 'default'}
                    className="text-[10px]"
                  >
                    {secret.flags?.includes('sensitive') ? 'Sensitive' : 'Normal'}
                  </Badge>
                </div>
                {revealed[secret.id] && (
                  <div className="mt-2 p-2 bg-background rounded-md border text-xs break-words max-h-[140px] overflow-auto">
                    {decrypted[secret.id] || '[Loading...]'}
                  </div>
                )}
                {secret.flags?.includes('sensitive') && (
                  <div className="absolute top-2 right-2" title="Sensitive data">
                    <AlertTriangle className="text-yellow-600 w-4 h-4" />
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
