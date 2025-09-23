import React, { useEffect, useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  ReferenceLine,
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { useTheme } from '@/shared/hooks/useTheme';
import { cn } from '@/shared/utils/classnames';
import { ShieldAlert, UserCheck, LockKeyhole } from 'lucide-react';
import { fetchVaultUsageAnalytics } from '@/services/vault/analytics.service';
import { useSecureContext } from '@/platform-security/zero-trust/contextValidator';
import { useRoleAccess } from '@/shared/hooks/useRoleAccess';
import { ACCESS_POLICY } from '@/platform-security/rbac/policies';
import { AuditLogEvent } from '@/components/Vault/AuditLogEvent';

type VaultUsageEntry = {
  date: string;
  totalUsed: number;
  criticalKeys: number;
  sharedKeys: number;
  decryptedKeys: number;
};

const formatBytes = (bytes: number) =>
  bytes > 1024
    ? `${(bytes / 1024).toFixed(1)} KB`
    : `${bytes} B`;

export const VaultUsageGraph: React.FC = () => {
  const [data, setData] = useState<VaultUsageEntry[] | null>(null);
  const [loading, setLoading] = useState(true);
  const theme = useTheme();
  const { isContextTrusted } = useSecureContext();
  const hasAccess = useRoleAccess(ACCESS_POLICY.VIEW_USAGE_GRAPH);

  useEffect(() => {
    if (!hasAccess || !isContextTrusted) return;

    const loadData = async () => {
      try {
        const result = await fetchVaultUsageAnalytics();
        setData(result);
      } catch (e) {
        console.error('Failed to fetch vault usage data:', e);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [hasAccess, isContextTrusted]);

  const chartData = useMemo(() => {
    if (!data) return [];
    return data.map(entry => ({
      ...entry,
      tooltipLabel: `${entry.date} – ${formatBytes(entry.totalUsed)}`,
    }));
  }, [data]);

  if (!hasAccess) {
    return (
      <Card className="w-full p-6 text-center text-sm text-muted-foreground">
        <LockKeyhole className="mx-auto mb-2" />
        Нет доступа к графику использования хранилища.
      </Card>
    );
  }

  if (!isContextTrusted) {
    return (
      <Card className="w-full p-6 text-center text-sm text-red-500">
        <ShieldAlert className="mx-auto mb-2" />
        Потенциально небезопасная среда. Загрузка графика заблокирована Zero-Trust политикой.
      </Card>
    );
  }

  return (
    <Card className="w-full shadow-md border border-border/40 rounded-2xl">
      <CardHeader>
        <CardTitle className="text-xl font-semibold">
          Использование хранилища
        </CardTitle>
      </CardHeader>
      <CardContent className="h-[400px] px-2 sm:px-6 pb-4">
        {loading ? (
          <Skeleton className="w-full h-full rounded-lg" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.2} />
              <XAxis dataKey="date" tick={{ fontSize: 12 }} />
              <YAxis tickFormatter={formatBytes} />
              <Tooltip
                formatter={(value: number) => formatBytes(value)}
                labelFormatter={(label) => `Дата: ${label}`}
              />
              <Legend verticalAlign="top" height={36} />
              <ReferenceLine y={1024 * 1024} label="Порог 1MB" stroke="red" strokeDasharray="3 3" />
              <Bar dataKey="totalUsed" stackId="a" fill={theme === 'dark' ? '#4c6ef5' : '#3b82f6'} name="Общий объём" />
              <Bar dataKey="criticalKeys" stackId="a" fill="#e11d48" name="Критические ключи" />
              <Bar dataKey="sharedKeys" stackId="a" fill="#facc15" name="Общие ключи" />
              <Bar dataKey="decryptedKeys" stackId="a" fill="#10b981" name="Расшифрованные" />
            </BarChart>
          </ResponsiveContainer>
        )}
        <div className="mt-4">
          <AuditLogEvent
            component="VaultUsageGraph"
            event="render"
            info="Graph rendered in trusted context with RBAC policy"
          />
        </div>
      </CardContent>
    </Card>
  );
};

export default VaultUsageGraph;
