// src/widgets/Security/ZeroTrustAccessControl.tsx
import React, { useState, useEffect, useCallback } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableHead, TableBody, TableRow, TableCell } from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";
import { PolicyEditorModal } from "@/widgets/Security/PolicyEditorModal";
import { useZTNAAccess } from "@/hooks/security/useZTNAAccess";
import { useAuditLogger } from "@/hooks/logging/useAuditLogger";
import { AccessChip } from "@/components/security/AccessChip";
import { RoleSelector } from "@/components/security/RoleSelector";
import { cn } from "@/lib/utils";

export const ZeroTrustAccessControl: React.FC = () => {
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [showEditor, setShowEditor] = useState(false);
  const [isGlobalLockdown, setGlobalLockdown] = useState(false);

  const { policies, toggleAccess, refreshPolicies, applyPolicy } = useZTNAAccess();
  const { logAuditEvent } = useAuditLogger();

  useEffect(() => {
    logAuditEvent("ZTNA_VIEW_ACCESSES", "Панель доступа просмотрена");
  }, [logAuditEvent]);

  const filteredPolicies = policies.filter(p =>
    p.resource.toLowerCase().includes(search.toLowerCase()) ||
    p.roles.some(role => role.toLowerCase().includes(search.toLowerCase()))
  );

  const onToggleAccess = useCallback((policyId: string, enabled: boolean) => {
    toggleAccess(policyId, enabled);
    logAuditEvent("ZTNA_TOGGLE_POLICY", `Политика ${policyId} ${enabled ? "включена" : "отключена"}`);
  }, [toggleAccess, logAuditEvent]);

  const onOpenEditor = (policyId?: string) => {
    setSelectedPolicy(policyId ?? null);
    setShowEditor(true);
  };

  const onLockdownChange = (value: boolean) => {
    setGlobalLockdown(value);
    logAuditEvent("ZTNA_GLOBAL_LOCKDOWN", `Глобальный режим: ${value ? "включен" : "выключен"}`);
  };

  return (
    <Card className="shadow-xl bg-background w-full">
      <CardHeader className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-foreground">Zero Trust: Управление доступом</h2>
          <p className="text-sm text-muted-foreground">Гибкое распределение прав доступа и контроль поведения пользователей</p>
        </div>
        <div className="flex items-center gap-3">
          <Input
            placeholder="Поиск по ресурсу или роли..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="max-w-xs"
          />
          <Button onClick={() => onOpenEditor()} variant="default">
            + Новая политика
          </Button>
        </div>
      </CardHeader>

      <CardContent className="overflow-x-auto">
        <div className="mb-4 flex justify-end items-center gap-2">
          <span className="text-sm text-muted-foreground">Глобальный Lockdown</span>
          <Switch checked={isGlobalLockdown} onCheckedChange={onLockdownChange} />
        </div>

        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Ресурс</TableCell>
              <TableCell>Роли</TableCell>
              <TableCell>Политика</TableCell>
              <TableCell>Статус</TableCell>
              <TableCell className="text-right">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredPolicies.map((policy) => (
              <TableRow key={policy.id}>
                <TableCell className="font-medium">{policy.resource}</TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {policy.roles.map((r) => <AccessChip key={r} role={r} />)}
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant={policy.type === "deny" ? "destructive" : "default"}>
                    {policy.type.toUpperCase()}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Switch
                    checked={policy.enabled}
                    onCheckedChange={(val) => onToggleAccess(policy.id, val)}
                  />
                </TableCell>
                <TableCell className="text-right">
                  <Button size="sm" variant="outline" onClick={() => onOpenEditor(policy.id)}>
                    Редактировать
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>

      {showEditor && (
        <PolicyEditorModal
          policyId={selectedPolicy}
          onClose={() => {
            setShowEditor(false);
            refreshPolicies();
          }}
        />
      )}
    </Card>
  );
};
