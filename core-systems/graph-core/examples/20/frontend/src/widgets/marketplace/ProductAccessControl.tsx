import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { toast } from 'react-hot-toast';
import { RoleSelector } from '@/widgets/Marketplace/components/RoleSelector';
import { FeatureFlagToggle } from '@/shared/components/FeatureFlagToggle';
import { AuditLogPanel } from '@/shared/components/AuditLogPanel';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { ErrorBoundary } from '@/shared/components/ErrorBoundary';
import { fetchProductAccessRules, updateProductAccessRules } from '@/services/api/accessAPI';
import { AccessControlRule, ProductAccessLevel } from '@/shared/types/access';
import { usePermission } from '@/shared/hooks/usePermission';
import { ConfirmModal } from '@/shared/components/ConfirmModal';

interface Props {
  productId: string;
  onUpdated?: () => void;
}

const ProductAccessControl: React.FC<Props> = ({ productId, onUpdated }) => {
  const [rules, setRules] = useState<AccessControlRule[]>([]);
  const [showConfirm, setShowConfirm] = useState(false);
  const [selectedRuleIndex, setSelectedRuleIndex] = useState<number | null>(null);
  const hasWriteAccess = usePermission('product:access:modify');

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['productAccessRules', productId],
    queryFn: () => fetchProductAccessRules(productId),
    refetchOnWindowFocus: false,
    staleTime: 1000 * 60 * 10,
  });

  useEffect(() => {
    if (data) {
      setRules(data);
    }
  }, [data]);

  const mutation = useMutation({
    mutationFn: (updated: AccessControlRule[]) => updateProductAccessRules(productId, updated),
    onSuccess: () => {
      toast.success('Правила доступа обновлены');
      onUpdated?.();
      refetch();
    },
    onError: () => {
      toast.error('Ошибка при обновлении доступа');
    },
  });

  const handleRoleChange = useCallback(
    (index: number, newRole: ProductAccessLevel) => {
      const updated = [...rules];
      updated[index].role = newRole;
      setRules(updated);
    },
    [rules]
  );

  const handleToggleFeatureFlag = useCallback(
    (index: number, enabled: boolean) => {
      const updated = [...rules];
      updated[index].featureFlag = enabled;
      setRules(updated);
    },
    [rules]
  );

  const handleDeleteRule = useCallback((index: number) => {
    setSelectedRuleIndex(index);
    setShowConfirm(true);
  }, []);

  const confirmDelete = () => {
    if (selectedRuleIndex === null) return;
    const updated = [...rules];
    updated.splice(selectedRuleIndex, 1);
    setRules(updated);
    setShowConfirm(false);
  };

  const handleSave = () => {
    mutation.mutate(rules);
  };

  const handleAddRule = () => {
    setRules([
      ...rules,
      {
        role: 'vip',
        featureFlag: false,
        createdBy: 'system',
        createdAt: new Date().toISOString(),
      },
    ]);
  };

  const renderRule = (rule: AccessControlRule, index: number) => (
    <div
      key={index}
      className="border rounded-lg p-4 flex flex-col sm:flex-row justify-between items-center gap-4 bg-gray-50 dark:bg-gray-800"
    >
      <RoleSelector
        value={rule.role}
        onChange={(role) => handleRoleChange(index, role)}
        disabled={!hasWriteAccess}
      />
      <FeatureFlagToggle
        label="Feature флаг"
        enabled={rule.featureFlag}
        onToggle={(enabled) => handleToggleFeatureFlag(index, enabled)}
        disabled={!hasWriteAccess}
      />
      <div className="flex gap-2 items-center text-sm text-muted-foreground">
        <span>Добавил: {rule.createdBy}</span>
        <span>{new Date(rule.createdAt).toLocaleString()}</span>
      </div>
      {hasWriteAccess && (
        <Button size="sm" variant="destructive" onClick={() => handleDeleteRule(index)}>
          Удалить
        </Button>
      )}
    </div>
  );

  return (
    <ErrorBoundary fallback="Ошибка отображения контроля доступа.">
      <div className="flex flex-col gap-6 w-full px-2 pb-4">
        <h2 className="text-xl font-semibold">Контроль доступа к товару</h2>

        {isLoading ? (
          <Spinner />
        ) : isError ? (
          <div className="text-red-600">Ошибка загрузки правил доступа</div>
        ) : (
          <>
            <div className="flex flex-col gap-3">
              {rules.map(renderRule)}
            </div>

            {hasWriteAccess && (
              <div className="flex gap-4 mt-4">
                <Button variant="outline" onClick={handleAddRule}>
                  Добавить правило
                </Button>
                <Button variant="primary" onClick={handleSave}>
                  Сохранить изменения
                </Button>
              </div>
            )}

            <AuditLogPanel resource={`product:${productId}`} />
          </>
        )}

        <ConfirmModal
          isOpen={showConfirm}
          title="Удалить правило доступа?"
          description="Вы уверены, что хотите удалить это правило? Оно будет удалено без возможности восстановления."
          onConfirm={confirmDelete}
          onCancel={() => setShowConfirm(false)}
        />
      </div>
    </ErrorBoundary>
  );
};

export default React.memo(ProductAccessControl);
