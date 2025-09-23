import React, { useCallback, useEffect, useMemo, useState, Suspense } from 'react';
import { useForm, Controller } from 'react-hook-form';
import { useMutation, useQuery } from '@tanstack/react-query';
import { debounce } from 'lodash';
import { toast } from 'react-hot-toast';
import { Input } from '@/shared/components/Input';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { Modal } from '@/shared/components/Modal';
import { validateQuantity, validateStatus } from '@/shared/utils/validators';
import { updateInventory, fetchInventoryById } from '@/services/api/productAPI';
import { InventoryItem, ProductStatus } from '@/shared/types/inventory';
import { hasPermission } from '@/shared/utils/permissions';

interface Props {
  productId: string;
  onClose: () => void;
  onUpdated?: () => void;
}

const ProductInventoryEditor: React.FC<Props> = ({ productId, onClose, onUpdated }) => {
  const [initialState, setInitialState] = useState<InventoryItem | null>(null);
  const [isReadOnly, setIsReadOnly] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ['inventory', productId],
    queryFn: () => fetchInventoryById(productId),
    staleTime: 5000,
  });

  const {
    control,
    handleSubmit,
    reset,
    watch,
    formState: { isDirty, isSubmitting },
  } = useForm<InventoryItem>({
    mode: 'onBlur',
    defaultValues: useMemo(() => initialState || {}, [initialState]),
  });

  const mutation = useMutation({
    mutationFn: (data: InventoryItem) => updateInventory(productId, data),
    onSuccess: () => {
      toast.success('Инвентарь успешно обновлён');
      onUpdated?.();
      onClose();
    },
    onError: () => {
      toast.error('Ошибка обновления инвентаря');
    },
  });

  useEffect(() => {
    if (data) {
      setInitialState(data);
      reset(data);
    }
  }, [data, reset]);

  useEffect(() => {
    setIsReadOnly(!hasPermission('inventory:write'));
  }, []);

  const onSubmit = useCallback(
    (values: InventoryItem) => {
      if (!isDirty) return;
      mutation.mutate(values);
    },
    [isDirty, mutation]
  );

  const debouncedSubmit = useMemo(() => debounce(onSubmit, 300), [onSubmit]);

  const quantity = watch('quantity');
  const status = watch('status');

  useEffect(() => {
    if (!isReadOnly && quantity != null && status) {
      debouncedSubmit({ ...watch() });
    }
  }, [quantity, status, debouncedSubmit, isReadOnly, watch]);

  return (
    <Modal title="Редактирование инвентаря" onClose={onClose} maxWidth="md">
      {isLoading || !initialState ? (
        <div className="flex justify-center items-center h-48">
          <Spinner />
        </div>
      ) : (
        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-4 px-2 py-2">
          <Controller
            name="quantity"
            control={control}
            rules={{ validate: validateQuantity }}
            render={({ field, fieldState }) => (
              <Input
                label="Количество"
                type="number"
                min={0}
                {...field}
                error={fieldState.error?.message}
                disabled={isReadOnly}
              />
            )}
          />
          <Controller
            name="status"
            control={control}
            rules={{ validate: validateStatus }}
            render={({ field, fieldState }) => (
              <Input
                label="Статус"
                {...field}
                error={fieldState.error?.message}
                disabled={isReadOnly}
              />
            )}
          />

          <div className="flex justify-between mt-6">
            <Button type="button" variant="secondary" onClick={onClose}>
              Отмена
            </Button>
            <Button type="submit" disabled={!isDirty || isSubmitting || isReadOnly}>
              Сохранить
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
};

export default React.memo(ProductInventoryEditor);
