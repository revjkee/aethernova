import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useForm, Controller } from 'react-hook-form';
import { useQuery, useMutation } from '@tanstack/react-query';
import { toast } from 'react-hot-toast';
import { Input } from '@/shared/components/Input';
import { Button } from '@/shared/components/Button';
import { Select } from '@/shared/components/Select';
import { Spinner } from '@/shared/components/Spinner';
import { ConfirmModal } from '@/shared/components/ConfirmModal';
import { fetchTokenList, fetchSwapRate, executeTokenSwap, checkAllowance, approveToken } from '@/services/api/tokenSwapAPI';
import { getWalletAddress } from '@/shared/utils/wallet';
import { TokenInfo, TokenSwapRequest } from '@/shared/types/tokens';
import { useWallet } from '@/shared/hooks/useWallet';
import { formatAmount, parseAmount } from '@/shared/utils/amounts';

interface SwapForm {
  fromToken: string;
  toToken: string;
  amount: string;
}

interface Props {
  requiredToken: string;
  requiredAmount: string;
  onSuccess: () => void;
}

const MarketplaceTokenSwapPanel: React.FC<Props> = ({ requiredToken, requiredAmount, onSuccess }) => {
  const { account, isConnected, connect } = useWallet();
  const [availableTokens, setAvailableTokens] = useState<TokenInfo[]>([]);
  const [confirming, setConfirming] = useState(false);
  const [currentRate, setCurrentRate] = useState<string | null>(null);
  const [loadingRate, setLoadingRate] = useState(false);

  const {
    control,
    handleSubmit,
    watch,
    setValue,
    formState: { isValid, isSubmitting },
  } = useForm<SwapForm>({
    mode: 'onChange',
    defaultValues: {
      fromToken: '',
      toToken: requiredToken,
      amount: '',
    },
  });

  const watchFrom = watch('fromToken');
  const watchAmount = watch('amount');

  const { data: tokenList, isLoading: loadingTokens } = useQuery({
    queryKey: ['tokenList'],
    queryFn: fetchTokenList,
    staleTime: 1000 * 60 * 10,
  });

  useEffect(() => {
    if (tokenList) {
      setAvailableTokens(tokenList);
      if (!watchFrom) setValue('fromToken', tokenList[0]?.symbol || '');
    }
  }, [tokenList, setValue, watchFrom]);

  const fetchRate = useCallback(async () => {
    if (!watchFrom || !requiredToken || !watchAmount) return;
    setLoadingRate(true);
    try {
      const rate = await fetchSwapRate(watchFrom, requiredToken, watchAmount);
      setCurrentRate(rate);
    } catch {
      setCurrentRate(null);
    } finally {
      setLoadingRate(false);
    }
  }, [watchFrom, requiredToken, watchAmount]);

  useEffect(() => {
    fetchRate();
  }, [fetchRate]);

  const swapMutation = useMutation({
    mutationFn: (payload: TokenSwapRequest) => executeTokenSwap(payload),
    onSuccess: () => {
      toast.success('Обмен успешно выполнен');
      onSuccess();
    },
    onError: () => {
      toast.error('Обмен не удался');
    },
  });

  const onSubmit = async (values: SwapForm) => {
    if (!account) {
      toast.error('Кошелёк не подключен');
      return;
    }

    const hasAllowance = await checkAllowance(account, values.fromToken, parseAmount(values.amount));
    if (!hasAllowance) {
      const approved = await approveToken(account, values.fromToken);
      if (!approved) {
        toast.error('Ошибка при одобрении токена');
        return;
      }
    }

    const payload: TokenSwapRequest = {
      fromToken: values.fromToken,
      toToken: values.toToken,
      amount: parseAmount(values.amount),
      userAddress: account,
    };

    setConfirming(true);
    swapMutation.mutate(payload);
  };

  const tokenOptions = useMemo(
    () =>
      availableTokens
        .filter((t) => t.symbol !== requiredToken)
        .map((token) => ({
          label: `${token.symbol} (${token.name})`,
          value: token.symbol,
        })),
    [availableTokens, requiredToken]
  );

  return (
    <div className="border rounded-lg p-6 bg-white dark:bg-zinc-900 shadow-md w-full max-w-2xl mx-auto">
      <h2 className="text-xl font-semibold mb-4">Обмен токенов перед покупкой</h2>

      {!isConnected ? (
        <Button onClick={connect}>Подключить кошелёк</Button>
      ) : loadingTokens ? (
        <Spinner />
      ) : (
        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-4">
          <Controller
            name="fromToken"
            control={control}
            rules={{ required: true }}
            render={({ field }) => (
              <Select {...field} label="Токен для обмена" options={tokenOptions} disabled={isSubmitting} />
            )}
          />
          <Controller
            name="amount"
            control={control}
            rules={{
              required: true,
              validate: (v) => parseFloat(v) > 0 || 'Введите корректное значение',
            }}
            render={({ field, fieldState }) => (
              <Input
                {...field}
                type="number"
                min={0}
                step="any"
                label="Сумма обмена"
                error={fieldState.error?.message}
                disabled={isSubmitting}
              />
            )}
          />

          {loadingRate ? (
            <Spinner />
          ) : currentRate ? (
            <div className="text-sm text-muted-foreground">
              Курс обмена: 1 {watchFrom} ≈ {formatAmount(currentRate)} {requiredToken}
            </div>
          ) : (
            <div className="text-sm text-red-600">Курс недоступен</div>
          )}

          <div className="flex justify-end">
            <Button type="submit" disabled={!isValid || isSubmitting}>
              Обменять и продолжить
            </Button>
          </div>
        </form>
      )}

      <ConfirmModal
        isOpen={confirming}
        title="Подтвердите обмен"
        description="Подтвердите транзакцию в кошельке для завершения обмена."
        onCancel={() => setConfirming(false)}
        onConfirm={() => setConfirming(false)}
      />
    </div>
  );
};

export default React.memo(MarketplaceTokenSwapPanel);
