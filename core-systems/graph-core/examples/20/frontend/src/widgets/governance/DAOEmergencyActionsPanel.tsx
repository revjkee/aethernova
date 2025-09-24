// src/widgets/Governance/DAOEmergencyActionsPanel.tsx

import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';
import { Dialog, DialogTrigger, DialogContent, DialogHeader, DialogFooter } from '@/components/ui/dialog';
import { Toggle } from '@/components/ui/toggle';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import {
  ShieldAlertIcon,
  ZapIcon,
  LoaderIcon,
  UserCheckIcon,
  AlertCircleIcon,
  ExternalLinkIcon
} from '@/components/icons';
import { validateEmergencyProtocol, triggerEmergencyAction } from '@/services/dao/emergency';
import { useCurrentUser } from '@/hooks/useCurrentUser';
import { cn } from '@/lib/utils';

interface EmergencyAction {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  requiresHumanApproval: boolean;
  aiRecommended: boolean;
}

export const DAOEmergencyActionsPanel: React.FC = () => {
  const [actions, setActions] = useState<EmergencyAction[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [reason, setReason] = useState('');
  const { toast } = useToast();
  const user = useCurrentUser();

  useEffect(() => {
    const availableActions: EmergencyAction[] = [
      {
        id: 'freezeTreasury',
        title: 'Заморозить казну',
        description: 'Блокирует все исходящие транзакции DAO до ручной разблокировки.',
        severity: 'critical',
        requiresHumanApproval: true,
        aiRecommended: true
      },
      {
        id: 'pauseGovernance',
        title: 'Приостановить голосования',
        description: 'Все голосования временно ставятся на паузу.',
        severity: 'high',
        requiresHumanApproval: true,
        aiRecommended: false
      },
      {
        id: 'isolateAgent',
        title: 'Изолировать агента',
        description: 'Отключает подозрительного агента от сети и задач.',
        severity: 'medium',
        requiresHumanApproval: false,
        aiRecommended: true
      },
      {
        id: 'revokeAccessKeys',
        title: 'Аннулировать ключи доступа',
        description: 'Удаляет подозрительные или скомпрометированные ключи.',
        severity: 'critical',
        requiresHumanApproval: true,
        aiRecommended: true
      },
      {
        id: 'activateZeroTrustLockdown',
        title: 'Zero-Trust блокировка',
        description: 'Перевод всех систем в sandbox режим и AI-мониторинг.',
        severity: 'critical',
        requiresHumanApproval: false,
        aiRecommended: true
      }
    ];
    setActions(availableActions);
  }, []);

  const toggleSelection = (id: string) => {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]
    );
  };

  const handleExecute = async () => {
    if (!selected.length || loading) return;

    setLoading(true);
    try {
      const isValid = await validateEmergencyProtocol(selected, user, reason);
      if (!isValid.success) {
        toast({
          variant: 'destructive',
          title: 'Ошибка верификации',
          description: isValid.message || 'Недостаточно прав или невалидный протокол.'
        });
        return;
      }

      const result = await triggerEmergencyAction(selected, user, reason);
      if (result.success) {
        toast({
          title: 'Аварийные действия инициированы',
          description: 'Результаты действий появятся в журнале через 10 сек.'
        });
        setSelected([]);
        setReason('');
      } else {
        throw new Error(result.message);
      }
    } catch (err: any) {
      toast({
        variant: 'destructive',
        title: 'Ошибка запуска',
        description: err.message || 'Что-то пошло не так.'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="border border-red-500/30 bg-red-50 dark:bg-red-900/10 p-6 rounded-xl space-y-5 shadow-lg">
      <div className="flex items-center gap-3 text-destructive font-semibold text-sm tracking-wide uppercase">
        <ShieldAlertIcon className="w-5 h-5" />
        ПАНЕЛЬ ЭКСТРЕННЫХ ДЕЙСТВИЙ DAO
      </div>

      <Alert className="bg-yellow-100 dark:bg-yellow-900/20 border-yellow-500/40">
        <AlertTitle className="flex items-center gap-2 text-sm font-semibold text-yellow-900 dark:text-yellow-100">
          <AlertCircleIcon className="w-4 h-4" />
          Предупреждение
        </AlertTitle>
        <AlertDescription className="text-xs text-muted-foreground">
          Действия будут зарегистрированы в immutable-журнале и требуют верификации протокола. Неправомерный запуск может быть зафиксирован как нарушение.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {actions.map((action) => (
          <Toggle
            key={action.id}
            pressed={selected.includes(action.id)}
            onPressedChange={() => toggleSelection(action.id)}
            className={cn(
              'flex flex-col items-start p-4 gap-2 rounded-lg border text-left transition text-sm font-medium shadow-sm',
              action.severity === 'critical' && 'border-red-500/80',
              action.severity === 'high' && 'border-orange-400/80',
              action.severity === 'medium' && 'border-yellow-400/80',
              selected.includes(action.id) && 'bg-red-100 dark:bg-red-900/30'
            )}
          >
            <div className="flex items-center gap-2">
              {action.aiRecommended && <ZapIcon className="w-4 h-4 text-blue-500" />}
              {action.requiresHumanApproval && <UserCheckIcon className="w-4 h-4 text-gray-500" />}
              {action.title}
            </div>
            <div className="text-xs text-muted-foreground">{action.description}</div>
          </Toggle>
        ))}
      </div>

      <Textarea
        placeholder="Причина вызова аварийного протокола (для аудита)..."
        className="text-xs"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        rows={3}
      />

      <Dialog>
        <DialogTrigger asChild>
          <Button
            disabled={!selected.length || loading}
            className="w-full"
            variant="destructive"
          >
            {loading ? <LoaderIcon className="animate-spin w-4 h-4" /> : 'Активировать аварийные действия'}
          </Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            Подтвердите активацию
          </DialogHeader>
          <div className="text-sm">
            Вы собираетесь активировать аварийные меры. Это действие необратимо.
          </div>
          <DialogFooter>
            <Button onClick={handleExecute} variant="destructive" disabled={loading}>
              Подтвердить и активировать
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};
