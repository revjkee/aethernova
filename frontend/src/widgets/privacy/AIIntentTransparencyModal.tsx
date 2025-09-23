import React, { useEffect, useMemo, useState } from 'react';
import { Dialog, DialogHeader, DialogTitle, DialogContent, DialogFooter } from '@/shared/components/Dialog';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { RiskLevelBadge } from '@/widgets/Privacy/components/RiskLevelBadge';
import { useTranslation } from 'react-i18next';
import { getAIIntentExplanation, rejectAIIntent } from '@/services/api/aiIntentAPI';
import { IntentExplanation } from '@/shared/types/privacy';
import { CopyButton } from '@/shared/components/CopyButton';
import { Tooltip } from '@/shared/components/Tooltip';
import { usePermission } from '@/shared/hooks/usePermission';
import { TraceButton } from '@/widgets/Privacy/components/TraceButton';
import { AiIcon, ShieldXIcon, BookOpenCheckIcon, BrainCogIcon } from 'lucide-react';

interface Props {
  intentId: string;
  isOpen: boolean;
  onClose: () => void;
  autoApprove?: boolean;
}

const AIIntentTransparencyModal: React.FC<Props> = ({ intentId, isOpen, onClose, autoApprove = false }) => {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [intent, setIntent] = useState<IntentExplanation | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const allowReject = usePermission('ai:intent:reject');

  useEffect(() => {
    if (!intentId || !isOpen) return;
    setLoading(true);
    getAIIntentExplanation(intentId)
      .then(setIntent)
      .catch(() => setIntent(null))
      .finally(() => setLoading(false));
  }, [intentId, isOpen]);

  const handleReject = async () => {
    if (!intent || !intentId) return;
    setSubmitting(true);
    try {
      await rejectAIIntent(intentId);
      onClose();
    } catch {
      // Silent fail with UX notification handled elsewhere
    } finally {
      setSubmitting(false);
    }
  };

  const renderItem = (label: string, value: React.ReactNode) => (
    <div className="flex flex-col gap-0.5">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-sm">{value}</div>
    </div>
  );

  const fields = useMemo(() => {
    if (!intent) return [];
    return [
      renderItem(t('privacy.intentModal.intentType'), <Badge>{intent.intentType}</Badge>),
      renderItem(t('privacy.intentModal.module'), <Tooltip content={intent.module}><span>{intent.module}</span></Tooltip>),
      renderItem(t('privacy.intentModal.dataUsed'), <span>{intent.dataType}</span>),
      renderItem(t('privacy.intentModal.purpose'), <span>{intent.purpose}</span>),
      renderItem(t('privacy.intentModal.reasoning'), <span>{intent.reasoning}</span>),
      renderItem(t('privacy.intentModal.alternatives'), <span>{intent.alternatives || t('privacy.intentModal.none')}</span>),
      renderItem(t('privacy.intentModal.timestamp'), <span>{new Date(intent.timestamp).toLocaleString()}</span>),
      renderItem(t('privacy.intentModal.trace'), <TraceButton traceId={intent.traceId} />),
    ];
  }, [intent, t]);

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogHeader className="flex items-center gap-2">
        <AiIcon size={20} className="text-blue-600" />
        <DialogTitle>{t('privacy.intentModal.title')}</DialogTitle>
      </DialogHeader>

      <DialogContent>
        {loading ? (
          <div className="flex justify-center items-center h-48">
            <Spinner />
          </div>
        ) : intent ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {fields}
            <div className="flex flex-col gap-0.5">
              <div className="text-xs text-muted-foreground">{t('privacy.intentModal.risk')}</div>
              <RiskLevelBadge level={intent.riskLevel} />
            </div>
            <div className="flex flex-col gap-0.5">
              <div className="text-xs text-muted-foreground">{t('privacy.intentModal.intentId')}</div>
              <CopyButton text={intentId} />
            </div>
          </div>
        ) : (
          <div className="text-red-600 text-sm text-center">{t('privacy.intentModal.failedToLoad')}</div>
        )}
      </DialogContent>

      <DialogFooter className="flex justify-between items-center">
        {allowReject && (
          <Button
            variant="destructive"
            onClick={handleReject}
            disabled={submitting || loading}
            icon={<ShieldXIcon size={16} />}
          >
            {t('privacy.intentModal.reject')}
          </Button>
        )}
        <Button
          variant="ghost"
          onClick={onClose}
          icon={<BookOpenCheckIcon size={16} />}
        >
          {t('privacy.intentModal.acknowledge')}
        </Button>
      </DialogFooter>
    </Dialog>
  );
};

export default React.memo(AIIntentTransparencyModal);
