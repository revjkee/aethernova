import React, { useState, useCallback } from 'react';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { toast } from 'react-hot-toast';
import { useMutation } from '@tanstack/react-query';
import { runPrivacyAudit } from '@/services/api/privacyAuditAPI';
import { AuditLogPanel } from '@/shared/components/AuditLogPanel';
import { useTranslation } from 'react-i18next';
import { usePermission } from '@/shared/hooks/usePermission';
import { ShieldCheckIcon, ShieldAlertIcon, LoaderIcon, RefreshCcwIcon } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/shared/components/Dialog';

interface Props {
  userId: string;
  auditScope?: 'self' | 'full';
  size?: 'sm' | 'md';
  showLogs?: boolean;
}

const PrivacyAuditTriggerButton: React.FC<Props> = ({
  userId,
  auditScope = 'self',
  size = 'md',
  showLogs = true,
}) => {
  const { t } = useTranslation();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [auditResult, setAuditResult] = useState<string | null>(null);
  const canRunAudit = usePermission('privacy:audit:run');

  const auditMutation = useMutation({
    mutationFn: () => runPrivacyAudit({ userId, scope: auditScope }),
    onMutate: () => {
      toast.loading(t('privacy.audit.inProgress'), { id: 'audit' });
    },
    onSuccess: (result) => {
      toast.success(t('privacy.audit.success'), { id: 'audit' });
      setAuditResult(result.summary || null);
      setDialogOpen(true);
    },
    onError: (err: any) => {
      console.error(err);
      toast.error(t('privacy.audit.failed'), { id: 'audit' });
    },
  });

  const triggerAudit = useCallback(() => {
    if (!canRunAudit) {
      toast.error(t('privacy.audit.noPermission'));
      return;
    }
    auditMutation.mutate();
  }, [canRunAudit, auditMutation]);

  return (
    <>
      <Button
        variant="outline"
        size={size}
        disabled={auditMutation.isLoading}
        onClick={triggerAudit}
        icon={
          auditMutation.isLoading ? (
            <LoaderIcon className="animate-spin" size={16} />
          ) : (
            <RefreshCcwIcon size={16} />
          )
        }
      >
        {t('privacy.audit.trigger')}
      </Button>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogHeader>
          <ShieldCheckIcon className="text-green-600" size={20} />
          <DialogTitle>{t('privacy.audit.reportTitle')}</DialogTitle>
        </DialogHeader>

        <DialogContent>
          {auditResult ? (
            <div className="text-sm whitespace-pre-wrap leading-relaxed text-muted-foreground">
              {auditResult}
            </div>
          ) : (
            <div className="flex justify-center py-12">
              <Spinner />
            </div>
          )}
          {showLogs && (
            <div className="mt-6">
              <AuditLogPanel resource={`privacy:audit:${userId}`} />
            </div>
          )}
        </DialogContent>

        <DialogFooter className="justify-end">
          <Button variant="ghost" onClick={() => setDialogOpen(false)}>
            {t('privacy.audit.close')}
          </Button>
        </DialogFooter>
      </Dialog>
    </>
  );
};

export default React.memo(PrivacyAuditTriggerButton);
