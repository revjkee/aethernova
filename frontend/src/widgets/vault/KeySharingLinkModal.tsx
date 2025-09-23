import React, { useState, useCallback, useEffect } from 'react';
import { Dialog, DialogHeader, DialogBody, DialogFooter } from '@/shared/components/Dialog';
import { Input } from '@/shared/components/Input';
import { Button } from '@/shared/components/Button';
import { Select } from '@/shared/components/Select';
import { Alert } from '@/shared/components/Alert';
import { Spinner } from '@/shared/components/Spinner';
import { useTranslation } from 'react-i18next';
import { generateSecureShareLink } from '@/services/security/keyExchangeService';
import { useAuditLog } from '@/services/logging/auditLogger';
import { classNames } from '@/shared/utils/classNames';
import { useClipboard } from '@/shared/hooks/useClipboard';
import { Tooltip } from '@/shared/components/Tooltip';
import { Copy } from 'lucide-react';
import { motion } from 'framer-motion';
import { useRBAC } from '@/shared/hooks/useRBAC';

interface KeySharingLinkModalProps {
  isOpen: boolean;
  onClose: () => void;
  objectId: string;
  keyId: string;
}

export const KeySharingLinkModal: React.FC<KeySharingLinkModalProps> = ({
  isOpen,
  onClose,
  objectId,
  keyId,
}) => {
  const { t } = useTranslation();
  const { logAction } = useAuditLog();
  const { copyToClipboard, isCopied } = useClipboard();
  const { hasPermission } = useRBAC();

  const [ttl, setTtl] = useState<number>(3600);
  const [usageLimit, setUsageLimit] = useState<number>(1);
  const [link, setLink] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const canShare = hasPermission('vault.share.key');

  const handleGenerate = useCallback(async () => {
    setIsGenerating(true);
    setError(null);
    setLink(null);

    try {
      const generated = await generateSecureShareLink({
        objectId,
        keyId,
        ttl,
        usageLimit,
      });

      setLink(generated);
      logAction('key_share_link_created', {
        objectId,
        keyId,
        ttl,
        usageLimit,
        method: 'modal',
        timestamp: new Date().toISOString(),
      });
    } catch (e) {
      setError(t('vault.share.error_generating'));
    } finally {
      setIsGenerating(false);
    }
  }, [objectId, keyId, ttl, usageLimit, t, logAction]);

  useEffect(() => {
    if (!isOpen) {
      setTtl(3600);
      setUsageLimit(1);
      setLink(null);
      setError(null);
    }
  }, [isOpen]);

  return (
    <Dialog isOpen={isOpen} onClose={onClose} size="md" ariaLabel="key-sharing-modal">
      <DialogHeader title={t('vault.share.title')} />

      <DialogBody>
        {!canShare ? (
          <Alert type="error" message={t('vault.share.no_permission')} />
        ) : (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('vault.share.expire_in')}
              </label>
              <Select
                value={ttl}
                onChange={(e) => setTtl(Number(e.target.value))}
                options={[
                  { value: 600, label: t('vault.share.10_min') },
                  { value: 3600, label: t('vault.share.1_hour') },
                  { value: 86400, label: t('vault.share.1_day') },
                  { value: 604800, label: t('vault.share.1_week') },
                ]}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('vault.share.usage_limit')}
              </label>
              <Input
                type="number"
                value={usageLimit}
                min={1}
                max={100}
                onChange={(e) => setUsageLimit(Number(e.target.value))}
              />
            </div>

            {error && <Alert type="error" message={error} />}
            {isGenerating && <Spinner label={t('vault.share.generating')} />}
            {link && (
              <motion.div
                initial={{ opacity: 0, y: -5 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex items-center justify-between bg-gray-100 dark:bg-gray-800 p-3 rounded shadow border dark:border-gray-600"
              >
                <div className="text-xs break-all text-gray-700 dark:text-gray-200 w-full mr-2">
                  {link}
                </div>
                <Tooltip content={isCopied ? t('vault.share.copied') : t('vault.share.copy')}>
                  <button
                    className="p-1 text-gray-700 dark:text-gray-300 hover:text-blue-500"
                    onClick={() => copyToClipboard(link)}
                    aria-label="copy-link"
                  >
                    <Copy size={16} />
                  </button>
                </Tooltip>
              </motion.div>
            )}
          </div>
        )}
      </DialogBody>

      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>
          {t('common.cancel')}
        </Button>
        <Button
          onClick={handleGenerate}
          disabled={!canShare || isGenerating}
          variant="primary"
        >
          {t('vault.share.generate_link')}
        </Button>
      </DialogFooter>
    </Dialog>
  );
};

export default KeySharingLinkModal;
