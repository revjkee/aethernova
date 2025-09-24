import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { Select } from '@/shared/components/Select';
import { useFeatureFlag } from '@/shared/hooks/useFeatureFlag';
import { useTranslation } from 'react-i18next';
import { usePermission } from '@/shared/hooks/usePermission';
import { AuditLogPanel } from '@/shared/components/AuditLogPanel';
import { ConfirmModal } from '@/shared/components/ConfirmModal';
import { Button } from '@/shared/components/Button';
import { updatePrivacyLevel } from '@/services/api/privacyAPI';
import { toast } from 'react-hot-toast';
import { PrivacyLevel, PRIVACY_LEVELS } from '@/shared/constants/privacy';
import { getCurrentPrivacyLevel } from '@/services/api/privacyAPI';
import { ShieldLockIcon, ShieldCheckIcon, ShieldXIcon } from 'lucide-react';

interface Props {
  resourceId: string;
  resourceType: 'profile' | 'asset' | 'agent' | 'channel';
  showAudit?: boolean;
  allowDowngrade?: boolean;
  compact?: boolean;
}

const PrivacyLevelSelector: React.FC<Props> = ({
  resourceId,
  resourceType,
  showAudit = true,
  allowDowngrade = false,
  compact = false,
}) => {
  const { t } = useTranslation();
  const [currentLevel, setCurrentLevel] = useState<PrivacyLevel | null>(null);
  const [selectedLevel, setSelectedLevel] = useState<PrivacyLevel | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const rbacAllowed = usePermission('privacy:change');
  const zeroTrustEnforced = useFeatureFlag('privacy:zero-trust');

  const iconMap = {
    strict: <ShieldLockIcon className="text-red-600" size={16} />,
    default: <ShieldCheckIcon className="text-green-600" size={16} />,
    open: <ShieldXIcon className="text-yellow-600" size={16} />,
  };

  useEffect(() => {
    getCurrentPrivacyLevel(resourceType, resourceId)
      .then((level) => {
        setCurrentLevel(level);
        setSelectedLevel(level);
      })
      .catch(() => {
        toast.error(t('privacy.fetchError'));
      });
  }, [resourceId, resourceType, t]);

  const levelOptions = useMemo(() => {
    return PRIVACY_LEVELS.map((level) => ({
      label: t(`privacy.level.${level}`),
      value: level,
      icon: iconMap[level],
    }));
  }, [t]);

  const handleChange = useCallback(
    (level: PrivacyLevel) => {
      if (!rbacAllowed) {
        toast.error(t('privacy.noPermission'));
        return;
      }

      if (!allowDowngrade && level < (currentLevel ?? level)) {
        toast.error(t('privacy.noDowngrade'));
        return;
      }

      if (zeroTrustEnforced && level !== 'strict') {
        toast.error(t('privacy.zeroTrustEnforced'));
        return;
      }

      setSelectedLevel(level);
      setConfirmOpen(true);
    },
    [rbacAllowed, allowDowngrade, currentLevel, zeroTrustEnforced, t]
  );

  const confirmChange = async () => {
    if (!selectedLevel || selectedLevel === currentLevel) {
      setConfirmOpen(false);
      return;
    }

    try {
      await updatePrivacyLevel(resourceType, resourceId, selectedLevel);
      setCurrentLevel(selectedLevel);
      toast.success(t('privacy.levelUpdated'));
    } catch {
      toast.error(t('privacy.updateError'));
    } finally {
      setConfirmOpen(false);
    }
  };

  return (
    <div className={compact ? 'max-w-xs' : 'w-full'}>
      <div className="mb-2 font-medium text-sm text-muted-foreground">
        {t('privacy.selectorLabel')}
      </div>
      <Select
        value={selectedLevel}
        options={levelOptions}
        onChange={(val) => handleChange(val as PrivacyLevel)}
        disabled={!rbacAllowed}
        withIcons
      />
      {showAudit && (
        <div className="mt-4">
          <AuditLogPanel resource={`privacy:${resourceType}:${resourceId}`} maxEntries={5} />
        </div>
      )}
      <ConfirmModal
        isOpen={confirmOpen}
        title={t('privacy.confirmTitle')}
        description={t(`privacy.confirmDescription.${selectedLevel}`)}
        onConfirm={confirmChange}
        onCancel={() => setConfirmOpen(false)}
      />
    </div>
  );
};

export default React.memo(PrivacyLevelSelector);
