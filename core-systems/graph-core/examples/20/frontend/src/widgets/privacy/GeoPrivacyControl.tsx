import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useFeatureFlag } from '@/shared/hooks/useFeatureFlag';
import { usePermission } from '@/shared/hooks/usePermission';
import { fetchGeoPrivacySettings, updateGeoPrivacySettings } from '@/services/api/privacyAPI';
import { toast } from 'react-hot-toast';
import { Select } from '@/shared/components/Select';
import { Input } from '@/shared/components/Input';
import { Switch } from '@/shared/components/Switch';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { ConfirmModal } from '@/shared/components/ConfirmModal';
import { AuditLogPanel } from '@/shared/components/AuditLogPanel';
import { GeoPrivacyLevel, GEO_PRIVACY_OPTIONS } from '@/shared/constants/privacy';
import { MapPreview } from '@/widgets/Privacy/components/MapPreview';
import { useLocationStatus } from '@/shared/hooks/useLocationStatus';

interface Props {
  userId: string;
  showAudit?: boolean;
}

const GeoPrivacyControl: React.FC<Props> = ({ userId, showAudit = true }) => {
  const { t } = useTranslation();
  const [geoLevel, setGeoLevel] = useState<GeoPrivacyLevel>('disabled');
  const [customRegion, setCustomRegion] = useState<string>('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pendingLevel, setPendingLevel] = useState<GeoPrivacyLevel | null>(null);
  const [loading, setLoading] = useState(true);
  const zeroTrust = useFeatureFlag('privacy:geo:zero-trust');
  const allowGeoEdit = usePermission('geo:privacy:update');
  const { locationEnabled, coordinates } = useLocationStatus();

  useEffect(() => {
    fetchGeoPrivacySettings(userId)
      .then((settings) => {
        setGeoLevel(settings.level);
        setCustomRegion(settings.customRegion || '');
      })
      .catch(() => {
        toast.error(t('privacy.geo.loadError'));
      })
      .finally(() => setLoading(false));
  }, [userId, t]);

  const handleChangeLevel = (newLevel: GeoPrivacyLevel) => {
    if (!allowGeoEdit) {
      toast.error(t('privacy.noPermission'));
      return;
    }

    if (zeroTrust && newLevel !== 'disabled') {
      toast.error(t('privacy.geo.zeroTrustBlocked'));
      return;
    }

    if (newLevel !== geoLevel) {
      setPendingLevel(newLevel);
      setConfirmOpen(true);
    }
  };

  const confirmChange = async () => {
    if (!pendingLevel) return;
    try {
      await updateGeoPrivacySettings(userId, {
        level: pendingLevel,
        customRegion: pendingLevel === 'region' ? customRegion : '',
      });
      setGeoLevel(pendingLevel);
      toast.success(t('privacy.geo.updated'));
    } catch {
      toast.error(t('privacy.geo.updateError'));
    } finally {
      setConfirmOpen(false);
      setPendingLevel(null);
    }
  };

  const privacyOptions = useMemo(() => {
    return GEO_PRIVACY_OPTIONS.map((option) => ({
      label: t(`privacy.geo.level.${option}`),
      value: option,
    }));
  }, [t]);

  const handleRegionChange = useCallback((value: string) => {
    setCustomRegion(value);
  }, []);

  const renderCustomRegionInput = () => {
    if (geoLevel !== 'region') return null;
    return (
      <Input
        label={t('privacy.geo.regionLabel')}
        placeholder={t('privacy.geo.regionPlaceholder')}
        value={customRegion}
        onChange={(e) => handleRegionChange(e.target.value)}
        disabled={!allowGeoEdit}
      />
    );
  };

  return (
    <div className="w-full max-w-2xl p-4 border rounded-lg bg-white dark:bg-zinc-900 shadow-sm">
      <h2 className="text-xl font-semibold mb-4">{t('privacy.geo.title')}</h2>

      {loading ? (
        <Spinner />
      ) : (
        <div className="flex flex-col gap-4">
          <Select
            label={t('privacy.geo.levelSelect')}
            value={geoLevel}
            options={privacyOptions}
            onChange={(val) => handleChangeLevel(val as GeoPrivacyLevel)}
            disabled={!allowGeoEdit}
          />

          {renderCustomRegionInput()}

          {geoLevel !== 'disabled' && (
            <div className="text-sm text-muted-foreground">
              {locationEnabled
                ? t('privacy.geo.gpsActive')
                : t('privacy.geo.gpsInactive')}
            </div>
          )}

          {coordinates && geoLevel !== 'disabled' && (
            <MapPreview lat={coordinates.lat} lng={coordinates.lng} />
          )}
        </div>
      )}

      {showAudit && (
        <div className="mt-6">
          <AuditLogPanel resource={`geo:privacy:${userId}`} />
        </div>
      )}

      <ConfirmModal
        isOpen={confirmOpen}
        title={t('privacy.geo.confirmTitle')}
        description={t(`privacy.geo.confirmDescription.${pendingLevel}`)}
        onCancel={() => setConfirmOpen(false)}
        onConfirm={confirmChange}
      />
    </div>
  );
};

export default React.memo(GeoPrivacyControl);
