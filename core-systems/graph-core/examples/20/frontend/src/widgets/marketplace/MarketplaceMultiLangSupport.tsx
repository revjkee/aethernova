import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Select } from '@/shared/components/Select';
import { Button } from '@/shared/components/Button';
import { useFeatureFlag } from '@/shared/hooks/useFeatureFlag';
import { useLocaleSync } from '@/shared/hooks/useLocaleSync';
import { getUserPreferredLanguage, setUserPreferredLanguage } from '@/services/api/userSettingsAPI';
import { SupportedLanguages, LANGUAGE_OPTIONS } from '@/shared/constants/i18n';
import { AuditLogPanel } from '@/shared/components/AuditLogPanel';
import { toast } from 'react-hot-toast';
import { detectBrowserLanguage } from '@/shared/utils/locale';

interface Props {
  showTitle?: boolean;
  enableAudit?: boolean;
  compactMode?: boolean;
}

const MarketplaceMultiLangSupport: React.FC<Props> = ({ showTitle = true, enableAudit = true, compactMode = false }) => {
  const { i18n, t } = useTranslation();
  const [currentLang, setCurrentLang] = useState<SupportedLanguages | null>(null);
  const [loading, setLoading] = useState(false);
  const aiLocalizationEnabled = useFeatureFlag('i18n:ai-assisted');
  const autoDetectEnabled = useFeatureFlag('i18n:autodetect');

  useLocaleSync(); // ensure app state & html lang is synced

  useEffect(() => {
    const initLang = async () => {
      setLoading(true);
      try {
        const userLang = await getUserPreferredLanguage();
        const browserLang = detectBrowserLanguage();
        const resolvedLang = userLang || (autoDetectEnabled ? browserLang : 'en');
        i18n.changeLanguage(resolvedLang);
        setCurrentLang(resolvedLang as SupportedLanguages);
      } catch {
        i18n.changeLanguage('en');
        setCurrentLang('en');
      } finally {
        setLoading(false);
      }
    };
    initLang();
  }, [i18n, autoDetectEnabled]);

  const languageOptions = useMemo(() => {
    return LANGUAGE_OPTIONS.map((lang) => ({
      value: lang.code,
      label: `${lang.label} (${lang.native})`,
    }));
  }, []);

  const handleChange = useCallback(
    async (lang: string) => {
      if (!lang) return;
      try {
        await setUserPreferredLanguage(lang as SupportedLanguages);
        i18n.changeLanguage(lang);
        setCurrentLang(lang as SupportedLanguages);
        toast.success(t('i18n.languageChanged'));
      } catch {
        toast.error(t('i18n.languageChangeError'));
      }
    },
    [i18n, t]
  );

  return (
    <div className={compactMode ? 'w-full max-w-sm' : 'w-full p-4 border rounded-lg bg-white dark:bg-zinc-900'}>
      {showTitle && <h2 className="text-lg font-semibold mb-2">{t('i18n.languageSelectorTitle')}</h2>}

      {loading ? (
        <div className="text-muted-foreground text-sm">{t('i18n.loading')}</div>
      ) : (
        <Select
          label={t('i18n.selectLanguage')}
          value={currentLang || ''}
          options={languageOptions}
          onChange={handleChange}
        />
      )}

      {aiLocalizationEnabled && (
        <div className="text-xs mt-2 text-muted-foreground">
          {t('i18n.aiDisclaimer')}: {t('i18n.generatedByAI')}
        </div>
      )}

      {!compactMode && enableAudit && (
        <div className="mt-4">
          <AuditLogPanel resource="i18n:language-change" maxEntries={10} />
        </div>
      )}
    </div>
  );
};

export default React.memo(MarketplaceMultiLangSupport);
