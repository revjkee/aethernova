import React, { useEffect, useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchAvailableLanguages, saveUserLanguagePreference } from '@/services/api/langAPI';
import { Button } from '@/shared/components/Button';
import { cn } from '@/shared/utils/cn';

interface Language {
  code: string;
  name: string;
  rtl: boolean;
  nativeName?: string;
}

interface Props {
  userId: string;
  currentLang: string;
  onLanguageChange?: (langCode: string) => void;
  className?: string;
}

const MultilangEduSupport: React.FC<Props> = ({ userId, currentLang, onLanguageChange, className }) => {
  const { t, i18n } = useTranslation();

  const [languages, setLanguages] = useState<Language[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedLang, setSelectedLang] = useState(currentLang);

  // Загрузка доступных языков
  useEffect(() => {
    let cancelled = false;
    const loadLanguages = async () => {
      setLoading(true);
      setError(null);
      try {
        const langs = await fetchAvailableLanguages();
        if (!cancelled) setLanguages(langs);
      } catch {
        if (!cancelled) setError(t('edu.multilang.loadError'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    loadLanguages();
    return () => {
      cancelled = true;
    };
  }, [t]);

  // Обработка смены языка
  const handleChangeLanguage = useCallback(
    async (langCode: string) => {
      setSelectedLang(langCode);
      try {
        await saveUserLanguagePreference(userId, langCode);
      } catch {
        // Игнорируем ошибки сохранения, можно логировать
      }
      i18n.changeLanguage(langCode);
      onLanguageChange?.(langCode);
      // Управление направлением текста
      const lang = languages.find((l) => l.code === langCode);
      if (lang) {
        document.documentElement.dir = lang.rtl ? 'rtl' : 'ltr';
      }
    },
    [userId, i18n, onLanguageChange, languages]
  );

  useEffect(() => {
    // При инициализации устанавливаем правильное направление
    const lang = languages.find((l) => l.code === selectedLang);
    if (lang) {
      document.documentElement.dir = lang.rtl ? 'rtl' : 'ltr';
    }
  }, [languages, selectedLang]);

  if (loading) {
    return (
      <div className={cn('flex justify-center p-6', className)} role="status" aria-live="polite">
        <span className="animate-spin rounded-full h-10 w-10 border-b-2 border-indigo-600" />
        <span className="sr-only">{t('edu.multilang.loading')}</span>
      </div>
    );
  }

  if (error) {
    return (
      <div
        className={cn('text-red-600 dark:text-red-400 text-center p-4', className)}
        role="alert"
        aria-live="assertive"
      >
        {error}
      </div>
    );
  }

  return (
    <section
      className={cn('flex flex-wrap gap-3 justify-center', className)}
      aria-label={t('edu.multilang.ariaLabel')}
    >
      {languages.map(({ code, name, rtl, nativeName }) => {
        const isSelected = code === selectedLang;
        return (
          <Button
            key={code}
            variant={isSelected ? 'primary' : 'outline'}
            onClick={() => handleChangeLanguage(code)}
            aria-pressed={isSelected}
            aria-label={t('edu.multilang.selectLanguage', { language: nativeName || name })}
            className={cn(
              'min-w-[96px] px-3 py-2 rounded shadow-sm',
              rtl ? 'font-arabic' : 'font-sans'
            )}
          >
            {nativeName || name}
          </Button>
        );
      })}
    </section>
  );
};

export default React.memo(MultilangEduSupport);
