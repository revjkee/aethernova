import React from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../ui/Button';

export const LanguageSwitcher: React.FC = () => {
  const { i18n } = useTranslation();

  const toggleLanguage = () => {
    const newLang = i18n.language === 'ru' ? 'en' : 'ru';
    i18n.changeLanguage(newLang);
  };

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={toggleLanguage}
      className="text-gray-600 hover:text-gray-900"
    >
      {i18n.language === 'ru' ? '🇺🇸 EN' : '🇷🇺 RU'}
    </Button>
  );
};