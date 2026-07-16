import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';

export const useDefaultLanguage = () => {
  const { i18n } = useTranslation();

  useEffect(() => {
    // Устанавливаем русский язык по умолчанию, если язык не задан
    const savedLanguage = localStorage.getItem('i18nextLng');
    if (!savedLanguage) {
      i18n.changeLanguage('ru');
    }
  }, [i18n]);
};