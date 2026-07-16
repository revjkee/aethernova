import React from 'react';
import { useTranslation } from 'react-i18next';
import { Globe, Palette, Bell } from 'lucide-react';

const Settings: React.FC = () => {
  const { t, i18n } = useTranslation();

  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
        {t('settings.title')}
      </h1>
      
      {/* Language Settings */}
      <div className="card">
        <div className="flex items-center space-x-3 mb-4">
          <Globe className="h-6 w-6 text-blue-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {t('settings.language')}
          </h3>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <button
            onClick={() => changeLanguage('en')}
            className={`p-4 rounded-lg border-2 transition-colors ${
              i18n.language === 'en'
                ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                : 'border-gray-300 dark:border-gray-600 hover:border-gray-400'
            }`}
          >
            <div className="text-left">
              <p className="font-medium text-gray-900 dark:text-white">English</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">EN</p>
            </div>
          </button>
          <button
            onClick={() => changeLanguage('ru')}
            className={`p-4 rounded-lg border-2 transition-colors ${
              i18n.language === 'ru'
                ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                : 'border-gray-300 dark:border-gray-600 hover:border-gray-400'
            }`}
          >
            <div className="text-left">
              <p className="font-medium text-gray-900 dark:text-white">Русский</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">РU</p>
            </div>
          </button>
        </div>
      </div>

      {/* Appearance Settings */}
      <div className="card">
        <div className="flex items-center space-x-3 mb-4">
          <Palette className="h-6 w-6 text-purple-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {t('settings.appearance')}
          </h3>
        </div>
        <p className="text-gray-600 dark:text-gray-400">
          Настройки внешнего вида и темы будут добавлены в будущих версиях.
        </p>
      </div>

      {/* Notifications Settings */}
      <div className="card">
        <div className="flex items-center space-x-3 mb-4">
          <Bell className="h-6 w-6 text-green-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {t('settings.notifications')}
          </h3>
        </div>
        <p className="text-gray-600 dark:text-gray-400">
          Настройки уведомлений и оповещений будут добавлены в будущих версиях.
        </p>
      </div>
    </div>
  );
};

export default Settings;