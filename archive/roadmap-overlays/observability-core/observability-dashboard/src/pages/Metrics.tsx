import React from 'react';
import { useTranslation } from 'react-i18next';

const Metrics: React.FC = () => {
  const { t } = useTranslation();
  
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
        {t('metrics.title')}
      </h1>
      <div className="card">
        <p className="text-gray-600 dark:text-gray-400">
          {t('metrics.realTime')} и данные производительности будут отображаться здесь.
        </p>
      </div>
    </div>
  );
};

export default Metrics;