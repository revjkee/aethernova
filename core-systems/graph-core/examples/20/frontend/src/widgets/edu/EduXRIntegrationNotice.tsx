import React, { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { checkXRSupport, fetchXRCourseStatus } from '@/services/api/xrAPI';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { cn } from '@/shared/utils/cn';

interface Props {
  courseId: string;
  className?: string;
}

type XRSupportStatus = 'supported' | 'unsupported' | 'checking' | 'partial' | 'unknown';

const EduXRIntegrationNotice: React.FC<Props> = ({ courseId, className }) => {
  const { t } = useTranslation();

  const [xrStatus, setXrStatus] = useState<XRSupportStatus>('checking');
  const [deviceCapabilities, setDeviceCapabilities] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [courseSupportsXR, setCourseSupportsXR] = useState<boolean>(false);

  const checkSupport = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const deviceCaps = await checkXRSupport();
      const courseXR = await fetchXRCourseStatus(courseId);
      setDeviceCapabilities(deviceCaps);
      setCourseSupportsXR(courseXR);
      if (deviceCaps.length === 0) setXrStatus('unsupported');
      else if (!courseXR) setXrStatus('unsupported');
      else if (deviceCaps.includes('full-xr')) setXrStatus('supported');
      else setXrStatus('partial');
    } catch {
      setXrStatus('unknown');
      setError(t('edu.xrIntegration.error'));
    } finally {
      setLoading(false);
    }
  }, [courseId, t]);

  useEffect(() => {
    checkSupport();
  }, [checkSupport]);

  if (loading) {
    return (
      <div
        role="status"
        aria-live="polite"
        className={cn('p-6 bg-indigo-100 dark:bg-indigo-900 text-indigo-800 dark:text-indigo-300 rounded-md text-center', className)}
      >
        <Spinner size="lg" />
        <p className="mt-2">{t('edu.xrIntegration.checking')}</p>
      </div>
    );
  }

  if (error) {
    return (
      <div
        role="alert"
        aria-live="assertive"
        className={cn('p-4 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded-md text-center', className)}
      >
        {error}
        <Button onClick={checkSupport} variant="outline" className="mt-3">
          {t('edu.xrIntegration.retry')}
        </Button>
      </div>
    );
  }

  if (!courseSupportsXR) {
    return null; // Курс не поддерживает XR, уведомление не показываем
  }

  return (
    <div
      role="region"
      aria-live="polite"
      className={cn(
        'p-6 rounded-md text-center space-y-4',
        xrStatus === 'supported' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-300' : '',
        xrStatus === 'partial' ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-300' : '',
        xrStatus === 'unsupported' ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-300' : '',
        className
      )}
    >
      {xrStatus === 'supported' && (
        <>
          <h3 className="text-xl font-semibold">{t('edu.xrIntegration.supportedTitle')}</h3>
          <p>{t('edu.xrIntegration.supportedDescription')}</p>
          <Button
            onClick={() => window.open('/xr/launch', '_blank')}
            variant="primary"
            aria-label={t('edu.xrIntegration.launchXR')}
          >
            {t('edu.xrIntegration.launchXR')}
          </Button>
        </>
      )}

      {xrStatus === 'partial' && (
        <>
          <h3 className="text-lg font-semibold">{t('edu.xrIntegration.partialTitle')}</h3>
          <p>{t('edu.xrIntegration.partialDescription')}</p>
          <ul className="list-disc list-inside text-left max-w-md mx-auto text-sm">
            {deviceCapabilities.map((cap) => (
              <li key={cap}>{t(`edu.xrIntegration.capabilities.${cap}`, cap)}</li>
            ))}
          </ul>
          <Button
            onClick={() => window.open('/xr/launch', '_blank')}
            variant="secondary"
            aria-label={t('edu.xrIntegration.tryXR')}
          >
            {t('edu.xrIntegration.tryXR')}
          </Button>
        </>
      )}

      {xrStatus === 'unsupported' && (
        <>
          <h3 className="text-lg font-semibold">{t('edu.xrIntegration.unsupportedTitle')}</h3>
          <p>{t('edu.xrIntegration.unsupportedDescription')}</p>
          <p className="text-sm italic">{t('edu.xrIntegration.suggestDevice')}</p>
          <Button
            onClick={checkSupport}
            variant="outline"
            aria-label={t('edu.xrIntegration.retry')}
          >
            {t('edu.xrIntegration.retry')}
          </Button>
        </>
      )}

      {xrStatus === 'unknown' && (
        <p>{t('edu.xrIntegration.unknownStatus')}</p>
      )}
    </div>
  );
};

export default React.memo(EduXRIntegrationNotice);
