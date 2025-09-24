import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchUserCourseData, generateCertificatePDF } from '@/services/api/certificateAPI';
import { Button } from '@/shared/components/Button';
import { Select } from '@/shared/components/Select';
import { Spinner } from '@/shared/components/Spinner';
import { cn } from '@/shared/utils/cn';

interface UserCourseData {
  userName: string;
  courseTitle: string;
  completionDate: string; // ISO string
  grade?: string;
  certificateId?: string;
}

interface CertificateTemplate {
  id: string;
  label: string;
  previewUrl: string;
}

interface Props {
  userId: string;
  courseId: string;
  className?: string;
}

const templates: CertificateTemplate[] = [
  {
    id: 'classic',
    label: 'Classic',
    previewUrl: '/assets/certificates/classic-preview.png',
  },
  {
    id: 'modern',
    label: 'Modern',
    previewUrl: '/assets/certificates/modern-preview.png',
  },
  {
    id: 'minimal',
    label: 'Minimal',
    previewUrl: '/assets/certificates/minimal-preview.png',
  },
];

const EduCertificateGenerator: React.FC<Props> = ({ userId, courseId, className }) => {
  const { t } = useTranslation();
  const [userCourseData, setUserCourseData] = useState<UserCourseData | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<string>(templates[0].id);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pdfBlobUrlRef = useRef<string | null>(null);

  // Загрузка данных пользователя и курса
  useEffect(() => {
    let cancelled = false;
    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchUserCourseData(userId, courseId);
        if (!cancelled) setUserCourseData(data);
      } catch {
        if (!cancelled) setError(t('edu.certificateGen.loadError'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    loadData();
    return () => {
      cancelled = true;
      if (pdfBlobUrlRef.current) {
        URL.revokeObjectURL(pdfBlobUrlRef.current);
        pdfBlobUrlRef.current = null;
      }
    };
  }, [userId, courseId, t]);

  // Генерация PDF сертификата
  const handleGenerate = useCallback(async () => {
    if (!userCourseData) return;
    setGenerating(true);
    setError(null);
    if (pdfBlobUrlRef.current) {
      URL.revokeObjectURL(pdfBlobUrlRef.current);
      pdfBlobUrlRef.current = null;
    }
    try {
      const pdfBlob = await generateCertificatePDF(userCourseData, selectedTemplate);
      const blobUrl = URL.createObjectURL(pdfBlob);
      pdfBlobUrlRef.current = blobUrl;
      window.open(blobUrl, '_blank');
    } catch {
      setError(t('edu.certificateGen.generateError'));
    } finally {
      setGenerating(false);
    }
  }, [userCourseData, selectedTemplate, t]);

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <Spinner size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center text-red-600 dark:text-red-400 max-w-md mx-auto p-4 rounded bg-red-50 dark:bg-red-900">
        {error}
      </div>
    );
  }

  if (!userCourseData) {
    return (
      <div className="text-center text-gray-700 dark:text-gray-300">
        {t('edu.certificateGen.noData')}
      </div>
    );
  }

  return (
    <section
      aria-label={t('edu.certificateGen.ariaLabel')}
      className={cn('max-w-4xl mx-auto bg-white dark:bg-zinc-900 rounded-md shadow-md p-6 space-y-6', className)}
    >
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
        {t('edu.certificateGen.title')}
      </h2>

      <div className="space-y-4">
        <p>
          <strong>{t('edu.certificateGen.student')}:</strong> {userCourseData.userName}
        </p>
        <p>
          <strong>{t('edu.certificateGen.course')}:</strong> {userCourseData.courseTitle}
        </p>
        <p>
          <strong>{t('edu.certificateGen.completedOn')}:</strong>{' '}
          {new Date(userCourseData.completionDate).toLocaleDateString()}
        </p>
        {userCourseData.grade && (
          <p>
            <strong>{t('edu.certificateGen.grade')}:</strong> {userCourseData.grade}
          </p>
        )}
      </div>

      <div>
        <label htmlFor="template-select" className="block font-medium text-gray-900 dark:text-gray-100 mb-2">
          {t('edu.certificateGen.selectTemplate')}
        </label>
        <Select
          id="template-select"
          value={selectedTemplate}
          onChange={(e) => setSelectedTemplate(e.target.value)}
          options={templates.map((t) => ({ label: t.label, value: t.id }))}
          className="max-w-xs"
        />
        <div className="mt-4 grid grid-cols-3 gap-4">
          {templates.map((tpl) => (
            <div
              key={tpl.id}
              className={cn(
                'border rounded cursor-pointer overflow-hidden',
                tpl.id === selectedTemplate
                  ? 'border-indigo-600 ring-2 ring-indigo-400 dark:ring-indigo-600'
                  : 'border-gray-300 dark:border-zinc-700'
              )}
              onClick={() => setSelectedTemplate(tpl.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setSelectedTemplate(tpl.id);
                }
              }}
              aria-pressed={tpl.id === selectedTemplate}
              aria-label={t('edu.certificateGen.templatePreview', { template: tpl.label })}
            >
              <img src={tpl.previewUrl} alt={`${tpl.label} template preview`} className="w-full h-auto" />
            </div>
          ))}
        </div>
      </div>

      <div className="flex justify-end">
        <Button
          variant="primary"
          onClick={handleGenerate}
          disabled={generating}
          aria-disabled={generating}
        >
          {generating ? (
            <>
              <Spinner size="sm" className="mr-2" />
              {t('edu.certificateGen.generating')}
            </>
          ) : (
            t('edu.certificateGen.generate')
          )}
        </Button>
      </div>
    </section>
  );
};

export default React.memo(EduCertificateGenerator);
