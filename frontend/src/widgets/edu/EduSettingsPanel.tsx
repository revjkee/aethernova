import React, { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchUserSettings, saveUserSettings } from '@/services/api/settingsAPI';
import { Button } from '@/shared/components/Button';
import { Select } from '@/shared/components/Select';
import { Switch } from '@/shared/components/Switch';
import { cn } from '@/shared/utils/cn';

interface LearningSettings {
  preferredTopics: string[];
  difficultyLevel: 'beginner' | 'intermediate' | 'advanced';
  notificationsEnabled: boolean;
  dailyReminderTime: string; // HH:mm format
}

interface Props {
  userId: string;
  className?: string;
}

const topicOptions = [
  { label: 'Mathematics', value: 'mathematics' },
  { label: 'Programming', value: 'programming' },
  { label: 'Physics', value: 'physics' },
  { label: 'Biology', value: 'biology' },
  { label: 'History', value: 'history' },
  { label: 'Languages', value: 'languages' },
];

const difficultyOptions = [
  { label: 'Beginner', value: 'beginner' },
  { label: 'Intermediate', value: 'intermediate' },
  { label: 'Advanced', value: 'advanced' },
];

const EduSettingsPanel: React.FC<Props> = ({ userId, className }) => {
  const { t } = useTranslation();

  const [settings, setSettings] = useState<LearningSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const loadSettings = async () => {
      setLoading(true);
      setError(null);
      try {
        const userSettings = await fetchUserSettings(userId);
        if (!cancelled) setSettings(userSettings);
      } catch {
        if (!cancelled) setError(t('edu.settings.loadError'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    loadSettings();
    return () => {
      cancelled = true;
    };
  }, [userId, t]);

  const handleTopicsChange = useCallback((selected: string[]) => {
    setSettings((prev) => (prev ? { ...prev, preferredTopics: selected } : prev));
  }, []);

  const handleDifficultyChange = useCallback((value: string) => {
    setSettings((prev) => (prev ? { ...prev, difficultyLevel: value as LearningSettings['difficultyLevel'] } : prev));
  }, []);

  const handleNotificationsToggle = useCallback((enabled: boolean) => {
    setSettings((prev) => (prev ? { ...prev, notificationsEnabled: enabled } : prev));
  }, []);

  const handleReminderTimeChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const time = e.target.value;
    setSettings((prev) => (prev ? { ...prev, dailyReminderTime: time } : prev));
  }, []);

  const handleSave = async () => {
    if (!settings) return;
    setSaving(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await saveUserSettings(userId, settings);
      setSuccessMsg(t('edu.settings.saveSuccess'));
    } catch {
      setError(t('edu.settings.saveError'));
    } finally {
      setSaving(false);
      setTimeout(() => setSuccessMsg(null), 4000);
    }
  };

  if (loading) {
    return (
      <div className={cn('flex justify-center p-12', className)}>
        <span
          className="animate-spin rounded-full h-12 w-12 border-b-4 border-indigo-600"
          aria-label={t('edu.settings.loading')}
        />
      </div>
    );
  }

  if (error) {
    return (
      <div role="alert" className={cn('text-center text-red-600 dark:text-red-400 p-4', className)}>
        {error}
      </div>
    );
  }

  if (!settings) {
    return (
      <div className={cn('text-center text-muted-foreground p-4', className)}>
        {t('edu.settings.noData')}
      </div>
    );
  }

  return (
    <section
      aria-label={t('edu.settings.ariaLabel')}
      className={cn('max-w-4xl mx-auto bg-white dark:bg-zinc-900 rounded-md shadow-md p-6 space-y-6', className)}
    >
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">{t('edu.settings.title')}</h2>

      <div className="space-y-6">
        {/* Preferred Topics */}
        <div>
          <label htmlFor="preferred-topics" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
            {t('edu.settings.preferredTopics')}
          </label>
          <Select
            id="preferred-topics"
            value={settings.preferredTopics}
            options={topicOptions.map(({ label, value }) => ({
              label: t(`edu.topics.${value}`),
              value,
            }))}
            multiple
            onChange={handleTopicsChange}
            className="max-w-lg"
          />
        </div>

        {/* Difficulty Level */}
        <div>
          <label htmlFor="difficulty-level" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
            {t('edu.settings.difficultyLevel')}
          </label>
          <Select
            id="difficulty-level"
            value={settings.difficultyLevel}
            options={difficultyOptions.map(({ label, value }) => ({
              label: t(`edu.difficulty.${value}`),
              value,
            }))}
            onChange={handleDifficultyChange}
            className="max-w-xs"
          />
        </div>

        {/* Notifications */}
        <div className="flex items-center justify-between">
          <label htmlFor="notifications-toggle" className="font-medium text-gray-900 dark:text-gray-100">
            {t('edu.settings.notificationsEnabled')}
          </label>
          <Switch
            id="notifications-toggle"
            checked={settings.notificationsEnabled}
            onChange={handleNotificationsToggle}
            aria-checked={settings.notificationsEnabled}
          />
        </div>

        {/* Daily Reminder Time */}
        {settings.notificationsEnabled && (
          <div>
            <label htmlFor="daily-reminder-time" className="block font-medium text-gray-900 dark:text-gray-100 mb-1">
              {t('edu.settings.dailyReminderTime')}
            </label>
            <input
              id="daily-reminder-time"
              type="time"
              value={settings.dailyReminderTime}
              onChange={handleReminderTimeChange}
              className="block w-32 rounded border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-gray-900 dark:text-gray-100 p-2 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              aria-label={t('edu.settings.dailyReminderTime')}
            />
          </div>
        )}
      </div>

      {successMsg && (
        <div className="text-green-600 dark:text-green-400 text-center" role="status" aria-live="polite">
          {successMsg}
        </div>
      )}

      <div className="flex justify-end">
        <Button
          variant="primary"
          onClick={handleSave}
          disabled={saving}
          aria-disabled={saving}
        >
          {saving ? t('edu.settings.saving') : t('edu.settings.save')}
        </Button>
      </div>
    </section>
  );
};

export default React.memo(EduSettingsPanel);
