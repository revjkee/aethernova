import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { saveNote, loadNote } from '@/services/api/notesAPI';
import { debounce } from 'lodash-es';
import { Spinner } from '@/shared/components/Spinner';
import { cn } from '@/shared/utils/cn';

// Используем react-markdown для рендера и react-simplemde-editor для редактирования
import SimpleMDE from 'react-simplemde-editor';
import 'easymde/dist/easymde.min.css';

interface Props {
  userId: string;
  lessonId: string;
  className?: string;
}

const AUTOSAVE_DEBOUNCE_MS = 1500;

const StudentNotesEditor: React.FC<Props> = ({ userId, lessonId, className }) => {
  const { t } = useTranslation();
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isMounted = useRef(true);

  useEffect(() => {
    isMounted.current = true;
    const fetchNote = async () => {
      setLoading(true);
      try {
        const note = await loadNote(userId, lessonId);
        if (isMounted.current) {
          setContent(note || '');
          setError(null);
        }
      } catch {
        if (isMounted.current) {
          setError(t('edu.studentNotes.loadError'));
        }
      } finally {
        if (isMounted.current) {
          setLoading(false);
        }
      }
    };
    fetchNote();
    return () => {
      isMounted.current = false;
    };
  }, [userId, lessonId, t]);

  // Автосохранение с debounce
  const debouncedSave = useRef(
    debounce(async (text: string) => {
      setSaving(true);
      setError(null);
      try {
        await saveNote(userId, lessonId, text);
      } catch {
        setError(t('edu.studentNotes.saveError'));
      } finally {
        setSaving(false);
      }
    }, AUTOSAVE_DEBOUNCE_MS)
  ).current;

  const handleChange = useCallback(
    (value: string) => {
      setContent(value);
      debouncedSave(value);
    },
    [debouncedSave]
  );

  return (
    <section aria-label={t('edu.studentNotes.ariaLabel')} className={cn('relative', className)}>
      {loading ? (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      ) : (
        <>
          <SimpleMDE
            value={content}
            onChange={handleChange}
            options={{
              spellChecker: true,
              placeholder: t('edu.studentNotes.placeholder'),
              status: ['autosave', 'lines', 'words', 'cursor'],
              minHeight: '240px',
              maxHeight: '480px',
              toolbar: [
                'bold',
                'italic',
                'heading',
                '|',
                'quote',
                'unordered-list',
                'ordered-list',
                '|',
                'link',
                'image',
                '|',
                'preview',
                'side-by-side',
                'fullscreen',
                '|',
                'guide',
              ],
              autofocus: true,
            }}
          />
          <div className="mt-2 flex justify-between items-center text-xs text-muted-foreground select-none">
            {saving ? t('edu.studentNotes.saving') : t('edu.studentNotes.saved')}
            {error && <span className="text-red-600 ml-2">{error}</span>}
          </div>
        </>
      )}
    </section>
  );
};

export default React.memo(StudentNotesEditor);
