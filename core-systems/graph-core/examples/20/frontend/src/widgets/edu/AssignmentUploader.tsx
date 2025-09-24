import React, { useState, useCallback, useRef } from 'react';
import { useMutation } from '@tanstack/react-query';
import { uploadAssignments } from '@/services/api/eduAPI';
import { Button } from '@/shared/components/Button';
import { ProgressBar } from '@/shared/components/ProgressBar';
import { Spinner } from '@/shared/components/Spinner';
import { useTranslation } from 'react-i18next';
import { cn } from '@/shared/utils/cn';

interface Props {
  assignmentId: string;
  userId: string;
  maxFileSizeMB?: number;
  acceptedFormats?: string[];
  onUploadSuccess?: () => void;
}

interface UploadFile {
  file: File;
  progress: number;
  status: 'pending' | 'uploading' | 'success' | 'error';
  error?: string;
}

const DEFAULT_MAX_FILE_SIZE_MB = 50;
const DEFAULT_ACCEPTED_FORMATS = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];

const AssignmentUploader: React.FC<Props> = ({
  assignmentId,
  userId,
  maxFileSizeMB = DEFAULT_MAX_FILE_SIZE_MB,
  acceptedFormats = DEFAULT_ACCEPTED_FORMATS,
  onUploadSuccess,
}) => {
  const { t } = useTranslation();
  const [files, setFiles] = useState<UploadFile[]>([]);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const uploadMutation = useMutation(uploadAssignments, {
    onSuccess: () => {
      onUploadSuccess && onUploadSuccess();
    },
  });

  const validateFile = (file: File): string | null => {
    if (file.size > maxFileSizeMB * 1024 * 1024) {
      return t('edu.uploader.errors.fileTooLarge', { size: maxFileSizeMB });
    }
    if (!acceptedFormats.includes(file.type)) {
      return t('edu.uploader.errors.invalidFormat');
    }
    return null;
  };

  const handleFilesSelected = useCallback(
    (selectedFiles: FileList | null) => {
      if (!selectedFiles) return;
      const newFiles: UploadFile[] = [];
      for (let i = 0; i < selectedFiles.length; i++) {
        const file = selectedFiles.item(i);
        if (!file) continue;
        const error = validateFile(file);
        newFiles.push({ file, progress: 0, status: error ? 'error' : 'pending', error });
      }
      setFiles((prev) => [...prev, ...newFiles]);
    },
    [maxFileSizeMB, acceptedFormats, t]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      handleFilesSelected(e.dataTransfer.files);
    },
    [handleFilesSelected]
  );

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const startUpload = async () => {
    for (const fileEntry of files) {
      if (fileEntry.status !== 'pending') continue;
      setFiles((prev) =>
        prev.map((f) => (f.file === fileEntry.file ? { ...f, status: 'uploading', progress: 0 } : f))
      );
      try {
        await uploadMutation.mutateAsync({
          assignmentId,
          userId,
          file: fileEntry.file,
          onProgress: (progressEvent: ProgressEvent) => {
            const progressPercent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            setFiles((prev) =>
              prev.map((f) => (f.file === fileEntry.file ? { ...f, progress: progressPercent } : f))
            );
          },
        });
        setFiles((prev) =>
          prev.map((f) => (f.file === fileEntry.file ? { ...f, status: 'success', progress: 100 } : f))
        );
      } catch (error: any) {
        setFiles((prev) =>
          prev.map((f) => (f.file === fileEntry.file ? { ...f, status: 'error', error: error.message || t('edu.uploader.errors.uploadFailed') } : f))
        );
      }
    }
  };

  const removeFile = (fileToRemove: File) => {
    setFiles((prev) => prev.filter((f) => f.file !== fileToRemove));
  };

  return (
    <section
      className="border border-dashed border-gray-400 rounded-md p-6 text-center bg-white dark:bg-zinc-900"
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      aria-label={t('edu.uploader.ariaLabel')}
    >
      <input
        ref={inputRef}
        type="file"
        multiple
        accept={acceptedFormats.join(',')}
        className="hidden"
        onChange={(e) => handleFilesSelected(e.target.files)}
      />
      <p className="mb-4 text-gray-700 dark:text-gray-300">{t('edu.uploader.instruction')}</p>
      <Button onClick={() => inputRef.current?.click()} className="mb-4">
        {t('edu.uploader.selectFiles')}
      </Button>
      {files.length > 0 && (
        <div className="space-y-3 max-h-64 overflow-y-auto">
          {files.map(({ file, progress, status, error }, idx) => (
            <div
              key={file.name + idx}
              className="flex items-center justify-between p-2 rounded bg-zinc-100 dark:bg-zinc-800"
            >
              <div className="flex flex-col max-w-[70%]">
                <span className="truncate font-medium text-gray-900 dark:text-gray-100">{file.name}</span>
                {status === 'error' && <span className="text-xs text-red-600">{error}</span>}
              </div>
              <div className="flex items-center gap-4 min-w-[120px]">
                <ProgressBar value={progress} className="flex-grow" />
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => removeFile(file)}
                  aria-label={t('edu.uploader.removeFile')}
                >
                  &times;
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="mt-6">
        <Button
          onClick={startUpload}
          disabled={files.every((f) => f.status !== 'pending')}
          variant="primary"
        >
          {t('edu.uploader.upload')}
        </Button>
      </div>
      {uploadMutation.isLoading && (
        <div className="mt-4 flex justify-center">
          <Spinner />
        </div>
      )}
    </section>
  );
};

export default React.memo(AssignmentUploader);
