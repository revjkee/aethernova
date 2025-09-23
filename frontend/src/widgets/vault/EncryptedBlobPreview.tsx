import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { decodeBase64, decodeHex } from '@/shared/utils/decoderUtils';
import { useDecryptionService } from '@/services/security/decryptionService';
import { useAuditLog } from '@/services/logging/auditLogger';
import { useTheme } from '@/shared/hooks/useTheme';
import { formatBytes } from '@/shared/utils/formatBytes';
import { Spinner } from '@/shared/components/Spinner';
import { Alert } from '@/shared/components/Alert';
import { Toggle } from '@/shared/components/Toggle';
import { SafeRenderBlob } from '@/shared/components/SafeRenderBlob';
import { classNames } from '@/shared/utils/classNames';
import { motion } from 'framer-motion';

export type DisplayMode = 'hex' | 'base64' | 'raw';

interface EncryptedBlobPreviewProps {
  encryptedData: string;
  objectId: string;
  sizeInBytes: number;
  mimeType?: string;
  userHasAccess: boolean;
}

export const EncryptedBlobPreview: React.FC<EncryptedBlobPreviewProps> = ({
  encryptedData,
  objectId,
  sizeInBytes,
  mimeType = 'application/octet-stream',
  userHasAccess,
}) => {
  const { t } = useTranslation();
  const { decryptBlob, isQuantumSafe } = useDecryptionService();
  const { logAction } = useAuditLog();
  const { theme } = useTheme();

  const [decryptedData, setDecryptedData] = useState<string | null>(null);
  const [displayMode, setDisplayMode] = useState<DisplayMode>('hex');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showDecrypted, setShowDecrypted] = useState(false);

  const handleDecryption = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await decryptBlob(encryptedData, objectId);
      setDecryptedData(result);
      logAction('vault_blob_decryption', {
        objectId,
        mimeType,
        mode: displayMode,
        theme,
        sizeInBytes,
        quantumSafe: isQuantumSafe(),
      });
    } catch (err) {
      setError(t('vault.preview.decryption_error'));
    } finally {
      setIsLoading(false);
    }
  }, [encryptedData, objectId, decryptBlob, displayMode, mimeType, theme, t, logAction, sizeInBytes, isQuantumSafe]);

  useEffect(() => {
    if (showDecrypted && !decryptedData && userHasAccess) {
      handleDecryption();
    }
  }, [showDecrypted, decryptedData, handleDecryption, userHasAccess]);

  const formattedPreview = useMemo(() => {
    if (!decryptedData) return null;

    switch (displayMode) {
      case 'base64':
        return btoa(decryptedData);
      case 'hex':
        return decodeHex(decryptedData);
      case 'raw':
      default:
        return decryptedData;
    }
  }, [decryptedData, displayMode]);

  return (
    <motion.div
      className="w-full p-4 border border-gray-300 dark:border-gray-700 rounded-lg shadow-sm bg-white dark:bg-gray-900"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2 }}
    >
      <div className="flex items-center justify-between mb-3">
        <div>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            {t('vault.preview.object_id')}: <strong>{objectId}</strong>
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t('vault.preview.size')}: {formatBytes(sizeInBytes)} — {mimeType}
          </p>
        </div>
        <Toggle
          label={t('vault.preview.toggle_decryption')}
          checked={showDecrypted}
          onChange={() => setShowDecrypted((prev) => !prev)}
        />
      </div>

      {error && <Alert type="error" message={error} />}

      {!showDecrypted && (
        <p className="text-sm italic text-gray-500 dark:text-gray-400">
          {t('vault.preview.encrypted_placeholder')}
        </p>
      )}

      {isLoading && <Spinner label={t('vault.preview.loading')} />}

      {showDecrypted && decryptedData && (
        <div className="mt-4">
          <div className="mb-2 flex items-center gap-3">
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
              {t('vault.preview.display_mode')}
            </label>
            <select
              className="text-sm rounded border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800"
              value={displayMode}
              onChange={(e) => setDisplayMode(e.target.value as DisplayMode)}
            >
              <option value="hex">HEX</option>
              <option value="base64">Base64</option>
              <option value="raw">{t('vault.preview.raw_text')}</option>
            </select>
          </div>

          <div className={classNames(
            'whitespace-pre-wrap text-xs p-3 rounded bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 font-mono max-h-96 overflow-auto border border-gray-300 dark:border-gray-700'
          )}>
            <SafeRenderBlob content={formattedPreview} />
          </div>
        </div>
      )}
    </motion.div>
  );
};

export default EncryptedBlobPreview;
