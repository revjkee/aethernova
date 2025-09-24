import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuditLog } from '@/services/logging/auditLogger';
import { useTagService } from '@/services/vault/tagService';
import { useRBAC } from '@/shared/hooks/useRBAC';
import { Input } from '@/shared/components/Input';
import { Tag } from '@/shared/components/Tag';
import { Button } from '@/shared/components/Button';
import { Tooltip } from '@/shared/components/Tooltip';
import { Badge } from '@/shared/components/Badge';
import { motion } from 'framer-motion';
import { PlusCircle, XCircle } from 'lucide-react';
import { classNames } from '@/shared/utils/classNames';
import { Spinner } from '@/shared/components/Spinner';
import { useSmartSuggest } from '@/services/ai/smartSuggest';

interface VaultTagManagerProps {
  objectId: string;
  editable?: boolean;
  context?: string;
}

export const VaultTagManager: React.FC<VaultTagManagerProps> = ({
  objectId,
  editable = true,
  context = 'vault',
}) => {
  const { t } = useTranslation();
  const { logAction } = useAuditLog();
  const { hasPermission } = useRBAC();
  const { getTags, addTag, removeTag, fetchSuggestions } = useTagService();
  const { suggestTags } = useSmartSuggest();

  const [tags, setTags] = useState<string[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [suggestions, setSuggestions] = useState<string[]>([]);

  const canEdit = useMemo(() => editable && hasPermission('vault.tag.edit'), [editable, hasPermission]);

  const loadTags = useCallback(async () => {
    setIsLoading(true);
    try {
      const loaded = await getTags(objectId);
      setTags(loaded || []);
    } catch {
      setError(t('vault.tags.load_error'));
    } finally {
      setIsLoading(false);
    }
  }, [objectId, getTags, t]);

  const handleAddTag = async (tag: string) => {
    const cleaned = tag.trim().toLowerCase();
    if (!cleaned || tags.includes(cleaned)) return;

    try {
      await addTag(objectId, cleaned);
      setTags((prev) => [...prev, cleaned]);
      setInputValue('');
      logAction('vault_tag_added', { objectId, tag: cleaned, context });
    } catch {
      setError(t('vault.tags.add_error'));
    }
  };

  const handleRemoveTag = async (tag: string) => {
    try {
      await removeTag(objectId, tag);
      setTags((prev) => prev.filter((t) => t !== tag));
      logAction('vault_tag_removed', { objectId, tag, context });
    } catch {
      setError(t('vault.tags.remove_error'));
    }
  };

  const loadSuggestions = useCallback(async () => {
    if (!editable) return;
    try {
      const aiSuggestions = await suggestTags(objectId);
      setSuggestions(aiSuggestions);
    } catch {
      // игнорируем ошибки AI подсказок
    }
  }, [objectId, suggestTags, editable]);

  useEffect(() => {
    loadTags();
    loadSuggestions();
  }, [loadTags, loadSuggestions]);

  return (
    <motion.div
      className="w-full p-4 rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2 }}
    >
      <div className="mb-3">
        <h3 className="text-sm font-medium text-gray-800 dark:text-gray-200">
          {t('vault.tags.title')}
        </h3>
      </div>

      {error && (
        <div className="text-sm text-red-600 dark:text-red-400 mb-2">
          {error}
        </div>
      )}

      {isLoading ? (
        <Spinner label={t('vault.tags.loading')} />
      ) : (
        <div className="flex flex-wrap gap-2 mb-3">
          {tags.map((tag) => (
            <Tag
              key={tag}
              text={tag}
              onRemove={canEdit ? () => handleRemoveTag(tag) : undefined}
              removable={canEdit}
            />
          ))}
        </div>
      )}

      {canEdit && (
        <div className="flex items-center gap-2 mb-4">
          <Input
            placeholder={t('vault.tags.add_placeholder')}
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAddTag(inputValue)}
            className="w-64"
          />
          <Button
            onClick={() => handleAddTag(inputValue)}
            variant="primary"
            size="sm"
            icon={<PlusCircle size={16} />}
            disabled={!inputValue.trim()}
          >
            {t('vault.tags.add')}
          </Button>
        </div>
      )}

      {suggestions.length > 0 && (
        <div className="mt-2">
          <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">
            {t('vault.tags.suggestions')}
          </p>
          <div className="flex flex-wrap gap-2">
            {suggestions.map((tag) => (
              <Badge
                key={tag}
                label={tag}
                onClick={canEdit ? () => handleAddTag(tag) : undefined}
                className={classNames(
                  'cursor-pointer hover:bg-blue-200 dark:hover:bg-blue-800',
                  canEdit ? '' : 'opacity-60 cursor-not-allowed'
                )}
              />
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
};

export default VaultTagManager;
