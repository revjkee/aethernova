import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  KeyboardEvent,
  FormEvent,
} from 'react';
import { useTranslation } from 'react-i18next';
import { sendMessageToGPT, cancelGPTRequest } from '@/services/api/gptAPI';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { Textarea } from '@/shared/components/Textarea';
import { cn } from '@/shared/utils/cn';

interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
}

interface Props {
  userId: string;
  sessionId: string;
  className?: string;
}

const AIStudyCompanionChat: React.FC<Props> = ({
  userId,
  sessionId,
  className,
}) => {
  const { t } = useTranslation();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = useCallback(
    async (e?: FormEvent<HTMLFormElement>) => {
      e?.preventDefault();
      if (loading || inputValue.trim() === '') return;
      const userMessage: ChatMessage = {
        id: `${Date.now()}-user`,
        sender: 'user',
        text: inputValue.trim(),
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, userMessage]);
      setInputValue('');
      setLoading(true);
      setError(null);
      abortControllerRef.current = new AbortController();

      try {
        const assistantMessageId = `${Date.now()}-assistant`;
        setMessages((prev) => [
          ...prev,
          {
            id: assistantMessageId,
            sender: 'assistant',
            text: '',
            timestamp: new Date().toISOString(),
          },
        ]);

        // Streamed response handler
        const stream = await sendMessageToGPT(
          userMessage.text,
          userId,
          sessionId,
          abortControllerRef.current.signal
        );

        let assistantText = '';
        const reader = stream.getReader();

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = new TextDecoder().decode(value);
          assistantText += chunk;
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === assistantMessageId
                ? { ...msg, text: assistantText }
                : msg
            )
          );
        }
      } catch (err: any) {
        if (err.name !== 'AbortError') {
          setError(err.message || t('edu.aiCompanion.error'));
          setMessages((prev) =>
            prev.filter((msg) => msg.sender !== 'assistant' || msg.text !== '')
          );
        }
      } finally {
        setLoading(false);
        abortControllerRef.current = null;
      }
    },
    [inputValue, loading, userId, sessionId, t]
  );

  const handleCancel = () => {
    if (abortControllerRef.current) {
      cancelGPTRequest();
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setLoading(false);
      setError(t('edu.aiCompanion.canceled'));
    }
  };

  const handleInputKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void handleSendMessage();
    }
  };

  return (
    <section
      className={cn(
        'flex flex-col h-full max-w-3xl mx-auto bg-white dark:bg-zinc-900 rounded-md shadow-md',
        className
      )}
      aria-label={t('edu.aiCompanion.ariaLabel')}
    >
      <div
        className="flex-grow overflow-y-auto p-4 space-y-4"
        role="log"
        aria-live="polite"
        aria-relevant="additions"
      >
        {messages.map(({ id, sender, text, timestamp }) => (
          <div
            key={id}
            className={cn(
              'max-w-[75%] p-3 rounded-lg whitespace-pre-wrap break-words',
              sender === 'user'
                ? 'bg-blue-500 text-white self-end'
                : 'bg-gray-200 dark:bg-zinc-700 text-gray-900 dark:text-gray-100 self-start'
            )}
            aria-label={`${sender === 'user' ? t('edu.aiCompanion.user') : t('edu.aiCompanion.assistant')} ${new Date(
              timestamp
            ).toLocaleTimeString()}`}
          >
            {text || (loading && sender === 'assistant' ? <Spinner size="sm" /> : null)}
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <form
        onSubmit={handleSendMessage}
        className="border-t border-gray-300 dark:border-zinc-700 p-4 flex flex-col gap-2"
      >
        <label htmlFor="ai-companion-input" className="sr-only">
          {t('edu.aiCompanion.inputLabel')}
        </label>
        <Textarea
          id="ai-companion-input"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleInputKeyDown}
          rows={3}
          placeholder={t('edu.aiCompanion.inputPlaceholder')}
          disabled={loading}
          aria-disabled={loading}
          autoComplete="off"
          spellCheck
          aria-multiline
        />
        <div className="flex justify-between items-center">
          {error && (
            <p className="text-red-600 dark:text-red-400 text-sm" role="alert">
              {error}
            </p>
          )}
          <div className="flex gap-2 ml-auto">
            {loading && (
              <Button
                type="button"
                variant="destructive"
                onClick={handleCancel}
                aria-label={t('edu.aiCompanion.cancel')}
              >
                {t('edu.aiCompanion.cancel')}
              </Button>
            )}
            <Button
              type="submit"
              variant="primary"
              disabled={loading || inputValue.trim() === ''}
              aria-disabled={loading || inputValue.trim() === ''}
            >
              {t('edu.aiCompanion.send')}
            </Button>
          </div>
        </div>
      </form>
    </section>
  );
};

export default React.memo(AIStudyCompanionChat);
