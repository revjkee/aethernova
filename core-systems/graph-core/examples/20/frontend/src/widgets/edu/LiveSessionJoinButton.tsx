import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { checkLiveSessionStatus, joinLiveSession } from '@/services/api/liveAPI';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { Modal } from '@/shared/components/Modal';
import { cn } from '@/shared/utils/cn';

interface Props {
  sessionId: string;
  userId: string;
  onJoinSuccess?: () => void;
  className?: string;
}

enum SessionState {
  Loading = 'loading',
  Upcoming = 'upcoming',
  Live = 'live',
  Ended = 'ended',
  Error = 'error',
}

const LiveSessionJoinButton: React.FC<Props> = ({ sessionId, userId, onJoinSuccess, className }) => {
  const { t } = useTranslation();
  const [sessionState, setSessionState] = useState<SessionState>(SessionState.Loading);
  const [countdown, setCountdown] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [joining, setJoining] = useState(false);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const countdownIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const fetchSessionStatus = useCallback(async () => {
    setSessionState(SessionState.Loading);
    setError(null);
    try {
      const status = await checkLiveSessionStatus(sessionId);
      switch (status.state) {
        case 'live':
          setSessionState(SessionState.Live);
          setCountdown(null);
          break;
        case 'upcoming':
          setSessionState(SessionState.Upcoming);
          setCountdown(status.secondsUntilStart);
          break;
        case 'ended':
          setSessionState(SessionState.Ended);
          setCountdown(null);
          break;
        default:
          setSessionState(SessionState.Error);
          setError(t('liveSession.unknownStatus'));
      }
    } catch {
      setSessionState(SessionState.Error);
      setError(t('liveSession.loadError'));
    }
  }, [sessionId, t]);

  useEffect(() => {
    fetchSessionStatus();
  }, [fetchSessionStatus]);

  useEffect(() => {
    if (sessionState === SessionState.Upcoming && countdown !== null && countdown > 0) {
      countdownIntervalRef.current = setInterval(() => {
        setCountdown((prev) => {
          if (prev === null) return null;
          if (prev <= 1) {
            clearInterval(countdownIntervalRef.current as NodeJS.Timeout);
            fetchSessionStatus();
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
    return () => {
      if (countdownIntervalRef.current) {
        clearInterval(countdownIntervalRef.current);
        countdownIntervalRef.current = null;
      }
    };
  }, [sessionState, countdown, fetchSessionStatus]);

  const handleJoinClick = () => {
    setShowConfirmModal(true);
  };

  const confirmJoin = async () => {
    setShowConfirmModal(false);
    setJoining(true);
    setError(null);
    try {
      await joinLiveSession(sessionId, userId);
      setJoining(false);
      onJoinSuccess && onJoinSuccess();
    } catch (e: any) {
      setJoining(false);
      setError(e.message || t('liveSession.joinError'));
    }
  };

  const formatCountdown = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  let buttonLabel = '';
  let buttonDisabled = false;

  switch (sessionState) {
    case SessionState.Loading:
      buttonLabel = t('liveSession.loading');
      buttonDisabled = true;
      break;
    case SessionState.Upcoming:
      buttonLabel = countdown !== null ? t('liveSession.startsIn', { time: formatCountdown(countdown) }) : t('liveSession.upcoming');
      buttonDisabled = true;
      break;
    case SessionState.Live:
      buttonLabel = t('liveSession.joinNow');
      buttonDisabled = joining;
      break;
    case SessionState.Ended:
      buttonLabel = t('liveSession.ended');
      buttonDisabled = true;
      break;
    case SessionState.Error:
      buttonLabel = t('liveSession.error');
      buttonDisabled = true;
      break;
  }

  return (
    <>
      <Button
        onClick={handleJoinClick}
        disabled={buttonDisabled}
        variant={sessionState === SessionState.Live ? 'primary' : 'outline'}
        className={cn('w-full max-w-xs mx-auto', className)}
        aria-live="polite"
        aria-disabled={buttonDisabled}
      >
        {joining ? <><Spinner size="sm" /> {t('liveSession.joining')}</> : buttonLabel}
      </Button>

      <Modal
        isOpen={showConfirmModal}
        onClose={() => setShowConfirmModal(false)}
        title={t('liveSession.confirmJoinTitle')}
        ariaLabel={t('liveSession.confirmJoinAria')}
      >
        <p className="mb-4">{t('liveSession.confirmJoinText')}</p>
        <div className="flex justify-end gap-4">
          <Button variant="outline" onClick={() => setShowConfirmModal(false)}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={confirmJoin}>
            {t('liveSession.confirm')}
          </Button>
        </div>
      </Modal>

      {error && (
        <div role="alert" className="mt-3 text-red-600 dark:text-red-400 text-center max-w-xs mx-auto">
          {error}
        </div>
      )}
    </>
  );
};

export default React.memo(LiveSessionJoinButton);
