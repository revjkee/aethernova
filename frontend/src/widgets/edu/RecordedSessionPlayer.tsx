import React, { useRef, useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Spinner } from '@/shared/components/Spinner';
import { Button } from '@/shared/components/Button';
import { cn } from '@/shared/utils/cn';

interface Props {
  videoUrl: string;
  subtitlesUrl?: string;
  sessionId: string;
  userId: string;
  className?: string;
  onProgressSave?: (progressSeconds: number) => void;
}

const STORAGE_KEY_PREFIX = 'recorded-session-progress-';

const RecordedSessionPlayer: React.FC<Props> = ({
  videoUrl,
  subtitlesUrl,
  sessionId,
  userId,
  className,
  onProgressSave,
}) => {
  const { t } = useTranslation();
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [loading, setLoading] = useState(true);
  const [playing, setPlaying] = useState(false);
  const [duration, setDuration] = useState(0);
  const [currentTime, setCurrentTime] = useState(0);
  const [playbackRate, setPlaybackRate] = useState(1);
  const [error, setError] = useState<string | null>(null);

  const storageKey = `${STORAGE_KEY_PREFIX}${sessionId}-${userId}`;

  useEffect(() => {
    const saved = localStorage.getItem(storageKey);
    if (saved && videoRef.current) {
      const savedTime = parseFloat(saved);
      if (!isNaN(savedTime)) {
        videoRef.current.currentTime = savedTime;
      }
    }
  }, [storageKey]);

  const handleLoadedMetadata = useCallback(() => {
    if (!videoRef.current) return;
    setDuration(videoRef.current.duration);
    setLoading(false);
  }, []);

  const handleTimeUpdate = useCallback(() => {
    if (!videoRef.current) return;
    const current = videoRef.current.currentTime;
    setCurrentTime(current);
    localStorage.setItem(storageKey, current.toString());
    onProgressSave && onProgressSave(current);
  }, [storageKey, onProgressSave]);

  const handlePlayPause = () => {
    if (!videoRef.current) return;
    if (videoRef.current.paused) {
      videoRef.current.play();
      setPlaying(true);
    } else {
      videoRef.current.pause();
      setPlaying(false);
    }
  };

  const handleSpeedChange = (rate: number) => {
    if (!videoRef.current) return;
    videoRef.current.playbackRate = rate;
    setPlaybackRate(rate);
  };

  const handleSeek = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (!videoRef.current) return;
    const newTime = parseFloat(event.target.value);
    videoRef.current.currentTime = newTime;
    setCurrentTime(newTime);
  };

  const handleVideoError = () => {
    setError(t('edu.recordedSessionPlayer.errorLoading'));
    setLoading(false);
  };

  return (
    <section
      className={cn('relative bg-black rounded-md overflow-hidden', className)}
      aria-label={t('edu.recordedSessionPlayer.ariaLabel')}
    >
      {loading && (
        <div className="absolute inset-0 flex justify-center items-center bg-black bg-opacity-70 z-10">
          <Spinner size="lg" />
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="absolute inset-0 flex justify-center items-center bg-black bg-opacity-70 text-red-500 text-center p-4 z-10"
        >
          {error}
        </div>
      )}

      <video
        ref={videoRef}
        src={videoUrl}
        className="w-full h-auto"
        controls={false}
        preload="metadata"
        onLoadedMetadata={handleLoadedMetadata}
        onTimeUpdate={handleTimeUpdate}
        onError={handleVideoError}
        aria-describedby={`${sessionId}-description`}
      >
        {subtitlesUrl && (
          <track
            kind="subtitles"
            srcLang="en"
            src={subtitlesUrl}
            default
            label={t('edu.recordedSessionPlayer.subtitles')}
          />
        )}
      </video>

      {/* Custom Controls */}
      <div className="absolute bottom-0 left-0 right-0 bg-black bg-opacity-70 p-3 flex flex-col md:flex-row items-center gap-3 md:gap-6">
        <Button
          variant="secondary"
          aria-label={playing ? t('edu.recordedSessionPlayer.pause') : t('edu.recordedSessionPlayer.play')}
          onClick={handlePlayPause}
          className="min-w-[48px]"
        >
          {playing ? t('edu.recordedSessionPlayer.pause') : t('edu.recordedSessionPlayer.play')}
        </Button>

        <input
          type="range"
          min={0}
          max={duration}
          step={0.1}
          value={currentTime}
          onChange={handleSeek}
          aria-valuemin={0}
          aria-valuemax={duration}
          aria-valuenow={currentTime}
          aria-label={t('edu.recordedSessionPlayer.seek')}
          className="flex-grow"
        />

        <label htmlFor="speedSelect" className="sr-only">
          {t('edu.recordedSessionPlayer.playbackSpeed')}
        </label>
        <select
          id="speedSelect"
          value={playbackRate}
          onChange={(e) => handleSpeedChange(parseFloat(e.target.value))}
          className="bg-transparent text-white text-sm rounded px-2 py-1"
          aria-label={t('edu.recordedSessionPlayer.playbackSpeed')}
        >
          {[0.5, 0.75, 1, 1.25, 1.5, 2].map((speed) => (
            <option key={speed} value={speed}>
              {speed}x
            </option>
          ))}
        </select>
      </div>

      <div id={`${sessionId}-description`} className="sr-only">
        {t('edu.recordedSessionPlayer.description')}
      </div>
    </section>
  );
};

export default React.memo(RecordedSessionPlayer);
