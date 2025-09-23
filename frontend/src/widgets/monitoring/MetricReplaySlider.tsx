// src/widgets/Monitoring/MetricReplaySlider.tsx

import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
  MutableRefObject,
} from 'react';
import { Slider } from '@/components/ui/slider';
import { Play, Pause, Rewind, FastForward } from 'lucide-react';
import { cn } from '@/shared/utils/classNames';
import { formatTimestamp } from '@/shared/utils/parseDate';
import { useTheme } from '@/shared/hooks/useTelegramTheme';
import { useWebSocketReplay } from '@/shared/hooks/useWebSocketReplay';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Skeleton } from '@/components/ui/skeleton';

interface MetricReplaySliderProps {
  timestamps: number[];
  onSeek: (timestamp: number) => void;
  isLoading: boolean;
  annotations?: Record<number, string>;
  className?: string;
  autoPlaySpeed?: number; // ms per step
}

export const MetricReplaySlider: React.FC<MetricReplaySliderProps> = ({
  timestamps,
  onSeek,
  isLoading,
  annotations = {},
  className,
  autoPlaySpeed = 800,
}) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(0);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const theme = useTheme();

  const currentTimestamp = useMemo(() => timestamps[currentIndex] ?? 0, [timestamps, currentIndex]);

  const togglePlay = useCallback(() => {
    setIsPlaying((prev) => !prev);
  }, []);

  const stopPlayback = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setIsPlaying(false);
  }, []);

  useEffect(() => {
    if (isPlaying && timestamps.length > 0) {
      intervalRef.current = setInterval(() => {
        setCurrentIndex((prev) => {
          const next = prev + 1;
          if (next >= timestamps.length) {
            stopPlayback();
            return prev;
          }
          onSeek(timestamps[next]);
          return next;
        });
      }, autoPlaySpeed);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isPlaying, timestamps, autoPlaySpeed, stopPlayback, onSeek]);

  const handleSeek = useCallback(
    (index: number) => {
      setCurrentIndex(index);
      onSeek(timestamps[index]);
    },
    [timestamps, onSeek]
  );

  const handleRewind = useCallback(() => {
    const newIndex = Math.max(0, currentIndex - 5);
    handleSeek(newIndex);
  }, [currentIndex, handleSeek]);

  const handleFastForward = useCallback(() => {
    const newIndex = Math.min(timestamps.length - 1, currentIndex + 5);
    handleSeek(newIndex);
  }, [currentIndex, timestamps.length, handleSeek]);

  if (isLoading || timestamps.length === 0) {
    return <Skeleton className="w-full h-8 rounded" />;
  }

  return (
    <div
      className={cn(
        'w-full px-4 py-2 rounded-xl bg-background border border-border shadow-md',
        className
      )}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-muted-foreground">
          {formatTimestamp(currentTimestamp)}
        </span>
        <div className="flex gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <button onClick={handleRewind} className="p-1 hover:bg-accent rounded">
                <Rewind size={18} />
              </button>
            </TooltipTrigger>
            <TooltipContent>Назад</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <button onClick={togglePlay} className="p-1 hover:bg-accent rounded">
                {isPlaying ? <Pause size={18} /> : <Play size={18} />}
              </button>
            </TooltipTrigger>
            <TooltipContent>{isPlaying ? 'Пауза' : 'Воспроизвести'}</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <button onClick={handleFastForward} className="p-1 hover:bg-accent rounded">
                <FastForward size={18} />
              </button>
            </TooltipTrigger>
            <TooltipContent>Вперёд</TooltipContent>
          </Tooltip>
        </div>
      </div>

      <Slider
        min={0}
        max={timestamps.length - 1}
        step={1}
        value={[currentIndex]}
        onValueChange={(val) => handleSeek(val[0])}
        className="w-full"
      />

      {annotations[currentTimestamp] && (
        <div className="mt-2 text-sm text-accent-foreground italic">
          {annotations[currentTimestamp]}
        </div>
      )}
    </div>
  );
};
