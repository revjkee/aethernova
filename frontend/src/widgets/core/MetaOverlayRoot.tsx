import React, {
  useState,
  useCallback,
  useEffect,
  useRef,
  ReactNode,
  forwardRef,
  useImperativeHandle,
} from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { useLockBodyScroll, useFocusTrap } from '@/shared/hooks/accessibilityHooks';
import { cn } from '@/shared/utils/cn';

interface OverlayConfig {
  id: string;
  element: ReactNode;
  zIndex?: number;
  modal?: boolean;
  onClose?: () => void;
  ariaLabel?: string;
  persistent?: boolean;
}

export interface MetaOverlayRootHandle {
  openOverlay: (config: OverlayConfig) => void;
  closeOverlay: (id: string) => void;
  closeAll: () => void;
}

const DEFAULT_Z_INDEX_BASE = 1000;

const MetaOverlayRoot = forwardRef<MetaOverlayRootHandle>((_, ref) => {
  const [overlays, setOverlays] = useState<OverlayConfig[]>([]);
  const containerRef = useRef<HTMLDivElement | null>(null);

  useLockBodyScroll(overlays.length > 0 && overlays.some(o => o.modal));

  useImperativeHandle(ref, () => ({
    openOverlay: (config: OverlayConfig) => {
      setOverlays((prev) => {
        if (prev.find((o) => o.id === config.id)) return prev;
        return [...prev, { ...config, zIndex: config.zIndex ?? (DEFAULT_Z_INDEX_BASE + prev.length * 10) }];
      });
    },
    closeOverlay: (id: string) => {
      setOverlays((prev) => prev.filter((o) => o.id !== id));
    },
    closeAll: () => {
      setOverlays([]);
    },
  }));

  // Handle Escape key to close top modal overlay if modal and close callback exist
  useEffect(() => {
    if (overlays.length === 0) return;

    const topModal = [...overlays].reverse().find(o => o.modal);
    if (!topModal) return;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && topModal.onClose) {
        e.preventDefault();
        topModal.onClose();
      }
    };

    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [overlays]);

  // Focus trap for modal overlays
  const modalOverlay = overlays.find(o => o.modal);
  useFocusTrap(modalOverlay ? `#overlay-${modalOverlay.id}` : null);

  return createPortal(
    <div
      ref={containerRef}
      aria-live="assertive"
      aria-relevant="additions removals"
      role="region"
      className="fixed inset-0 pointer-events-none z-[9999]"
    >
      <AnimatePresence>
        {overlays.map(({ id, element, zIndex, modal, ariaLabel, persistent }) => (
          <motion.div
            key={id}
            id={`overlay-${id}`}
            role="dialog"
            aria-modal={modal || undefined}
            aria-label={ariaLabel}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.25 }}
            style={{ zIndex, pointerEvents: modal ? 'auto' : 'none' }}
            className={cn(
              'fixed inset-0 flex justify-center items-center bg-black bg-opacity-50',
              persistent ? 'pointer-events-auto' : ''
            )}
            onClick={(e) => {
              if (!modal) return;
              if (e.target === e.currentTarget && !persistent) {
                const overlay = overlays.find(o => o.id === id);
                overlay?.onClose && overlay.onClose();
              }
            }}
          >
            <div className="relative pointer-events-auto max-w-full max-h-full overflow-auto rounded-lg shadow-lg bg-white dark:bg-zinc-900 p-6">
              {element}
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>,
    document.body
  );
});

export default React.memo(MetaOverlayRoot);
