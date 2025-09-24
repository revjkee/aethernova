import time
import random
import logging
import threading
from typing import Optional, Callable
from datetime import datetime

from silentlink_core.utils.noise import inject_system_noise
from silentlink_core.security.temporal_model import evaluate_timing_signature
from silentlink_core.core.errors import TimingObfuscationError

logger = logging.getLogger("covert.timing_obfuscator")
logging.basicConfig(level=logging.INFO)

BASE_LATENCY_MS = 80
JITTER_RANGE_MS = (25, 150)
PHASE_NOISE_AMPLITUDE = 0.3  # в долях секунды
SIGNATURE_THRESHOLD = 0.75

class TimingObfuscator:
    def __init__(self):
        self.enabled = True

    def _apply_jitter(self) -> float:
        jitter_ms = random.uniform(*JITTER_RANGE_MS)
        jitter_sec = jitter_ms / 1000.0
        logger.debug(f"Applied jitter: {jitter_ms:.2f}ms")
        return jitter_sec

    def _apply_phase_noise(self) -> float:
        phase_shift = random.gauss(0, PHASE_NOISE_AMPLITUDE)
        logger.debug(f"Applied phase noise: {phase_shift:.3f}s")
        return phase_shift

    def _verify_temporal_safety(self, delay: float) -> bool:
        score = evaluate_timing_signature(delay)
        logger.debug(f"Timing signature score: {score:.4f}")
        return score < SIGNATURE_THRESHOLD

    def delay_with_obfuscation(self, base_delay: Optional[float] = None):
        if not self.enabled:
            return

        try:
            base_sec = base_delay or (BASE_LATENCY_MS / 1000.0)
            total_delay = base_sec + self._apply_jitter() + self._apply_phase_noise()
            inject_system_noise(duration=total_delay * 0.1)

            if not self._verify_temporal_safety(total_delay):
                raise TimingObfuscationError("Temporal fingerprint too strong")

            logger.info(f"Delaying execution by {total_delay:.3f}s for obfuscation")
            time.sleep(max(total_delay, 0))

        except Exception as e:
            logger.warning(f"Obfuscation error: {e}")
            time.sleep(base_delay or 0.1)

    def run_with_obfuscation(self, func: Callable, *args, **kwargs):
        try:
            self.delay_with_obfuscation()
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Function execution with obfuscation failed: {e}")
            raise

    def async_obfuscate_action(self, func: Callable, *args, **kwargs):
        def wrapped():
            self.run_with_obfuscation(func, *args, **kwargs)
        thread = threading.Thread(target=wrapped, daemon=True)
        thread.start()

    def mark(self) -> str:
        return f"OBF-{datetime.utcnow().isoformat()}Z"

    def disable(self):
        self.enabled = False

    def enable(self):
        self.enabled = True
