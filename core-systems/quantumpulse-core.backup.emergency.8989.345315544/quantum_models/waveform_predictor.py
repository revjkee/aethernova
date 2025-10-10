import numpy as np
from typing import List, Dict, Optional
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field
from scipy.fft import fft, ifft
from scipy.signal import savgol_filter
from quantumpulse_core.utils.signal_tools import normalize_signal, detect_spike_anomalies
from quantumpulse_core.utils.qmath import QWaveAnalyzer
from quantumpulse_core.security.guardrails import spectrum_integrity_check
from quantumpulse_core.interfaces.model_loader import QuantumModelLoader
from quantumpulse_core.core.errors import WaveformPredictionError
import logging

logger = logging.getLogger("quantum.waveform_predictor")
logging.basicConfig(level=logging.INFO)

class WaveformInput(BaseModel):
    signal: List[float]
    signal_id: UUID = Field(default_factory=uuid4)
    source_tag: Optional[str] = "unlabeled"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, str]] = {}

class WaveformOutput(BaseModel):
    forecast: List[float]
    frequency_profile: Dict[str, float]
    noise_level: float
    anomaly_count: int
    qcomplexity: float
    confidence: float
    waveform_id: UUID = Field(default_factory=uuid4)
    issued_at: datetime = Field(default_factory=datetime.utcnow)

class WaveformPredictor:
    def __init__(self, model_loader: QuantumModelLoader, model_name: str = "waveform-forecast-v3"):
        self.model_loader = model_loader
        self.model_name = model_name
        self.model = None
        self.qanalyzer = QWaveAnalyzer()

    def initialize(self):
        try:
            self.model = self.model_loader.load(self.model_name)
            logger.info(f"Waveform prediction model '{self.model_name}' loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load model '{self.model_name}': {e}")
            raise WaveformPredictionError("Model loading failed") from e

    def predict(self, input_data: WaveformInput) -> WaveformOutput:
        if not self.model:
            raise WaveformPredictionError("Predictor model not initialized")

        logger.debug(f"Received signal of length {len(input_data.signal)} from source: {input_data.source_tag}")
        
        if not spectrum_integrity_check(input_data.signal):
            raise WaveformPredictionError("Signal failed spectrum integrity check")

        try:
            normalized_signal = normalize_signal(np.array(input_data.signal))
            filtered_signal = savgol_filter(normalized_signal, window_length=17, polyorder=3)
            qfeatures = self.qanalyzer.extract_features(filtered_signal)

            prediction = self.model.forecast(qfeatures)
            freq_spectrum = self.qanalyzer.analyze_spectrum(filtered_signal)
            qcomplexity = self.qanalyzer.calculate_complexity(filtered_signal)
            noise_level = self.qanalyzer.estimate_noise(filtered_signal)
            anomalies = detect_spike_anomalies(filtered_signal)

            return WaveformOutput(
                forecast=list(prediction),
                frequency_profile=freq_spectrum,
                noise_level=noise_level,
                anomaly_count=len(anomalies),
                qcomplexity=qcomplexity,
                confidence=self.model.estimate_confidence(qfeatures)
            )
        except Exception as e:
            logger.exception("Waveform prediction failed")
            raise WaveformPredictionError("Waveform prediction failed") from e
