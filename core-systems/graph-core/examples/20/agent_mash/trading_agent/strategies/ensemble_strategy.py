# ensemble_strategy.py

from typing import List, Dict, Any, Optional
from .base_strategy import BaseStrategy, Signal


class EnsembleStrategy(BaseStrategy):
    """
    Ансамблевая стратегия: агрегирует сигналы от нескольких подстратегий с учётом весов и уверенности.
    """

    def __init__(self, strategies: List[BaseStrategy], parameters: Optional[Dict[str, Any]] = None):
        super().__init__(parameters)
        self.strategies = strategies
        self.weights = self.params.get("weights", [1.0 for _ in strategies])
        assert len(self.strategies) == len(self.weights), "Количество стратегий и весов должно совпадать"

    def default_parameters(self) -> Dict[str, Any]:
        return {
            "confidence_threshold": 0.65,
            "risk_limit": 0.02,
            "conflict_resolution": "confidence",  # или "majority"
        }

    def aggregate_signals(self, signals: List[Signal]) -> Signal:
        """
        Агрегирует входящие сигналы в итоговый.
        """
        scores = {"buy": 0.0, "sell": 0.0, "hold": 0.0}
        meta = {"sources": []}

        for i, signal in enumerate(signals):
            weight = self.weights[i]
            weighted_score = signal.confidence * weight
            scores[signal.action] += weighted_score
            meta["sources"].append({
                "strategy": self.strategies[i].__class__.__name__,
                "signal": signal.action,
                "confidence": signal.confidence
            })

        final_action = max(scores, key=scores.get)
        total_score = scores[final_action]
        total_weight = sum(self.weights)
        final_confidence = round(total_score / total_weight, 4)

        return Signal(
            action=final_action,
            confidence=final_confidence,
            metadata=meta
        )

    def generate_signal(self, market_data: Dict[str, Any]) -> Signal:
        individual_signals = []
        for strategy in self.strategies:
            try:
                signal = strategy.generate_signal(market_data)
                individual_signals.append(signal)
            except Exception as e:
                individual_signals.append(Signal("hold", 0.0, metadata={"error": str(e)}))

        aggregated = self.aggregate_signals(individual_signals)
        self.state.last_signal = aggregated.action
        return aggregated
