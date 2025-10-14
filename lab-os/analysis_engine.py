"""
Analysis Engine - автоматический анализ данных экспериментов
"""
from typing import Dict, List, Any, Optional
import numpy as np
from scipy import stats
from dataclasses import dataclass

@dataclass
class AnalysisResult:
    experiment_id: str
    analysis_type: str
    results: Dict[str, Any]
    statistics: Dict[str, float]
    visualizations: List[str]
    interpretation: str

class AnalysisEngine:
    def __init__(self):
        self.results: Dict[str, AnalysisResult] = {}
        
    def analyze_experiment(self, experiment_id: str, data: Dict[str, List[float]], 
                          analysis_types: List[str] = None) -> AnalysisResult:
        if analysis_types is None:
            analysis_types = ['descriptive', 'correlation']
        
        results = {}
        statistics = {}
        
        for key, values in data.items():
            if not values:
                continue
            arr = np.array(values)
            statistics[f"{key}_mean"] = float(np.mean(arr))
            statistics[f"{key}_std"] = float(np.std(arr))
            statistics[f"{key}_min"] = float(np.min(arr))
            statistics[f"{key}_max"] = float(np.max(arr))
        
        if 'correlation' in analysis_types and len(data) >= 2:
            keys = list(data.keys())
            if len(keys) >= 2:
                x, y = np.array(data[keys[0]]), np.array(data[keys[1]])
                if len(x) == len(y) and len(x) > 1:
                    corr, p_value = stats.pearsonr(x, y)
                    statistics['correlation'] = float(corr)
                    statistics['p_value'] = float(p_value)
        
        result = AnalysisResult(
            experiment_id=experiment_id,
            analysis_type=', '.join(analysis_types),
            results=results,
            statistics=statistics,
            visualizations=[],
            interpretation=self._generate_interpretation(statistics)
        )
        
        self.results[experiment_id] = result
        return result
    
    def _generate_interpretation(self, stats: Dict[str, float]) -> str:
        interpretations = []
        for key, value in stats.items():
            if 'mean' in key:
                interpretations.append(f"{key}: {value:.2f}")
        return "; ".join(interpretations)
    
    def get_analysis(self, experiment_id: str) -> Optional[AnalysisResult]:
        return self.results.get(experiment_id)
    
    def compare_experiments(self, exp_ids: List[str]) -> Dict[str, Any]:
        comparisons = {}
        for exp_id in exp_ids:
            if exp_id in self.results:
                comparisons[exp_id] = self.results[exp_id].statistics
        return comparisons
