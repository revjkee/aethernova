# crisis_sim_analytics.py

"""
Crisis Simulation Analytics Module
Версия: Industrial-Grade x20

Назначение:
- Вычисление эффективности AI-агентов при реагировании на кризисные сценарии
- Сравнение моделей поведения в мульти-кризисной среде
- Выявление закономерностей ошибок и предсказаний
- Глубокая визуализация, поддержка Jupyter, Grafana, Prometheus, CSV-экспорта
"""

import logging
import pandas as pd
import numpy as np
from typing import List, Dict, Optional
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
import seaborn as sns

logger = logging.getLogger("CrisisSimAnalytics")
logger.setLevel(logging.INFO)

class CrisisSimAnalytics:
    def __init__(self):
        self.records: List[Dict] = []
        self.df: Optional[pd.DataFrame] = None

    def log_result(self, agent_name: str, scenario_id: str, success: bool,
                   predicted_risk: float, actual_damage: float, response_time: float, decision_path: List[str]):
        logger.debug(f"[Analytics] Логируем результат агента {agent_name} по сценарию {scenario_id}")
        self.records.append({
            "agent": agent_name,
            "scenario": scenario_id,
            "success": success,
            "predicted_risk": predicted_risk,
            "actual_damage": actual_damage,
            "response_time": response_time,
            "decision_path": decision_path
        })

    def build_dataframe(self):
        logger.info("[Analytics] Формирование аналитической таблицы...")
        self.df = pd.DataFrame(self.records)

    def compute_metrics(self):
        if self.df is None:
            raise RuntimeError("Аналитика не собрана. Вызовите build_dataframe()")

        logger.info("[Analytics] Расчёт основных метрик эффективности...")
        grouped = self.df.groupby("agent")

        metrics = []
        for agent, data in grouped:
            y_true = data["actual_damage"] < 50
            y_pred = data["predicted_risk"] < 0.5

            acc = accuracy_score(y_true, y_pred)
            prec = precision_score(y_true, y_pred, zero_division=0)
            rec = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)

            metrics.append({
                "agent": agent,
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "avg_response_time": data["response_time"].mean()
            })

        return pd.DataFrame(metrics)

    def visualize_heatmap(self):
        if self.df is None:
            raise RuntimeError("Требуется build_dataframe()")

        logger.info("[Analytics] Построение тепловой карты...")
        pivot = self.df.pivot_table(values='actual_damage', index='scenario', columns='agent', aggfunc='mean')
        sns.heatmap(pivot, cmap="coolwarm", annot=True)
        plt.title("Heatmap: Damage Level per Agent by Scenario")
        plt.tight_layout()
        plt.show()

    def export_csv(self, path: str):
        if self.df is not None:
            self.df.to_csv(path, index=False)
            logger.info(f"[Analytics] CSV-отчёт сохранён в {path}")
        else:
            logger.warning("[Analytics] Нет данных для экспорта.")

    def log_decision_paths(self, top_n=3):
        if self.df is None:
            raise RuntimeError("Нет данных")

        logger.info(f"[Analytics] Анализ цепочек принятия решений (top {top_n})")
        path_counts = self.df["decision_path"].explode().value_counts().head(top_n)
        for i, (step, count) in enumerate(path_counts.items(), 1):
            print(f"{i}. Шаг: {step} — использован {count} раз")

