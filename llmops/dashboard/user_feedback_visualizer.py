# llmops/dashboard/user_feedback_visualizer.py

import pandas as pd
import plotly.express as px
from fastapi import APIRouter, Query
from typing import Optional, List
from datetime import datetime
from pathlib import Path
import json

router = APIRouter()

# Конфигурация путей к данным
DATA_PATH = Path("llmops/data/feedback/feedback.jsonl")


def load_feedback_data(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    user_ids: Optional[List[str]] = None,
    metric_types: Optional[List[str]] = None
) -> pd.DataFrame:
    """
    Загружает и фильтрует данные обратной связи пользователей из JSONL.
    """
    if not DATA_PATH.exists():
        return pd.DataFrame()

    rows = []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
                rows.append(row)
            except json.JSONDecodeError:
                continue

    df = pd.DataFrame(rows)

    if df.empty:
        return df

    # Приведение типов
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    # Фильтрация по времени
    if start_date:
        df = df[df["timestamp"] >= start_date]
    if end_date:
        df = df[df["timestamp"] <= end_date]

    # Фильтрация по user_id
    if user_ids:
        df = df[df["user_id"].isin(user_ids)]

    # Фильтрация по метрике
    if metric_types:
        df = df[df["metric"].isin(metric_types)]

    return df


def generate_feedback_plot(df: pd.DataFrame):
    """
    Строит интерактивный график оценки пользовательской обратной связи.
    """
    if df.empty:
        return px.scatter(title="Нет данных для отображения")

    fig = px.line(
        df,
        x="timestamp",
        y="value",
        color="metric",
        line_group="user_id",
        hover_data=["user_id", "value", "prompt_id", "metric"],
        title="Динамика пользовательских оценок по времени"
    )
    fig.update_layout(height=600, template="plotly_white")
    return fig


@router.get("/feedback/plot")
def get_feedback_plot(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    user_ids: Optional[List[str]] = Query(None),
    metric_types: Optional[List[str]] = Query(None)
):
    """
    Endpoint: возвращает JSON-представление интерактивного графика.
    Используется на frontend (например, в React-дашборде).
    """
    df = load_feedback_data(start_date, end_date, user_ids, metric_types)
    fig = generate_feedback_plot(df)
    return fig.to_dict()
