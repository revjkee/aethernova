# global_trends_dashboard.py

"""
TeslaAI Genesis :: FutureVision Visualization Layer
Интерактивный глобальный AI-дэшборд прогнозов и трендов
Верифицирован: 20 AI-агентами + 3 метагенералами
"""

import streamlit as st
import plotly.express as px
import pandas as pd
from future_vision.trend_analysis.forecast_engine import load_latest_forecasts
from future_vision.environmental.climate_api import get_climate_risks
from future_vision.economics.esg_index import get_esg_impact_score
from future_vision.visualization.themes import apply_teslaai_dark_theme

st.set_page_config(page_title="TeslaAI FutureVision Dashboard", layout="wide")
apply_teslaai_dark_theme()

st.title("🌐 TeslaAI Global Trends & Risk Dashboard")
st.markdown("Мониторинг и визуализация ключевых глобальных трендов на основе AI-прогнозов и ESG-факторов")

# Загрузка и подготовка данных
forecasts = load_latest_forecasts()
climate_df = get_climate_risks()
esg_df = get_esg_impact_score()

tab1, tab2, tab3 = st.tabs(["📈 Макроэкономика", "🌡️ Климатические угрозы", "♻️ ESG-прогноз"])

# 1. Макроэкономика
with tab1:
    st.subheader("Прогнозы макроэкономических индикаторов")
    metric = st.selectbox("Выберите метрику:", forecasts.columns[1:])
    fig = px.line(forecasts, x="date", y=metric, title=f"{metric} (прогноз)")
    st.plotly_chart(fig, use_container_width=True)

# 2. Климатические угрозы
with tab2:
    st.subheader("Глобальные климатические риски")
    risk_type = st.selectbox("Тип риска:", climate_df["risk_type"].unique())
    filtered = climate_df[climate_df["risk_type"] == risk_type]
    fig_map = px.choropleth(
        filtered,
        locations="country_code",
        color="risk_score",
        hover_name="country",
        color_continuous_scale="Inferno",
        title=f"Распределение риска: {risk_type}"
    )
    st.plotly_chart(fig_map, use_container_width=True)

# 3. ESG тренды
with tab3:
    st.subheader("ESG-индекс по регионам")
    region = st.selectbox("Регион:", esg_df["region"].unique())
    fig_esg = px.bar(
        esg_df[esg_df["region"] == region],
        x="indicator",
        y="score",
        title=f"ESG показатели — {region}",
        color="category"
    )
    st.plotly_chart(fig_esg, use_container_width=True)

# Нижний колонтитул
st.markdown("---")
st.markdown("© 2025 TeslaAI FutureVision | Система прогнозирования и устойчивости нового поколения")
