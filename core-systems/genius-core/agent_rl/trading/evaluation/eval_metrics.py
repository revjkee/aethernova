# agent_rl/trading/evaluation/eval_metrics.py

import numpy as np
import pandas as pd
from typing import Dict, Union


def calculate_pnl(returns: Union[np.ndarray, pd.Series]) -> float:
    return float(np.sum(returns))


def calculate_sharpe(returns: Union[np.ndarray, pd.Series], risk_free_rate: float = 0.0) -> float:
    excess_returns = returns - risk_free_rate
    std = np.std(excess_returns)
    if std == 0:
        return 0.0
    return float(np.mean(excess_returns) / std * np.sqrt(252))


def calculate_sortino(returns: Union[np.ndarray, pd.Series], risk_free_rate: float = 0.0) -> float:
    downside = returns[returns < risk_free_rate]
    std_down = np.std(downside) if len(downside) > 0 else 0.0
    if std_down == 0:
        return 0.0
    return float((np.mean(returns - risk_free_rate)) / std_down * np.sqrt(252))


def calculate_volatility(returns: Union[np.ndarray, pd.Series]) -> float:
    return float(np.std(returns) * np.sqrt(252))


def calculate_max_drawdown(equity_curve: Union[np.ndarray, pd.Series]) -> float:
    peak = np.maximum.accumulate(equity_curve)
    drawdown = (peak - equity_curve) / peak
    return float(np.max(drawdown))


def calculate_mar(pnl: float, max_drawdown: float) -> float:
    return float(pnl / max_drawdown) if max_drawdown > 0 else 0.0


def evaluate_all_metrics(
    returns: Union[np.ndarray, pd.Series],
    equity_curve: Union[np.ndarray, pd.Series],
    risk_free_rate: float = 0.0
) -> Dict[str, float]:
    pnl = calculate_pnl(returns)
    sharpe = calculate_sharpe(returns, risk_free_rate)
    sortino = calculate_sortino(returns, risk_free_rate)
    vol = calculate_volatility(returns)
    mdd = calculate_max_drawdown(equity_curve)
    mar = calculate_mar(pnl, mdd)

    return {
        "PnL": pnl,
        "Sharpe Ratio": sharpe,
        "Sortino Ratio": sortino,
        "Volatility": vol,
        "Max Drawdown": mdd,
        "MAR Ratio": mar
    }
