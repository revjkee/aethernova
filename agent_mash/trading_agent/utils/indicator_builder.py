# indicator_builder.py

import numpy as np
import pandas as pd
from typing import Union, Dict, Any

class IndicatorBuilder:
    """
    Промышленный генератор технических индикаторов.
    Принимает DataFrame с колонками: open, high, low, close, volume.
    """

    def __init__(self, data: pd.DataFrame):
        required = {"open", "high", "low", "close", "volume"}
        if not required.issubset(data.columns):
            raise ValueError(f"Ожидаются колонки: {required}")
        self.data = data

    def rsi(self, period: int = 14) -> pd.Series:
        delta = self.data['close'].diff()
        gain = np.where(delta > 0, delta, 0)
        loss = np.where(delta < 0, -delta, 0)
        roll_up = pd.Series(gain).rolling(window=period).mean()
        roll_down = pd.Series(loss).rolling(window=period).mean()
        rs = roll_up / (roll_down + 1e-9)
        return 100 - (100 / (1 + rs))

    def ema(self, period: int = 20, column: str = "close") -> pd.Series:
        return self.data[column].ewm(span=period, adjust=False).mean()

    def sma(self, period: int = 20, column: str = "close") -> pd.Series:
        return self.data[column].rolling(window=period).mean()

    def macd(self, fast: int = 12, slow: int = 26, signal: int = 9) -> Dict[str, pd.Series]:
        ema_fast = self.ema(period=fast)
        ema_slow = self.ema(period=slow)
        macd_line = ema_fast - ema_slow
        signal_line = macd_line.ewm(span=signal, adjust=False).mean()
        histogram = macd_line - signal_line
        return {
            "macd": macd_line,
            "signal": signal_line,
            "histogram": histogram
        }

    def atr(self, period: int = 14) -> pd.Series:
        high_low = self.data['high'] - self.data['low']
        high_close = np.abs(self.data['high'] - self.data['close'].shift())
        low_close = np.abs(self.data['low'] - self.data['close'].shift())
        tr = pd.concat([high_low, high_close, low_close], axis=1).max(axis=1)
        return tr.rolling(window=period).mean()

    def bollinger_bands(self, period: int = 20, std_multiplier: float = 2.0) -> Dict[str, pd.Series]:
        sma = self.sma(period)
        std = self.data['close'].rolling(window=period).std()
        upper = sma + std_multiplier * std
        lower = sma - std_multiplier * std
        return {"upper_band": upper, "lower_band": lower, "middle_band": sma}

    def stochastic_oscillator(self, k_period: int = 14, d_period: int = 3) -> Dict[str, pd.Series]:
        low_min = self.data['low'].rolling(window=k_period).min()
        high_max = self.data['high'].rolling(window=k_period).max()
        k = 100 * (self.data['close'] - low_min) / (high_max - low_min + 1e-9)
        d = k.rolling(window=d_period).mean()
        return {"%K": k, "%D": d}

    def all_indicators(self) -> pd.DataFrame:
        """
        Возвращает DataFrame со всеми основными индикаторами.
        """
        df = pd.DataFrame(index=self.data.index)
        df["rsi"] = self.rsi()
        df["ema20"] = self.ema(20)
        df["ema50"] = self.ema(50)
        df["sma20"] = self.sma(20)
        df["atr14"] = self.atr(14)

        macd = self.macd()
        for k, v in macd.items():
            df[f"macd_{k}"] = v

        bb = self.bollinger_bands()
        df["bb_upper"] = bb["upper_band"]
        df["bb_lower"] = bb["lower_band"]

        so = self.stochastic_oscillator()
        df["stoch_k"] = so["%K"]
        df["stoch_d"] = so["%D"]

        return df

    def describe(self) -> Dict[str, Any]:
        return {
            "indicators": [
                "rsi", "ema", "sma", "macd", "atr", "bollinger_bands", "stochastic_oscillator"
            ],
            "columns_required": ["open", "high", "low", "close", "volume"]
        }
