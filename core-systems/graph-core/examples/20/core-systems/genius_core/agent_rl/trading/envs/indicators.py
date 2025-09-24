import numpy as np
import pandas as pd
from typing import Union, Tuple

class TechnicalIndicators:
    """
    Промышленный модуль вычисления технических индикаторов.
    Поддерживает:
    - RSI
    - MACD
    - EMA
    - Базовые предобработки
    - Проверка на выбросы и NaN
    """

    def __init__(self, price_series: Union[np.ndarray, pd.Series]):
        if isinstance(price_series, np.ndarray):
            self.prices = pd.Series(price_series)
        else:
            self.prices = price_series.copy()

        self._clean_data()
        self.results = {}

    def _clean_data(self):
        self.prices = self.prices.replace([np.inf, -np.inf], np.nan).dropna()
        self.prices = self.prices.clip(lower=0.01)

    def compute_ema(self, window: int = 14) -> pd.Series:
        ema = self.prices.ewm(span=window, adjust=False).mean()
        self.results[f'ema_{window}'] = ema
        return ema

    def compute_rsi(self, period: int = 14) -> pd.Series:
        delta = self.prices.diff()
        up = delta.clip(lower=0)
        down = -1 * delta.clip(upper=0)

        ma_up = up.rolling(window=period, min_periods=period).mean()
        ma_down = down.rolling(window=period, min_periods=period).mean()

        rs = ma_up / (ma_down + 1e-8)
        rsi = 100 - (100 / (1 + rs))

        self.results[f'rsi_{period}'] = rsi
        return rsi

    def compute_macd(self, fast: int = 12, slow: int = 26, signal: int = 9) -> Tuple[pd.Series, pd.Series]:
        ema_fast = self.prices.ewm(span=fast, adjust=False).mean()
        ema_slow = self.prices.ewm(span=slow, adjust=False).mean()

        macd_line = ema_fast - ema_slow
        signal_line = macd_line.ewm(span=signal, adjust=False).mean()

        self.results['macd'] = macd_line
        self.results['macd_signal'] = signal_line
        return macd_line, signal_line

    def compute_all(self) -> pd.DataFrame:
        self.compute_rsi()
        self.compute_ema(14)
        self.compute_ema(50)
        self.compute_macd()
        return pd.DataFrame(self.results)

    def as_numpy(self) -> np.ndarray:
        return self.compute_all().dropna().values.astype(np.float32)


# Пример использования:
if __name__ == "__main__":
    prices = np.random.normal(100, 1, 200)
    ti = TechnicalIndicators(prices)
    indicators_df = ti.compute_all()
    print(indicators_df.tail())
