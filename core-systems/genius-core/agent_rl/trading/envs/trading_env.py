import gym
import numpy as np
from typing import Tuple, Dict, Any, List
from gym.spaces import Box, Discrete

class TradingEnv(gym.Env):
    """
    Промышленная RL-среда для обучения торговых агентов.
    Включает:
    - мультифакторные наблюдения
    - адаптивную награду
    - продвинутую обработку состояний и сделок
    """

    metadata = {'render.modes': ['human']}

    def __init__(
        self,
        initial_balance: float = 10000.0,
        max_steps: int = 1000,
        trading_fee: float = 0.001,
        reward_mode: str = "pnl",  # ['pnl', 'sharpe', 'risk-adjusted']
        history_length: int = 50,
        symbol: str = "BTCUSDT"
    ):
        super().__init__()
        self.initial_balance = initial_balance
        self.balance = initial_balance
        self.max_steps = max_steps
        self.trading_fee = trading_fee
        self.reward_mode = reward_mode
        self.history_length = history_length
        self.symbol = symbol

        self.current_step = 0
        self.position = 0  # -1 short, 0 neutral, 1 long
        self.entry_price = 0.0

        self.prices = self._generate_mock_data()
        self.price_history = np.zeros((history_length, 6))  # price, rsi, macd, volume, volatility, returns

        self.action_space = Discrete(3)  # 0 = hold, 1 = buy, 2 = sell
        self.observation_space = Box(low=-np.inf, high=np.inf, shape=(history_length * 6 + 3,), dtype=np.float32)

        self.done = False

    def _generate_mock_data(self, total: int = 2000) -> np.ndarray:
        """ Имитация рыночных данных для тренировки. """
        prices = np.cumsum(np.random.normal(loc=0.0, scale=1.0, size=total)) + 29000
        returns = np.diff(prices, prepend=prices[0]) / prices[:-1]
        indicators = np.column_stack([
            prices,
            np.clip(np.random.normal(50, 10, size=total), 0, 100),  # RSI
            np.random.normal(0, 1, size=total),                     # MACD
            np.random.randint(50000, 200000, size=total),           # Volume
            np.random.uniform(0.01, 0.05, size=total),              # Volatility
            returns
        ])
        return indicators

    def reset(self) -> np.ndarray:
        self.balance = self.initial_balance
        self.current_step = self.history_length
        self.position = 0
        self.entry_price = 0.0
        self.done = False
        self.price_history = self.prices[self.current_step - self.history_length:self.current_step]
        return self._get_observation()

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict[str, Any]]:
        assert self.action_space.contains(action)
        prev_price = self.prices[self.current_step - 1][0]
        price = self.prices[self.current_step][0]

        reward = 0.0
        info = {}

        if action == 1:  # Buy
            if self.position == 0:
                self.position = 1
                self.entry_price = price
            elif self.position == -1:
                pnl = self.entry_price - price
                reward = self._calculate_reward(pnl)
                self.balance += pnl
                self.position = 0

        elif action == 2:  # Sell
            if self.position == 0:
                self.position = -1
                self.entry_price = price
            elif self.position == 1:
                pnl = price - self.entry_price
                reward = self._calculate_reward(pnl)
                self.balance += pnl
                self.position = 0

        else:  # Hold
            reward = 0.0

        self.current_step += 1
        if self.current_step >= len(self.prices) or self.current_step >= self.max_steps:
            self.done = True

        self.price_history = self.prices[self.current_step - self.history_length:self.current_step]
        return self._get_observation(), reward, self.done, info

    def _calculate_reward(self, pnl: float) -> float:
        """ Вычисление награды на основе выбранного режима. """
        if self.reward_mode == "pnl":
            return pnl - abs(pnl) * self.trading_fee
        elif self.reward_mode == "sharpe":
            return pnl / (np.std(self.price_history[:, 5]) + 1e-8)
        elif self.reward_mode == "risk-adjusted":
            return pnl / (np.abs(pnl) + 0.01)
        return pnl

    def _get_observation(self) -> np.ndarray:
        flat_history = self.price_history.flatten()
        obs = np.concatenate([
            flat_history,
            np.array([self.balance, self.position, self.entry_price], dtype=np.float32)
        ])
        return obs

    def render(self, mode='human'):
        price = self.prices[self.current_step][0]
        print(f"[{self.symbol}] Step: {self.current_step}, Price: {price:.2f}, Position: {self.position}, Balance: {self.balance:.2f}")

    def close(self):
        pass
