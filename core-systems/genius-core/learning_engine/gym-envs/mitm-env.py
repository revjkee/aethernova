# genius-core/learning-engine/gym-envs/mitm-env.py

import gym
import numpy as np
from gym import spaces
from enum import Enum
import random

class NetworkState(Enum):
    NORMAL = 0
    DNS_SPOOF = 1
    ARP_POISON = 2
    SSL_STRIP = 3

class MitmEnv(gym.Env):
    """
    MITM-симулятор: тренирует агентов в условиях перехвата и защиты сетевого трафика.
    """
    def __init__(self):
        super(MitmEnv, self).__init__()
        self.max_steps = 100
        self.current_step = 0

        # Пространство наблюдений: состояние сети (one-hot) + чувствительность цели + уровень защиты
        self.observation_space = spaces.Box(low=0, high=1, shape=(6,), dtype=np.float32)

        # Пространство действий: перехват / защита
        self.action_space = spaces.Discrete(4)  # [0] ничего, [1] DNS spoof, [2] ARP poison, [3] SSL strip

        self.state = None
        self.done = False
        self.defense_enabled = False
        self.target_sensitive = True  # сценарий с важным трафиком

    def reset(self):
        self.current_step = 0
        self.done = False
        self.defense_enabled = random.choice([True, False])
        self.target_sensitive = random.choice([True, False])
        self.state = self._get_obs()
        return self.state

    def _get_obs(self):
        # one-hot состояние сети (только одно активно)
        net_state = np.zeros(4)
        net_state[0] = 1.0  # NORMAL
        sensitive = [1.0] if self.target_sensitive else [0.0]
        defense = [1.0] if self.defense_enabled else [0.0]
        return np.array(list(net_state) + sensitive + defense, dtype=np.float32)

    def step(self, action):
        self.current_step += 1

        if self.done:
            return self.state, 0.0, self.done, {}

        reward = 0.0
        info = {}

        if action == 0:
            reward = -0.1  # ничего не делает — маленький штраф
        elif action == 1:  # DNS spoof
            reward = self._simulate_attack("DNS")
        elif action == 2:  # ARP poison
            reward = self._simulate_attack("ARP")
        elif action == 3:  # SSL strip
            reward = self._simulate_attack("SSL")
        else:
            reward = -1.0  # невалидное действие

        self.done = self.current_step >= self.max_steps
        self.state = self._get_obs()
        return self.state, reward, self.done, info

    def _simulate_attack(self, attack_type):
        """
        Эмуляция MITM-атаки: результат зависит от включённой защиты и чувствительности цели.
        """
        base_reward = {
            "DNS": 1.0,
            "ARP": 1.5,
            "SSL": 2.0
        }.get(attack_type, 0.0)

        if self.defense_enabled:
            return -1.0  # атака блокирована
        elif not self.target_sensitive:
            return 0.1  # атака проходит, но цель незначима
        else:
            return base_reward  # успешный перехват

    def render(self, mode='human'):
        print(f"[{self.current_step}] State: {self.state}, Done: {self.done}")

    def close(self):
        pass
