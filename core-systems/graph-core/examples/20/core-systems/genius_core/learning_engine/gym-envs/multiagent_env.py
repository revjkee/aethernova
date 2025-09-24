# genius-core/learning-engine/gym-envs/multiagent_env.py

import gym
from gym import spaces
import numpy as np

class MultiAgentEnv(gym.Env):
    """
    Пример многоконтурной среды для self-play.
    Среда поддерживает несколько агентов с собственными наблюдениями и действиями.
    """

    metadata = {'render.modes': ['human']}

    def __init__(self, num_agents=2, state_dim=10, action_dim=3, max_steps=100):
        super(MultiAgentEnv, self).__init__()

        self.num_agents = num_agents
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.max_steps = max_steps

        # Пространство наблюдений для каждого агента
        self.observation_spaces = [spaces.Box(low=-np.inf, high=np.inf, shape=(state_dim,), dtype=np.float32) for _ in range(num_agents)]
        # Пространство действий для каждого агента (дискретное или непрерывное)
        self.action_spaces = [spaces.Box(low=-1, high=1, shape=(action_dim,), dtype=np.float32) for _ in range(num_agents)]

        self.current_step = 0
        self.state = None

    def reset(self):
        """
        Сброс среды и состояний для всех агентов.
        Возвращает список наблюдений для каждого агента.
        """
        self.current_step = 0
        self.state = np.random.randn(self.num_agents, self.state_dim).astype(np.float32)
        return [self.state[i] for i in range(self.num_agents)]

    def step(self, actions):
        """
        Получает список действий от каждого агента.
        Возвращает tuple (наблюдения, вознаграждения, done, info) для каждого агента.
        """

        assert len(actions) == self.num_agents, "Количество действий должно соответствовать количеству агентов"

        self.current_step += 1

        # Пример обновления состояния: простое прибавление действия к состоянию
        for i in range(self.num_agents):
            self.state[i] = self.state[i] + actions[i]

        # Пример вознаграждения: отрицание нормы действия (за минимизацию усилий)
        rewards = [-np.linalg.norm(action) for action in actions]

        done = self.current_step >= self.max_steps

        # Пример информации (пустой словарь для каждого агента)
        info = [{} for _ in range(self.num_agents)]

        observations = [self.state[i] for i in range(self.num_agents)]

        return observations, rewards, done, info

    def render(self, mode='human'):
        # Пример простой печати состояния среды
        print(f"Step: {self.current_step}")
        for i in range(self.num_agents):
            print(f"Agent {i} state: {self.state[i]}")

    def close(self):
        pass
