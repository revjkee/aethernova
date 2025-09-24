# genius-core/learning-engine/agent_rl/utils.py

import numpy as np
import torch
import random
import os
import logging
from collections import deque
from typing import Tuple, List


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def set_global_seed(seed: int) -> None:
    """
    Устанавливает фиксированный seed для воспроизводимости.
    """
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    logger.info(f"Global seed set to {seed}")


def normalize_state(state: np.ndarray, mean: float = 0.0, std: float = 1.0) -> np.ndarray:
    """
    Нормализация состояния (например, наблюдений среды).
    """
    norm_state = (state - mean) / (std + 1e-8)
    return np.clip(norm_state, -10, 10)


def soft_update(target_net, source_net, tau: float) -> None:
    """
    Плавное обновление весов target-сети.
    """
    for target_param, source_param in zip(target_net.parameters(), source_net.parameters()):
        target_param.data.copy_(tau * source_param.data + (1.0 - tau) * target_param.data)


def hard_update(target_net, source_net) -> None:
    """
    Полное копирование весов из source в target.
    """
    target_net.load_state_dict(source_net.state_dict())


class ReplayBuffer:
    """
    Буфер воспроизведения для хранения переходов (опытов) агента.
    """
    def __init__(self, capacity: int):
        self.buffer = deque(maxlen=capacity)

    def push(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size: int) -> Tuple:
        batch = random.sample(self.buffer, batch_size)
        state, action, reward, next_state, done = map(np.array, zip(*batch))
        return state, action, reward, next_state, done

    def __len__(self) -> int:
        return len(self.buffer)


def compute_td_error(q_values, next_q_values, rewards, dones, gamma: float) -> torch.Tensor:
    """
    Расчёт TD-ошибки.
    """
    target = rewards + (1 - dones) * gamma * next_q_values
    return (q_values - target.detach()).pow(2).mean()


def log_metrics(episode: int, reward: float, loss: float = None, success_rate: float = None) -> None:
    """
    Логирование метрик для мониторинга RL-обучения.
    """
    message = f"[Episode {episode}] Reward: {reward:.2f}"
    if loss is not None:
        message += f" | Loss: {loss:.4f}"
    if success_rate is not None:
        message += f" | Success Rate: {success_rate:.2%}"
    logger.info(message)


def epsilon_greedy_action(q_values: np.ndarray, epsilon: float) -> int:
    """
    Epsilon-greedy стратегия выбора действия.
    """
    if random.random() < epsilon:
        return random.randint(0, len(q_values) - 1)
    return int(np.argmax(q_values))


def check_nan_gradients(model) -> bool:
    """
    Проверка на наличие NaN-градиентов.
    """
    for param in model.parameters():
        if param.grad is not None and torch.isnan(param.grad).any():
            logger.warning("Detected NaN gradients.")
            return True
    return False
