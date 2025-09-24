# genius-core/learning-engine/gym-envs/env_utils.py

import gym
import numpy as np
from typing import Optional, Tuple

def make_env(env_id: str, seed: Optional[int] = None, render_mode: Optional[str] = None) -> gym.Env:
    """
    Создание и инициализация Gym-окружения с опциональной установкой seed и режима рендера.
    
    :param env_id: Идентификатор среды (например, "CartPole-v1")
    :param seed: Опциональное значение seed для воспроизводимости
    :param render_mode: Опциональный режим рендера (например, "human", "rgb_array")
    :return: Инициализированное Gym-окружение
    """
    env = gym.make(env_id, render_mode=render_mode) if render_mode else gym.make(env_id)
    if seed is not None:
        env.seed(seed)
        env.action_space.seed(seed)
        env.observation_space.seed(seed)
    return env

def preprocess_observation(obs: np.ndarray, normalize: bool = True) -> np.ndarray:
    """
    Предобработка наблюдения из окружения для подачи в модель.
    
    :param obs: Наблюдение (обычно numpy array)
    :param normalize: Нормализовать ли вход (в диапазон [0,1])
    :return: Обработанное наблюдение
    """
    if normalize:
        if obs.dtype == np.uint8:
            obs = obs.astype(np.float32) / 255.0
        else:
            obs = (obs - np.min(obs)) / (np.ptp(obs) + 1e-8)
    return obs

def stack_frames(frames: list, max_frames: int = 4) -> np.ndarray:
    """
    Создание стека кадров для временной информации (используется в Atari и других задачах).
    
    :param frames: Список numpy-массивов кадров
    :param max_frames: Максимальное количество кадров в стеке
    :return: numpy array с размерами (max_frames, H, W) или (H, W, max_frames) в зависимости от формата
    """
    assert len(frames) <= max_frames, "Количество кадров не должно превышать max_frames"
    while len(frames) < max_frames:
        frames.insert(0, frames[0])  # Повторяем первый кадр для заполнения стека

    return np.stack(frames, axis=0)

def calculate_discounted_returns(rewards: list, gamma: float) -> np.ndarray:
    """
    Вычисление дисконтированных суммарных вознаграждений (returns) для эпизода.
    
    :param rewards: Список наград за эпизод
    :param gamma: Дисконтирующий коэффициент (0 < gamma <= 1)
    :return: numpy array с дисконтированными суммами
    """
    discounted = np.zeros_like(rewards, dtype=np.float32)
    running_sum = 0.0
    for t in reversed(range(len(rewards))):
        running_sum = rewards[t] + gamma * running_sum
        discounted[t] = running_sum
    return discounted

def clip_action(action: np.ndarray, action_space: gym.spaces.Space) -> np.ndarray:
    """
    Ограничение действий в допустимых границах action_space.
    
    :param action: Массив действий
    :param action_space: Пространство действий окружения
    :return: Ограниченное действие
    """
    if hasattr(action_space, "low") and hasattr(action_space, "high"):
        return np.clip(action, action_space.low, action_space.high)
    return action

def is_done(info: dict) -> bool:
    """
    Проверка по дополнительной информации из окружения, завершился ли эпизод.
    
    :param info: Словарь с информацией от окружения
    :return: True если эпизод завершён, False иначе
    """
    # В Gym часто 'done' возвращается отдельно, но иногда полезно проверить дополнительные сигналы
    return info.get('done', False) or info.get('TimeLimit.truncated', False)

