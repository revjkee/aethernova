# genius-core/learning-engine/replay-buffer/priority_buffer.py

import numpy as np
import random
import threading

class PrioritizedReplayBuffer:
    """
    Приоритетный буфер воспроизведения для опыта в RL с поддержкой
    приоритетного семплинга и обновления приоритетов по TD ошибкам.

    Источник концепции: Schaul et al., "Prioritized Experience Replay", 2015.
    """

    def __init__(self, capacity: int, alpha: float = 0.6, beta_start: float = 0.4, beta_frames: int = 100000):
        """
        :param capacity: Максимальное количество элементов в буфере
        :param alpha: Степень приоритета (0 - равномерный выбор, 1 - жёсткий приоритет)
        :param beta_start: Начальное значение параметра коррекции смещения (importance-sampling)
        :param beta_frames: Количество кадров для линейного роста beta от beta_start до 1
        """
        self.capacity = capacity
        self.alpha = alpha
        self.beta_start = beta_start
        self.beta_frames = beta_frames
        self.buffer = []
        self.priorities = np.zeros((capacity,), dtype=np.float32)
        self.pos = 0
        self.lock = threading.Lock()
        self.frame = 1  # Счётчик обращений для изменения beta

    def push(self, experience):
        """
        Добавить новый опыт в буфер с максимальным приоритетом.
        :param experience: Кортеж (state, action, reward, next_state, done)
        """
        with self.lock:
            max_priority = self.priorities.max() if self.buffer else 1.0

            if len(self.buffer) < self.capacity:
                self.buffer.append(experience)
            else:
                self.buffer[self.pos] = experience

            self.priorities[self.pos] = max_priority
            self.pos = (self.pos + 1) % self.capacity

    def sample(self, batch_size: int):
        """
        Семплирование мини-батча с приоритетным распределением.
        Возвращает батч и веса для коррекции смещения.
        """
        with self.lock:
            if len(self.buffer) == self.capacity:
                prios = self.priorities
            else:
                prios = self.priorities[:self.pos]

            probs = prios ** self.alpha
            probs /= probs.sum()

            indices = np.random.choice(len(self.buffer), batch_size, p=probs)
            samples = [self.buffer[idx] for idx in indices]

            beta = min(1.0, self.beta_start + (1.0 - self.beta_start) * self.frame / self.beta_frames)
            self.frame += 1

            weights = (len(self.buffer) * probs[indices]) ** (-beta)
            weights /= weights.max()
            weights = np.array(weights, dtype=np.float32)

            return samples, indices, weights

    def update_priorities(self, indices, priorities):
        """
        Обновление приоритетов после вычисления TD ошибок.
        :param indices: Индексы семплированных элементов
        :param priorities: Новые приоритеты (TD ошибки)
        """
        with self.lock:
            for idx, priority in zip(indices, priorities):
                self.priorities[idx] = priority

    def __len__(self):
        return len(self.buffer)
