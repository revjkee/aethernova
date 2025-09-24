# telegram-bot/ai-assistant/rl_planner_v2.py

import asyncio
from typing import List, Dict, Any, Optional
import random
import time

class RLPlannerV2:
    """
    Новый: улучшенный RL планировщик для Telegram AI ассистента.
    Обрабатывает задачи, приоритизацию, планирование и адаптацию на основе 
    Q-learning и эвристик для максимально эффективного распределения ресурсов.
    """

    def __init__(self, actions: List[str], learning_rate: float = 0.1, discount_factor: float = 0.9, exploration_rate: float = 0.2):
        self.actions = actions
        self.learning_rate = learning_rate      # скорость обучения α
        self.discount_factor = discount_factor  # фактор дисконтирования γ
        self.exploration_rate = exploration_rate # вероятность исследования ε
        self.q_table: Dict[str, Dict[str, float]] = {}  # Q-таблица: состояние -> действие -> ценность
        self.current_state: Optional[str] = None

    def _get_state_key(self, state: Dict[str, Any]) -> str:
        """
        Генерирует ключ состояния из словаря.
        """
        # Пример: упрощённое сериализованное состояние (можно усложнить)
        keys = sorted(state.keys())
        return "|".join(f"{k}:{state[k]}" for k in keys)

    def select_action(self, state: Dict[str, Any]) -> str:
        """
        Выбор действия на основе ε-жадной стратегии.
        """
        state_key = self._get_state_key(state)
        self.current_state = state_key

        if state_key not in self.q_table:
            self.q_table[state_key] = {a: 0.0 for a in self.actions}

        # Исследование или использование
        if random.random() < self.exploration_rate:
            action = random.choice(self.actions)
        else:
            max_value = max(self.q_table[state_key].values())
            best_actions = [a for a, v in self.q_table[state_key].items() if v == max_value]
            action = random.choice(best_actions)
        return action

    def update_q_value(self, state: Dict[str, Any], action: str, reward: float, next_state: Dict[str, Any]) -> None:
        """
        Обновляет Q-значение по формуле Q-learning.
        """
        state_key = self._get_state_key(state)
        next_state_key = self._get_state_key(next_state)

        if state_key not in self.q_table:
            self.q_table[state_key] = {a: 0.0 for a in self.actions}
        if next_state_key not in self.q_table:
            self.q_table[next_state_key] = {a: 0.0 for a in self.actions}

        old_value = self.q_table[state_key][action]
        next_max = max(self.q_table[next_state_key].values())

        new_value = old_value + self.learning_rate * (reward + self.discount_factor * next_max - old_value)
        self.q_table[state_key][action] = new_value

    async def plan(self, initial_state: Dict[str, Any], max_steps: int = 50) -> List[str]:
        """
        Асинхронное планирование с учётом адаптации и обучения.
        Возвращает список действий.
        """
        state = initial_state
        actions_taken = []

        for _ in range(max_steps):
            action = self.select_action(state)
            actions_taken.append(action)

            reward, next_state = await self.execute_action(state, action)

            self.update_q_value(state, action, reward, next_state)
            state = next_state

            # Можно добавить условия прерывания, если достигнута цель
            if reward >= 1.0:
                break

        return actions_taken

    async def execute_action(self, state: Dict[str, Any], action: str) -> (float, Dict[str, Any]):
        """
        Выполняет действие, возвращает награду и новое состояние.
        Заглушка, которую нужно заменить на реальную логику взаимодействия.
        """
        await asyncio.sleep(0.05)  # эмуляция задержки выполнения

        # Пример простой логики награды и изменения состояния
        reward = random.uniform(-0.1, 1.0)  # случайная награда для обучения
        new_state = state.copy()

        # Эвристика изменения состояния (пример)
        if action == "prioritize_task":
            new_state["pending_tasks"] = max(0, state.get("pending_tasks", 0) - 1)
        elif action == "gather_info":
            new_state["info_level"] = min(10, state.get("info_level", 0) + 1)
        elif action == "request_user_feedback":
            new_state["user_feedback"] = True

        return reward, new_state

    def save_q_table(self, filepath: str) -> None:
        """
        Сохраняет Q-таблицу в файл JSON.
        """
        import json
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.q_table, f, ensure_ascii=False, indent=4)

    def load_q_table(self, filepath: str) -> None:
        """
        Загружает Q-таблицу из файла JSON.
        """
        import json
        with open(filepath, "r", encoding="utf-8") as f:
            self.q_table = json.load(f)



