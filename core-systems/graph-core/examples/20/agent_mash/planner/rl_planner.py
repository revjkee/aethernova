import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any

from agent_mash.core.policies import RLPolicy
from agent_mash.core.environment import WorldState
from agent_mash.utils.global_state import GlobalStateManager
from agent_mash.security.ethics_filter import EthicsGuard
from agent_mash.metrics.tracker import InteractionLogger
from agent_mash.memory.replay_buffer import ExperienceReplayBuffer
from agent_mash.models.reward_shaper import RewardShaper
from agent_mash.config.settings import RLPlannerConfig

logger = logging.getLogger("RLPlanner")


class RLPlanner:
    def __init__(self, agent_id: str, config: RLPlannerConfig):
        self.agent_id = agent_id
        self.config = config
        self.policy = RLPolicy(config.policy)
        self.replay_buffer = ExperienceReplayBuffer(config.replay_buffer_size)
        self.global_state = GlobalStateManager()
        self.ethics_guard = EthicsGuard()
        self.reward_shaper = RewardShaper()
        self.logger = InteractionLogger(agent_id)

    def plan(self, observation: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Основная логика принятия решений агентом на основе RL-политики."""
        shaped_obs = self._preprocess_observation(observation, context)
        action = self.policy.select_action(shaped_obs)
        safe_action = self.ethics_guard.validate_action(action, context)

        # Логирование взаимодействий и принятого решения
        self.logger.log_decision(
            agent_id=self.agent_id,
            timestamp=datetime.utcnow(),
            observation=observation,
            action=safe_action,
            context=context
        )

        return safe_action

    def _preprocess_observation(self, observation: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Препроцессинг входных данных для улучшения обучаемости."""
        return self.reward_shaper.transform_observation(observation, context)

    def update(self, transition: Dict[str, Any]):
        """Обновление памяти и обучение политики."""
        transition["shaped_reward"] = self.reward_shaper.shape(transition)
        self.replay_buffer.add(transition)

        if self.replay_buffer.is_ready():
            batch = self.replay_buffer.sample(self.config.batch_size)
            self.policy.train_on_batch(batch)

    def synchronize_state(self):
        """Обновление глобального состояния агента."""
        latest_state = self.policy.extract_state_vector()
        self.global_state.update_agent_state(self.agent_id, latest_state)

    def export_state(self) -> Dict[str, Any]:
        """Экспорт текущего состояния для репликации или симуляции."""
        return {
            "agent_id": self.agent_id,
            "policy_state": self.policy.get_internal_state(),
            "replay_memory": self.replay_buffer.dump(),
            "last_sync": datetime.utcnow().isoformat()
        }

    def reset(self):
        """Полный сброс состояния планировщика."""
        self.policy.reset()
        self.replay_buffer.clear()
        self.logger.clear()
        self.global_state.clear_agent_state(self.agent_id)
