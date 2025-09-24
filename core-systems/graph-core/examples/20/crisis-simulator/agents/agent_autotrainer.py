# agent_autotrainer.py

"""
AI-автотренировка агентов кризисного реагирования.
Использует синтетические сценарии, RL-механизмы и имитационную среду TeslaAI CrisisSim.
Поддерживает self-improvement loop, meta-evolution и rollback memory reinforcement.
"""

import logging
import random
from typing import List

from crisis_simulator.core.models import CrisisScenario, CrisisAgent
from crisis_simulator.core.simulator import CrisisEnvironment
from crisis_simulator.core.replay.memory import ScenarioReplayMemory
from crisis_simulator.core.rewards import AdaptiveCrisisReward
from crisis_simulator.core.trainers.reinforce import ReinforcementTrainer
from crisis_simulator.core.validators.agent_metrics import evaluate_agent_performance

logger = logging.getLogger("CrisisAgentAutoTrainer")

class AgentAutoTrainer:
    def __init__(
        self,
        agents: List[CrisisAgent],
        environment: CrisisEnvironment,
        episodes: int = 1000,
        memory_replay: bool = True,
        evaluation_interval: int = 100
    ):
        self.agents = agents
        self.env = environment
        self.episodes = episodes
        self.memory = ScenarioReplayMemory() if memory_replay else None
        self.trainer = ReinforcementTrainer()
        self.reward_fn = AdaptiveCrisisReward()
        self.evaluation_interval = evaluation_interval

    def train(self):
        logger.info("[TRAINER] Starting agent autotraining loop.")
        for ep in range(self.episodes):
            scenario = self.env.sample_scenario()
            for agent in self.agents:
                logger.debug(f"[TRAINER] Episode {ep} - Training agent {agent.id}")
                reward = self.trainer.train_on_scenario(
                    agent=agent,
                    scenario=scenario,
                    reward_fn=self.reward_fn
                )
                if self.memory:
                    self.memory.store(agent.id, scenario, reward)

            if (ep + 1) % self.evaluation_interval == 0:
                self._evaluate_agents()

        if self.memory:
            logger.info("[TRAINER] Activating memory replay reinforcement.")
            self._run_memory_reinforcement()

        logger.info("[TRAINER] Training completed.")

    def _evaluate_agents(self):
        for agent in self.agents:
            metrics = evaluate_agent_performance(agent, self.env)
            logger.info(f"[EVAL] Agent {agent.id} performance: {metrics}")

    def _run_memory_reinforcement(self):
        for agent in self.agents:
            memories = self.memory.retrieve(agent.id)
            for past_scenario, past_reward in memories:
                self.trainer.retrain_from_memory(
                    agent=agent,
                    scenario=past_scenario,
                    expected_reward=past_reward
                )
