# genius-core/learning-engine/agent_rl/self_play_agent.py

import copy
import torch
import numpy as np
from collections import deque
import random

from sac_td3_agent import TD3Agent, GaussianPolicy  # импорт SAC или TD3 агентов
from genius_core.learning_engine.agent_rl.copilot_adapter import get_strategy

class SelfPlayAgent:
    async def choose_action(self, observation, agent_id="self_agent"):
        summary = self.format_obs(observation)
        strategy = await get_strategy(agent_id, summary)

        return self.policy(observation, hint=strategy)

    def format_obs(self, obs):
        return f"env_state:{obs}"
        
class SelfPlayAgent:
    def __init__(self, agent_class, state_dim, action_dim, max_action, device='cpu', num_agents=2):
        self.device = device
        self.num_agents = num_agents

        # Инициализация агентов одного класса
        self.agents = [agent_class(state_dim, action_dim, max_action, device) for _ in range(num_agents)]

        # Общий replay buffer для self-play опыта
        self.replay_buffer = deque(maxlen=1_000_000)

        self.batch_size = 256
        self.gamma = 0.99
        self.tau = 0.005

    def select_actions(self, states, deterministic=False):
        # states - список состояний для каждого агента
        actions = []
        for i, agent in enumerate(self.agents):
            if deterministic and hasattr(agent, 'select_action_deterministic'):
                action = agent.select_action_deterministic(states[i])
            else:
                action = agent.select_action(states[i])
            actions.append(action)
        return actions

    def add_transition(self, state, action, reward, next_state, done):
        # Добавляем в общий replay buffer
        self.replay_buffer.append((state, action, reward, next_state, done))
        for agent in self.agents:
            agent.replay_buffer.add((state, action, reward, next_state, done))

    def train_all(self):
        if len(self.replay_buffer) < self.batch_size:
            return

        for agent in self.agents:
            agent.train(self.batch_size)

    def save(self, prefix_path):
        for idx, agent in enumerate(self.agents):
            torch.save(agent.actor.state_dict(), f"{prefix_path}_agent_{idx}_actor.pth")
            torch.save(agent.critic1.state_dict(), f"{prefix_path}_agent_{idx}_critic1.pth")
            torch.save(agent.critic2.state_dict(), f"{prefix_path}_agent_{idx}_critic2.pth")

    def load(self, prefix_path):
        for idx, agent in enumerate(self.agents):
            agent.actor.load_state_dict(torch.load(f"{prefix_path}_agent_{idx}_actor.pth", map_location=self.device))
            agent.critic1.load_state_dict(torch.load(f"{prefix_path}_agent_{idx}_critic1.pth", map_location=self.device))
            agent.critic2.load_state_dict(torch.load(f"{prefix_path}_agent_{idx}_critic2.pth", map_location=self.device))
