# agent_rl/trading/agents/rl_trader_policy_gradient.py

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from collections import deque
from typing import List, Tuple


class Actor(nn.Module):
    def __init__(self, state_dim, action_dim, hidden_dims=(128, 128)):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(state_dim, hidden_dims[0]),
            nn.ReLU(),
            nn.Linear(hidden_dims[0], hidden_dims[1]),
            nn.ReLU(),
            nn.Linear(hidden_dims[1], action_dim),
            nn.Softmax(dim=-1)
        )

    def forward(self, state):
        return self.model(state)


class Critic(nn.Module):
    def __init__(self, state_dim, hidden_dims=(128, 128)):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(state_dim, hidden_dims[0]),
            nn.ReLU(),
            nn.Linear(hidden_dims[0], hidden_dims[1]),
            nn.ReLU(),
            nn.Linear(hidden_dims[1], 1)
        )

    def forward(self, state):
        return self.model(state)


class PolicyGradientAgent:
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        gamma: float = 0.99,
        entropy_coef: float = 0.01,
        lr: float = 1e-3,
        device: str = "cuda" if torch.cuda.is_available() else "cpu"
    ):
        self.device = device
        self.gamma = gamma
        self.entropy_coef = entropy_coef

        self.actor = Actor(state_dim, action_dim).to(device)
        self.critic = Critic(state_dim).to(device)

        self.optimizer_actor = optim.Adam(self.actor.parameters(), lr=lr)
        self.optimizer_critic = optim.Adam(self.critic.parameters(), lr=lr)

        self.reset_episode_memory()

    def reset_episode_memory(self):
        self.log_probs: List[torch.Tensor] = []
        self.rewards: List[float] = []
        self.states: List[np.ndarray] = []

    def select_action(self, state: np.ndarray) -> int:
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        probs = self.actor(state_tensor)
        dist = torch.distributions.Categorical(probs)
        action = dist.sample()
        self.log_probs.append(dist.log_prob(action))
        self.states.append(state)
        return action.item()

    def store_reward(self, reward: float):
        self.rewards.append(reward)

    def compute_returns(self) -> List[float]:
        G = 0
        returns = []
        for r in reversed(self.rewards):
            G = r + self.gamma * G
            returns.insert(0, G)
        return returns

    def train_episode(self):
        if not self.rewards:
            return

        returns = torch.FloatTensor(self.compute_returns()).to(self.device)
        states_tensor = torch.FloatTensor(self.states).to(self.device)
        values = self.critic(states_tensor).squeeze()

        advantages = returns - values.detach()

        log_probs_tensor = torch.stack(self.log_probs).to(self.device)
        entropy = -torch.sum(torch.exp(log_probs_tensor) * log_probs_tensor)

        actor_loss = -(log_probs_tensor * advantages).mean() - self.entropy_coef * entropy
        critic_loss = nn.MSELoss()(values, returns)

        self.optimizer_actor.zero_grad()
        actor_loss.backward()
        self.optimizer_actor.step()

        self.optimizer_critic.zero_grad()
        critic_loss.backward()
        self.optimizer_critic.step()

        self.reset_episode_memory()

    def save(self, path: str):
        torch.save({
            "actor": self.actor.state_dict(),
            "critic": self.critic.state_dict()
        }, path)

    def load(self, path: str):
        checkpoint = torch.load(path)
        self.actor.load_state_dict(checkpoint["actor"])
        self.critic.load_state_dict(checkpoint["critic"])
