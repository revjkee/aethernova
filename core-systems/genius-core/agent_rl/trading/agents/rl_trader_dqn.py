# agent_rl/trading/agents/rl_trader_dqn.py

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import random
from collections import deque
from typing import Tuple

class QNetwork(nn.Module):
    def __init__(self, state_size: int, action_size: int, hidden_dims: Tuple[int, int] = (128, 128)):
        super(QNetwork, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(state_size, hidden_dims[0]),
            nn.ReLU(),
            nn.Linear(hidden_dims[0], hidden_dims[1]),
            nn.ReLU(),
            nn.Linear(hidden_dims[1], action_size)
        )

    def forward(self, state):
        return self.model(state)


class DQNAgent:
    def __init__(
        self,
        state_size: int,
        action_size: int,
        learning_rate: float = 1e-3,
        gamma: float = 0.99,
        epsilon_start: float = 1.0,
        epsilon_end: float = 0.01,
        epsilon_decay: float = 0.995,
        buffer_size: int = 100_000,
        batch_size: int = 64,
        target_update_freq: int = 10,
        device: str = "cuda" if torch.cuda.is_available() else "cpu"
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.gamma = gamma
        self.epsilon = epsilon_start
        self.epsilon_min = epsilon_end
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size
        self.device = device
        self.target_update_freq = target_update_freq
        self.learn_step = 0

        self.policy_net = QNetwork(state_size, action_size).to(self.device)
        self.target_net = QNetwork(state_size, action_size).to(self.device)
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=learning_rate)
        self.loss_fn = nn.MSELoss()

        self.replay_buffer = deque(maxlen=buffer_size)

        self._sync_target()

    def _sync_target(self):
        self.target_net.load_state_dict(self.policy_net.state_dict())

    def act(self, state: np.ndarray) -> int:
        if np.random.rand() <= self.epsilon:
            return random.choice(range(self.action_size))
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        with torch.no_grad():
            q_values = self.policy_net(state_tensor)
        return int(torch.argmax(q_values))

    def remember(self, state, action, reward, next_state, done):
        self.replay_buffer.append((state, action, reward, next_state, done))

    def train_step(self):
        if len(self.replay_buffer) < self.batch_size:
            return

        batch = random.sample(self.replay_buffer, self.batch_size)
        states, actions, rewards, next_states, dones = zip(*batch)

        states_tensor = torch.FloatTensor(states).to(self.device)
        actions_tensor = torch.LongTensor(actions).unsqueeze(1).to(self.device)
        rewards_tensor = torch.FloatTensor(rewards).unsqueeze(1).to(self.device)
        next_states_tensor = torch.FloatTensor(next_states).to(self.device)
        dones_tensor = torch.BoolTensor(dones).unsqueeze(1).to(self.device)

        q_values = self.policy_net(states_tensor).gather(1, actions_tensor)
        with torch.no_grad():
            target_q = self.target_net(next_states_tensor).max(1, keepdim=True)[0]
            target_values = rewards_tensor + (self.gamma * target_q * (~dones_tensor))

        loss = self.loss_fn(q_values, target_values)

        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()

        if self.learn_step % self.target_update_freq == 0:
            self._sync_target()

        self.epsilon = max(self.epsilon * self.epsilon_decay, self.epsilon_min)
        self.learn_step += 1

    def save(self, path: str):
        torch.save(self.policy_net.state_dict(), path)

    def load(self, path: str):
        self.policy_net.load_state_dict(torch.load(path))
        self._sync_target()
