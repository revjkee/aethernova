# agent_rl/trading/agents/rl_trader_sac.py

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from collections import deque
import random
from typing import Tuple

LOG_SIG_MAX = 2
LOG_SIG_MIN = -20
EPS = 1e-6


class MLP(nn.Module):
    def __init__(self, input_dim, output_dim, hidden_dims=(256, 256)):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(input_dim, hidden_dims[0]),
            nn.ReLU(),
            nn.Linear(hidden_dims[0], hidden_dims[1]),
            nn.ReLU(),
            nn.Linear(hidden_dims[1], output_dim)
        )

    def forward(self, x):
        return self.model(x)


class GaussianPolicy(nn.Module):
    def __init__(self, state_dim, action_dim):
        super().__init__()
        self.linear = nn.Linear(state_dim, 256)
        self.mean = nn.Linear(256, action_dim)
        self.log_std = nn.Linear(256, action_dim)

    def forward(self, state):
        x = torch.relu(self.linear(state))
        mean = self.mean(x)
        log_std = torch.clamp(self.log_std(x), LOG_SIG_MIN, LOG_SIG_MAX)
        std = log_std.exp()

        normal = torch.distributions.Normal(mean, std)
        z = normal.rsample()
        action = torch.tanh(z)

        log_prob = normal.log_prob(z) - torch.log(1 - action.pow(2) + EPS)
        log_prob = log_prob.sum(1, keepdim=True)

        return action, log_prob, mean


class SACAgent:
    def __init__(
        self,
        state_dim,
        action_dim,
        gamma=0.99,
        tau=0.005,
        alpha=0.2,
        lr=3e-4,
        buffer_size=1000000,
        batch_size=256,
        automatic_entropy_tuning=True,
        target_entropy=None,
        device="cuda" if torch.cuda.is_available() else "cpu"
    ):
        self.device = device
        self.gamma = gamma
        self.tau = tau
        self.alpha = alpha
        self.batch_size = batch_size
        self.replay_buffer = deque(maxlen=buffer_size)

        self.policy_net = GaussianPolicy(state_dim, action_dim).to(device)
        self.q1_net = MLP(state_dim + action_dim, 1).to(device)
        self.q2_net = MLP(state_dim + action_dim, 1).to(device)
        self.value_net = MLP(state_dim, 1).to(device)
        self.target_value_net = MLP(state_dim, 1).to(device)

        self.target_value_net.load_state_dict(self.value_net.state_dict())

        self.policy_optimizer = optim.Adam(self.policy_net.parameters(), lr=lr)
        self.q1_optimizer = optim.Adam(self.q1_net.parameters(), lr=lr)
        self.q2_optimizer = optim.Adam(self.q2_net.parameters(), lr=lr)
        self.value_optimizer = optim.Adam(self.value_net.parameters(), lr=lr)

        self.automatic_entropy_tuning = automatic_entropy_tuning
        if self.automatic_entropy_tuning:
            self.target_entropy = target_entropy or -action_dim
            self.log_alpha = torch.tensor(np.log(alpha)).to(device).requires_grad_()
            self.alpha_optimizer = optim.Adam([self.log_alpha], lr=lr)

    def select_action(self, state, eval=False):
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        action, _, mean = self.policy_net(state_tensor)
        return mean.detach().cpu().numpy()[0] if eval else action.detach().cpu().numpy()[0]

    def remember(self, state, action, reward, next_state, done):
        self.replay_buffer.append((state, action, reward, next_state, float(done)))

    def train_step(self):
        if len(self.replay_buffer) < self.batch_size:
            return

        batch = random.sample(self.replay_buffer, self.batch_size)
        state, action, reward, next_state, done = zip(*batch)

        state = torch.FloatTensor(state).to(self.device)
        action = torch.FloatTensor(action).to(self.device)
        reward = torch.FloatTensor(reward).unsqueeze(1).to(self.device)
        next_state = torch.FloatTensor(next_state).to(self.device)
        done = torch.FloatTensor(done).unsqueeze(1).to(self.device)

        with torch.no_grad():
            next_action, next_log_prob, _ = self.policy_net(next_state)
            target_value = self.target_value_net(next_state)
            q_target = reward + (1 - done) * self.gamma * (target_value)

        # Q1/Q2 loss
        q1_pred = self.q1_net(torch.cat([state, action], dim=1))
        q2_pred = self.q2_net(torch.cat([state, action], dim=1))

        q1_loss = nn.MSELoss()(q1_pred, q_target)
        q2_loss = nn.MSELoss()(q2_pred, q_target)

        self.q1_optimizer.zero_grad()
        q1_loss.backward()
        self.q1_optimizer.step()

        self.q2_optimizer.zero_grad()
        q2_loss.backward()
        self.q2_optimizer.step()

        # Value loss
        new_action, log_prob, _ = self.policy_net(state)
        q1_new = self.q1_net(torch.cat([state, new_action], dim=1))
        q2_new = self.q2_net(torch.cat([state, new_action], dim=1))
        q_min = torch.min(q1_new, q2_new)
        value_target = q_min - self.alpha * log_prob
        value_pred = self.value_net(state)

        value_loss = nn.MSELoss()(value_pred, value_target.detach())

        self.value_optimizer.zero_grad()
        value_loss.backward()
        self.value_optimizer.step()

        # Policy loss
        policy_loss = (self.alpha * log_prob - q_min).mean()

        self.policy_optimizer.zero_grad()
        policy_loss.backward()
        self.policy_optimizer.step()

        # Update α
        if self.automatic_entropy_tuning:
            alpha_loss = -(self.log_alpha * (log_prob + self.target_entropy).detach()).mean()
            self.alpha_optimizer.zero_grad()
            alpha_loss.backward()
            self.alpha_optimizer.step()
            self.alpha = self.log_alpha.exp().item()

        # Soft update target
        for target_param, param in zip(self.target_value_net.parameters(), self.value_net.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)

    def save(self, path):
        torch.save(self.policy_net.state_dict(), path)

    def load(self, path):
        self.policy_net.load_state_dict(torch.load(path))
