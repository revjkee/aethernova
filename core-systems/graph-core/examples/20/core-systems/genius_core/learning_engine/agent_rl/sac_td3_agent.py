# genius-core/learning-engine/agent_rl/sac_td3_agent.py

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import random
from collections import deque
import copy
from genius_core.learning_engine.agent_rl.copilot_adapter import get_strategy
# ===== Actor & Critic Architectures =====

class SACAgent:
    async def act(self, observation, agent_id="agent_sac"):
        obs_summary = self.summarize_obs(observation)

        strategy_hint = await get_strategy(agent_id, obs_summary)
        action = self.policy(observation, hint=strategy_hint)
        return action

    def summarize_obs(self, obs):
        return f"obs={obs[:5]}"  # можно сделать умнее
        
class MLP(nn.Module):
    def __init__(self, input_dim, output_dim, hidden_dim=256, activation=nn.ReLU):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            activation(),
            nn.Linear(hidden_dim, hidden_dim),
            activation(),
            nn.Linear(hidden_dim, output_dim)
        )

    def forward(self, x):
        return self.net(x)


class GaussianPolicy(nn.Module):  # Used in SAC
    def __init__(self, state_dim, action_dim, hidden_dim=256, log_std_min=-20, log_std_max=2):
        super().__init__()
        self.fc = MLP(state_dim, hidden_dim)
        self.mean = nn.Linear(hidden_dim, action_dim)
        self.log_std = nn.Linear(hidden_dim, action_dim)
        self.log_std_min = log_std_min
        self.log_std_max = log_std_max

    def forward(self, state):
        x = self.fc(state)
        mean = self.mean(x)
        log_std = self.log_std(x)
        log_std = torch.clamp(log_std, self.log_std_min, self.log_std_max)
        std = torch.exp(log_std)
        return mean, std

    def sample(self, state):
        mean, std = self.forward(state)
        normal = torch.distributions.Normal(mean, std)
        x_t = normal.rsample()
        action = torch.tanh(x_t)
        log_prob = normal.log_prob(x_t).sum(dim=-1)
        log_prob -= torch.log(1 - action.pow(2) + 1e-6).sum(dim=-1)
        return action, log_prob


class DeterministicPolicy(nn.Module):  # Used in TD3
    def __init__(self, state_dim, action_dim, hidden_dim=256):
        super().__init__()
        self.net = MLP(state_dim, action_dim, hidden_dim)

    def forward(self, state):
        return torch.tanh(self.net(state))


# ===== Replay Buffer =====

class ReplayBuffer:
    def __init__(self, max_size=1_000_000):
        self.buffer = deque(maxlen=max_size)

    def add(self, transition):
        self.buffer.append(transition)

    def sample(self, batch_size):
        batch = random.sample(self.buffer, batch_size)
        state, action, reward, next_state, done = zip(*batch)
        return (
            torch.FloatTensor(state),
            torch.FloatTensor(action),
            torch.FloatTensor(reward).unsqueeze(1),
            torch.FloatTensor(next_state),
            torch.FloatTensor(done).unsqueeze(1)
        )

    def __len__(self):
        return len(self.buffer)


# ===== TD3 Agent =====

class TD3Agent:
    def __init__(self, state_dim, action_dim, max_action, device='cpu'):
        self.device = device
        self.actor = DeterministicPolicy(state_dim, action_dim).to(device)
        self.actor_target = copy.deepcopy(self.actor)
        self.actor_optimizer = torch.optim.Adam(self.actor.parameters(), lr=1e-3)

        self.critic1 = MLP(state_dim + action_dim, 1).to(device)
        self.critic2 = MLP(state_dim + action_dim, 1).to(device)
        self.critic1_target = copy.deepcopy(self.critic1)
        self.critic2_target = copy.deepcopy(self.critic2)
        self.critic_optimizer = torch.optim.Adam(
            list(self.critic1.parameters()) + list(self.critic2.parameters()), lr=1e-3
        )

        self.replay_buffer = ReplayBuffer()
        self.max_action = max_action
        self.policy_noise = 0.2
        self.noise_clip = 0.5
        self.tau = 0.005
        self.gamma = 0.99
        self.policy_delay = 2
        self.total_it = 0

    def select_action(self, state):
        state = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        return self.actor(state).cpu().data.numpy().flatten()

    def train(self, batch_size=256):
        if len(self.replay_buffer) < batch_size:
            return

        self.total_it += 1
        state, action, reward, next_state, done = self.replay_buffer.sample(batch_size)

        with torch.no_grad():
            noise = (
                torch.randn_like(action) * self.policy_noise
            ).clamp(-self.noise_clip, self.noise_clip)
            next_action = (self.actor_target(next_state) + noise).clamp(-1, 1)

            q1_target = self.critic1_target(torch.cat([next_state, next_action], 1))
            q2_target = self.critic2_target(torch.cat([next_state, next_action], 1))
            q_target = reward + self.gamma * (1 - done) * torch.min(q1_target, q2_target)

        q1 = self.critic1(torch.cat([state, action], 1))
        q2 = self.critic2(torch.cat([state, action], 1))
        critic_loss = F.mse_loss(q1, q_target) + F.mse_loss(q2, q_target)

        self.critic_optimizer.zero_grad()
        critic_loss.backward()
        self.critic_optimizer.step()

        if self.total_it % self.policy_delay == 0:
            actor_loss = -self.critic1(torch.cat([state, self.actor(state)], 1)).mean()
            self.actor_optimizer.zero_grad()
            actor_loss.backward()
            self.actor_optimizer.step()

            for param, target_param in zip(self.actor.parameters(), self.actor_target.parameters()):
                target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)

            for param, target_param in zip(self.critic1.parameters(), self.critic1_target.parameters()):
                target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)

            for param, target_param in zip(self.critic2.parameters(), self.critic2_target.parameters()):
                target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)


# ===== SAC Agent (можно добавить аналогично при необходимости) =====
# (По твоему коду SAC пока нет, могу сделать по запросу)

# ===== Self-Play Wrapper для мультиагентного обучения =====

class SelfPlayWrapper:
    """
    Обёртка для организации self-play обучения между несколькими агентами,
    поддерживает TD3 или SAC агентов.
    """
    def __init__(self, agents):
        """
        agents: dict с ключами - имена агентов, значениями - объекты агентов TD3Agent или SACAgent
        """
        self.agents = agents
        self.current_agent_name = list(agents.keys())[0]

    def select_action(self, state, agent_name=None):
        """
        Выбор действия указанным агентом или текущим по очереди
        """
        if agent_name is None:
            agent_name = self.current_agent_name
        return self.agents[agent_name].select_action(state)

    def switch_agent(self):
        """
        Переключение между агентами для self-play
        """
        names = list(self.agents.keys())
        idx = names.index(self.current_agent_name)
        idx = (idx + 1) % len(names)
        self.current_agent_name = names[idx]

    def add_transition(self, agent_name, transition):
        """
        Добавить опыт (transition) агенту
        """
        self.agents[agent_name].replay_buffer.add(transition)

    def train_agents(self, batch_size=256):
        """
        Обучить всех агентов
        """
        for agent in self.agents.values():
            agent.train(batch_size)

# ===== SAC Agent =====

class SACAgent:
    def __init__(self, state_dim, action_dim, max_action, device='cpu'):
        self.device = device

        self.actor = GaussianPolicy(state_dim, action_dim).to(device)
        self.actor_optimizer = torch.optim.Adam(self.actor.parameters(), lr=3e-4)

        self.critic1 = MLP(state_dim + action_dim, 1).to(device)
        self.critic2 = MLP(state_dim + action_dim, 1).to(device)
        self.critic1_target = copy.deepcopy(self.critic1)
        self.critic2_target = copy.deepcopy(self.critic2)
        self.critic_optimizer = torch.optim.Adam(
            list(self.critic1.parameters()) + list(self.critic2.parameters()), lr=3e-4
        )

        self.replay_buffer = ReplayBuffer()
        self.max_action = max_action

        self.gamma = 0.99
        self.tau = 0.005
        self.alpha = 0.2  # энтропийный коэффициент
        self.total_it = 0

    def select_action(self, state, deterministic=False):
        state = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        if deterministic:
            mean, _ = self.actor.forward(state)
            action = torch.tanh(mean)
            return action.cpu().data.numpy().flatten()
        else:
            action, _ = self.actor.sample(state)
            return action.cpu().data.numpy().flatten()

    def train(self, batch_size=256):
        if len(self.replay_buffer) < batch_size:
            return

        self.total_it += 1
        state, action, reward, next_state, done = self.replay_buffer.sample(batch_size)

        state = state.to(self.device)
        action = action.to(self.device)
        reward = reward.to(self.device)
        next_state = next_state.to(self.device)
        done = done.to(self.device)

        with torch.no_grad():
            next_action, next_log_prob = self.actor.sample(next_state)
            q1_next = self.critic1_target(torch.cat([next_state, next_action], 1))
            q2_next = self.critic2_target(torch.cat([next_state, next_action], 1))
            q_next = torch.min(q1_next, q2_next) - self.alpha * next_log_prob.unsqueeze(1)
            q_target = reward + self.gamma * (1 - done) * q_next

        q1 = self.critic1(torch.cat([state, action], 1))
        q2 = self.critic2(torch.cat([state, action], 1))
        critic_loss = F.mse_loss(q1, q_target) + F.mse_loss(q2, q_target)

        self.critic_optimizer.zero_grad()
        critic_loss.backward()
        self.critic_optimizer.step()

        action_new, log_prob_new = self.actor.sample(state)
        q1_new = self.critic1(torch.cat([state, action_new], 1))
        q2_new = self.critic2(torch.cat([state, action_new], 1))
        q_new = torch.min(q1_new, q2_new)

        actor_loss = (self.alpha * log_prob_new.unsqueeze(1) - q_new).mean()

        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        self.actor_optimizer.step()

        for param, target_param in zip(self.critic1.parameters(), self.critic1_target.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)

        for param, target_param in zip(self.critic2.parameters(), self.critic2_target.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)

