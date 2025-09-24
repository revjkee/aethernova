# genius-core/learning-engine/training-scripts/eval_agent.py

import torch
import numpy as np

class AgentEvaluator:
    def __init__(self, agent, env, device='cpu', eval_episodes=10):
        self.agent = agent
        self.env = env
        self.device = device
        self.eval_episodes = eval_episodes

    def evaluate(self, render=False):
        rewards = []
        for episode in range(self.eval_episodes):
            state = self.env.reset()
            done = False
            episode_reward = 0.0
            while not done:
                state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                with torch.no_grad():
                    action = self.agent.select_action(state_tensor)
                next_state, reward, done, _ = self.env.step(action)
                if render:
                    self.env.render()
                episode_reward += reward
                state = next_state
            rewards.append(episode_reward)
        avg_reward = np.mean(rewards)
        return avg_reward, rewards
