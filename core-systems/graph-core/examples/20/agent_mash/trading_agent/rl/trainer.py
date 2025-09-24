# trainer.py

import os
import time
import torch
import numpy as np
import logging
from torch.utils.tensorboard import SummaryWriter
from typing import Optional, Dict, Any
from .environment import TradingEnvironment
from .reward_functions import CompositeReward
from agent_mash.trading_agent.rl.agents.base_agent import BaseRLAgent

logger = logging.getLogger("trainer")
logger.setLevel(logging.INFO)


class RLTrainer:
    """
    Промышленный тренер трейдинг-агента на основе RL.
    Поддержка TensorBoard, чекпоинтов, early stopping.
    """

    def __init__(
        self,
        env: TradingEnvironment,
        agent: BaseRLAgent,
        reward_fn: CompositeReward,
        max_episodes: int = 1000,
        log_dir: str = "./logs/training",
        checkpoint_dir: str = "./checkpoints",
        early_stopping_patience: int = 20
    ):
        self.env = env
        self.agent = agent
        self.reward_fn = reward_fn
        self.max_episodes = max_episodes
        self.checkpoint_dir = checkpoint_dir
        self.writer = SummaryWriter(log_dir)
        self.early_stopping_patience = early_stopping_patience

        os.makedirs(self.checkpoint_dir, exist_ok=True)

    def train(self):
        best_reward = float('-inf')
        patience_counter = 0

        for episode in range(1, self.max_episodes + 1):
            state = self.env.reset()
            total_reward = 0
            done = False
            step = 0

            while not done:
                action = self.agent.act(state)
                next_state, market_info, done = self.env.step(action)
                reward = self.reward_fn.compute(market_info)
                self.agent.learn(state, action, reward, next_state, done)

                state = next_state
                total_reward += reward
                step += 1

            self.writer.add_scalar("EpisodeReward", total_reward, episode)
            logger.info(f"[EP {episode}] Reward: {total_reward:.4f}, Steps: {step}")

            # Early stopping check
            if total_reward > best_reward:
                best_reward = total_reward
                patience_counter = 0
                self._save_checkpoint(episode, best=True)
            else:
                patience_counter += 1

            if patience_counter >= self.early_stopping_patience:
                logger.info(f"[Trainer] Early stopping at episode {episode}")
                break

            # Checkpoint every 50 episodes
            if episode % 50 == 0:
                self._save_checkpoint(episode)

        self.writer.close()

    def _save_checkpoint(self, episode: int, best: bool = False):
        """
        Сохраняет состояние агента.
        """
        filename = "best_model.pth" if best else f"model_ep{episode}.pth"
        path = os.path.join(self.checkpoint_dir, filename)
        state = {
            'episode': episode,
            'model_state_dict': self.agent.model.state_dict(),
            'optimizer_state_dict': self.agent.optimizer.state_dict()
        }
        torch.save(state, path)
        logger.info(f"[Checkpoint] Saved at {path}")
