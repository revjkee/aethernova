# agent_rl/trading/scripts/train_trader_agent.py

import os
import yaml
import torch
import random
import numpy as np
from pathlib import Path
from datetime import datetime

from agent_rl.trading.envs.trading_env import TradingEnv
from agent_rl.trading.agents.rl_trader_dqn import DQNAgent
from agent_rl.trading.agents.rl_trader_sac import SACAgent
from agent_rl.trading.agents.rl_trader_policy_gradient import PolicyGradientAgent

CONFIG_PATH = Path("agent_rl/trading/configs")


def set_seed(seed: int, deterministic: bool = True):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    if deterministic:
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False


def load_yaml(file: Path) -> dict:
    with open(file, "r") as f:
        return yaml.safe_load(f)


def select_device(requested: str) -> str:
    return "cuda" if requested == "auto" and torch.cuda.is_available() else requested


def create_agent(agent_type: str, obs_dim: int, action_dim: int, config: dict):
    if agent_type == "dqn_agent":
        return DQNAgent(state_size=obs_dim, action_size=action_dim, **config["dqn"])
    elif agent_type == "sac_agent":
        return SACAgent(state_dim=obs_dim, action_dim=action_dim, **config["sac"])
    elif agent_type == "pg_agent":
        return PolicyGradientAgent(state_dim=obs_dim, action_dim=action_dim, **config["pg"])
    else:
        raise ValueError(f"Unknown agent type: {agent_type}")


def train():
    # === Load configs ===
    env_cfg = load_yaml(CONFIG_PATH / "env_config.yaml")
    agent_cfg = load_yaml(CONFIG_PATH / "agent_config.yaml")
    hparams = load_yaml(CONFIG_PATH / "hyperparams.yaml")

    device = select_device(agent_cfg["device"])
    set_seed(agent_cfg["random_seed"], agent_cfg["deterministic"])

    # === Init environment ===
    env = TradingEnv(env_cfg)
    obs_dim = env.observation_space.shape[0]
    action_dim = env.action_space.n

    # === Create agent ===
    agent_type = agent_cfg["agent_name"]
    agent = create_agent(agent_type, obs_dim, action_dim, hparams)
    print(f"[INIT] Agent {agent_type} on {device}")

    total_episodes = hparams["global"]["episodes"]
    steps_per_episode = hparams["global"]["steps_per_episode"]
    save_dir = Path("models") / agent_type / datetime.now().strftime("%Y%m%d_%H%M%S")
    save_dir.mkdir(parents=True, exist_ok=True)

    # === Training loop ===
    for episode in range(1, total_episodes + 1):
        state = env.reset()
        episode_reward = 0
        for step in range(steps_per_episode):
            action = agent.select_action(state)
            next_state, reward, done, _ = env.step(action)
            agent.remember(state, action, reward, next_state, done)
            if hasattr(agent, "train_step"):
                agent.train_step()
            elif hasattr(agent, "store_reward"):
                agent.store_reward(reward)
            state = next_state
            episode_reward += reward
            if done:
                break

        if hasattr(agent, "train_episode"):
            agent.train_episode()

        print(f"[EP {episode:04d}] reward={episode_reward:.4f}")

        # === Save model ===
        if episode % hparams["global"]["save_interval"] == 0:
            agent.save(str(save_dir / f"agent_ep{episode}.pt"))

        # === Early stopping ===
        if episode_reward >= hparams["global"]["early_stopping_reward"]:
            print(f"[✓] Early stopping triggered at EP {episode}")
            break


if __name__ == "__main__":
    train()
