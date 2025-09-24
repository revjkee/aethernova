# agent_rl/trading/scripts/evaluate_trader_agent.py

import os
import yaml
import torch
import numpy as np
import pandas as pd
from pathlib import Path

from agent_rl.trading.envs.trading_env import TradingEnv
from agent_rl.trading.agents.rl_trader_dqn import DQNAgent
from agent_rl.trading.agents.rl_trader_sac import SACAgent
from agent_rl.trading.agents.rl_trader_policy_gradient import PolicyGradientAgent
from agent_rl.trading.evaluation.eval_metrics import evaluate_all_metrics

CONFIG_PATH = Path("agent_rl/trading/configs")


def load_yaml(file: Path) -> dict:
    with open(file, "r") as f:
        return yaml.safe_load(f)


def select_device(requested: str) -> str:
    return "cuda" if requested == "auto" and torch.cuda.is_available() else requested


def load_agent(agent_type: str, obs_dim: int, action_dim: int, config: dict, checkpoint_path: str):
    if agent_type == "dqn_agent":
        agent = DQNAgent(state_size=obs_dim, action_size=action_dim, **config["dqn"])
    elif agent_type == "sac_agent":
        agent = SACAgent(state_dim=obs_dim, action_dim=action_dim, **config["sac"])
    elif agent_type == "pg_agent":
        agent = PolicyGradientAgent(state_dim=obs_dim, action_dim=action_dim, **config["pg"])
    else:
        raise ValueError(f"Unknown agent type: {agent_type}")
    agent.load(checkpoint_path)
    return agent


def evaluate(agent, env, steps: int = 500) -> dict:
    state = env.reset()
    rewards = []
    returns = []
    equity = [env.initial_balance]

    for _ in range(steps):
        action = agent.select_action(state)
        state, reward, done, _ = env.step(action)
        rewards.append(reward)
        equity.append(env.balance)
        if done:
            break

    returns = np.array(rewards)
    equity = np.array(equity)
    return evaluate_all_metrics(returns=returns, equity_curve=equity)


def run_evaluation(model_path: str, output_csv: str = "eval_results.csv", steps: int = 500):
    env_cfg = load_yaml(CONFIG_PATH / "env_config.yaml")
    agent_cfg = load_yaml(CONFIG_PATH / "agent_config.yaml")
    hparams = load_yaml(CONFIG_PATH / "hyperparams.yaml")

    device = select_device(agent_cfg["device"])
    env_cfg["mode"] = "test"

    env = TradingEnv(env_cfg)
    obs_dim = env.observation_space.shape[0]
    action_dim = env.action_space.n
    agent = load_agent(agent_cfg["agent_name"], obs_dim, action_dim, hparams, model_path)

    metrics = evaluate(agent, env, steps=steps)
    metrics["Agent"] = agent_cfg["agent_name"]
    metrics["Checkpoint"] = os.path.basename(model_path)

    df = pd.DataFrame([metrics])
    df.to_csv(output_csv, index=False)
    print(f"[✓] Evaluation complete. Results saved to {output_csv}")
    print(df.to_string(index=False))


if __name__ == "__main__":
    # Пример: путь до модели можно заменить при запуске
    MODEL_PATH = "models/sac_agent/20250801_1535/agent_ep100.pt"
    run_evaluation(model_path=MODEL_PATH)
