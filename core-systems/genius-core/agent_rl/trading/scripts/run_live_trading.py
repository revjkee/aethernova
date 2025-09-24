# agent_rl/trading/scripts/run_live_trading.py

import time
import yaml
import torch
import logging
from pathlib import Path
from agent_rl.trading.envs.trading_env import TradingEnv
from agent_rl.trading.agents.rl_trader_dqn import DQNAgent
from agent_rl.trading.agents.rl_trader_sac import SACAgent
from agent_rl.trading.agents.rl_trader_policy_gradient import PolicyGradientAgent
from agent_rl.trading.utils.market_api_adapter import MarketAPIAdapter
from agent_rl.trading.utils.order_formatter import OrderFormatter
from agent_rl.trading.policy.risk_policy import RiskPolicy
from agent_rl.trading.utils.trade_logger import TradeLogger

CONFIG_PATH = Path("agent_rl/trading/configs")
MODEL_PATH = "models/sac_agent/20250801_1535/agent_ep100.pt"


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


def main():
    env_cfg = load_yaml(CONFIG_PATH / "env_config.yaml")
    agent_cfg = load_yaml(CONFIG_PATH / "agent_config.yaml")
    hparams = load_yaml(CONFIG_PATH / "hyperparams.yaml")

    env_cfg["mode"] = "live"
    device = select_device(agent_cfg["device"])

    # === Init subsystems ===
    market_api = MarketAPIAdapter(env_cfg["market"])
    order_formatter = OrderFormatter()
    logger = TradeLogger("live_trading")
    risk_policy = RiskPolicy()
    env = TradingEnv(env_cfg)

    obs_dim = env.observation_space.shape[0]
    action_dim = env.action_space.n
    agent = load_agent(agent_cfg["agent_name"], obs_dim, action_dim, hparams, MODEL_PATH)

    print(f"[STARTED] Live trading loop with {agent_cfg['agent_name']}")

    try:
        while True:
            observation = env.get_live_observation(market_api)
            action = agent.select_action(observation)
            action_ok = risk_policy.allows_action(action, context=observation)

            if not action_ok:
                logger.warn("Blocked action by risk policy", extra={"action": action})
                time.sleep(env_cfg["live"]["live_trading_interval_sec"])
                continue

            order = order_formatter.format(action, context=observation)
            if env_cfg["live"]["allow_live_order_send"]:
                market_api.execute_order(order)
                logger.info("Order executed", extra=order)
            else:
                logger.info("Dry-run: Order generated", extra=order)

            time.sleep(env_cfg["live"]["live_trading_interval_sec"])

    except KeyboardInterrupt:
        print("[STOPPED] Gracefully exited.")
    except Exception as e:
        logger.exception("Critical failure in live loop", error=str(e))


if __name__ == "__main__":
    main()
