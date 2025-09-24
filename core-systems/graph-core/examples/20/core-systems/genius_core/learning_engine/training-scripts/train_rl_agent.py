# genius-core/learning-engine/training-scripts/train_rl_agent.py

import argparse
import os
import torch
import numpy as np
from agent_rl.dqn_agent import DQNAgent
from agent_rl.sac_td3_agent import SACAgent, TD3Agent
from replay_buffer.buffer import ReplayBuffer
from gym-envs.mitm-env import MitmEnv
from gym-envs.exploit-env import ExploitEnv

def parse_args():
    parser = argparse.ArgumentParser(description="Train RL Agent for TeslaAI")
    parser.add_argument("--algo", choices=["dqn", "sac", "td3"], default="dqn", help="Algorithm to use")
    parser.add_argument("--env", choices=["mitm", "exploit"], default="mitm", help="Environment to train on")
    parser.add_argument("--episodes", type=int, default=500, help="Number of training episodes")
    parser.add_argument("--save-dir", type=str, default="./checkpoints", help="Directory to save models")
    return parser.parse_args()

def make_env(env_name):
    if env_name == "mitm":
        return MitmEnv()
    elif env_name == "exploit":
        return ExploitEnv()
    else:
        raise ValueError("Invalid environment name")

def select_agent(algo, env):
    state_dim = env.observation_space.shape[0]
    action_dim = env.action_space.n if algo == "dqn" else env.action_space.shape[0]

    if algo == "dqn":
        return DQNAgent(state_dim, action_dim)
    elif algo == "sac":
        return SACAgent(state_dim, action_dim)
    elif algo == "td3":
        return TD3Agent(state_dim, action_dim)
    else:
        raise ValueError("Invalid algorithm")

def train():
    args = parse_args()
    env = make_env(args.env)
    agent = select_agent(args.algo, env)
    replay_buffer = ReplayBuffer(capacity=100_000)

    os.makedirs(args.save_dir, exist_ok=True)

    for episode in range(args.episodes):
        state = env.reset()
        done = False
        total_reward = 0

        while not done:
            action = agent.select_action(state)
            next_state, reward, done, _ = env.step(action)
            replay_buffer.add(state, action, reward, next_state, done)
            agent.update(replay_buffer)
            state = next_state
            total_reward += reward

        print(f"Episode {episode + 1}/{args.episodes} - Reward: {total_reward:.2f}")

        if (episode + 1) % 50 == 0:
            checkpoint_path = os.path.join(args.save_dir, f"{args.algo}_ep{episode+1}.pt")
            agent.save(checkpoint_path)

    final_path = os.path.join(args.save_dir, f"{args.algo}_final.pt")
    agent.save(final_path)
    print(f"Training complete. Final model saved to {final_path}")

if __name__ == "__main__":
    train()
