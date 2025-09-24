# genius-core/learning-engine/training-scripts/train_sac_td3.py

import torch
import torch.nn.functional as F
from torch.utils.tensorboard import SummaryWriter
import numpy as np
import gym
import argparse
from collections import deque
import random
import time
import os

from genius-core.learning_engine.agent_rl.sac_td3_agent import TD3Agent, GaussianPolicy, ReplayBuffer

def evaluate_policy(agent, env_name, seed, eval_episodes=10):
    eval_env = gym.make(env_name)
    eval_env.seed(seed)
    avg_reward = 0.
    for _ in range(eval_episodes):
        state = eval_env.reset()
        done = False
        while not done:
            action = agent.select_action(state)
            state, reward, done, _ = eval_env.step(action)
            avg_reward += reward
    avg_reward /= eval_episodes
    return avg_reward

def train(args):
    env = gym.make(args.env_name)
    env.seed(args.seed)
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    random.seed(args.seed)

    state_dim = env.observation_space.shape[0]
    action_dim = env.action_space.shape[0]
    max_action = float(env.action_space.high[0])

    agent = TD3Agent(state_dim, action_dim, max_action, device=args.device)

    replay_buffer = agent.replay_buffer

    writer = SummaryWriter(log_dir=args.log_dir) if args.log_dir else None

    total_timesteps = 0
    episode_num = 0
    done = True

    evaluations = []

    state, episode_reward, episode_timesteps = env.reset(), 0, 0

    while total_timesteps < args.max_timesteps:

        if done:
            if total_timesteps != 0:
                if writer:
                    writer.add_scalar('reward/train', episode_reward, total_timesteps)
                print(f"Total Timesteps: {total_timesteps} Episode Num: {episode_num} Reward: {episode_reward:.3f}")
                episode_num += 1

            if total_timesteps % args.eval_freq == 0:
                eval_reward = evaluate_policy(agent, args.env_name, args.seed)
                evaluations.append(eval_reward)
                if writer:
                    writer.add_scalar('reward/eval', eval_reward, total_timesteps)
                print(f"Evaluation reward at timestep {total_timesteps}: {eval_reward:.3f}")

            state, episode_reward, episode_timesteps = env.reset(), 0, 0

        # Select action randomly or according to policy
        if total_timesteps < args.start_timesteps:
            action = env.action_space.sample()
        else:
            action = agent.select_action(np.array(state))
            action = (action + np.random.normal(0, args.expl_noise, size=action_dim)).clip(
                env.action_space.low, env.action_space.high
            )

        next_state, reward, done, _ = env.step(action)
        done_bool = float(done) if episode_timesteps + 1 < env._max_episode_steps else 0

        replay_buffer.add((state, action, reward, next_state, done_bool))

        state = next_state
        episode_reward += reward
        episode_timesteps += 1
        total_timesteps += 1

        # Train agent after collecting sufficient data
        if total_timesteps >= args.start_timesteps:
            agent.train(args.batch_size)

    # Final evaluation
    eval_reward = evaluate_policy(agent, args.env_name, args.seed)
    evaluations.append(eval_reward)
    if writer:
        writer.add_scalar('reward/eval', eval_reward, total_timesteps)
    print(f"Final evaluation reward: {eval_reward:.3f}")

    if writer:
        writer.close()

    if args.save_model:
        os.makedirs(args.save_dir, exist_ok=True)
        torch.save(agent.actor.state_dict(), os.path.join(args.save_dir, 'actor.pth'))
        torch.save(agent.critic1.state_dict(), os.path.join(args.save_dir, 'critic1.pth'))
        torch.save(agent.critic2.state_dict(), os.path.join(args.save_dir, 'critic2.pth'))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--env_name", default="Pendulum-v1")
    parser.add_argument("--seed", default=0, type=int)
    parser.add_argument("--max_timesteps", default=1_000_000, type=int)
    parser.add_argument("--start_timesteps", default=25_000, type=int)
    parser.add_argument("--eval_freq", default=5_000, type=int)
    parser.add_argument("--batch_size", default=256, type=int)
    parser.add_argument("--expl_noise", default=0.1, type=float)
    parser.add_argument("--device", default="cpu", type=str)
    parser.add_argument("--log_dir", default=None, type=str)
    parser.add_argument("--save_model", action="store_true")
    parser.add_argument("--save_dir", default="./models", type=str)
    args = parser.parse_args()

    train(args)
