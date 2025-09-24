# agent-mesh/tests/test_rl_planner.py

import pytest
from agent_mesh.planner.rl_planner import RLPlanner


class MockEnvironment:
    """
    Простое окружение с конечным числом допустимых действий.
    """
    def __init__(self):
        self.available_actions = ["scan", "explore", "respond"]

    def get_actions(self, state):
        return self.available_actions


@pytest.fixture
def setup_planner():
    env = MockEnvironment()
    planner = RLPlanner(env)
    return planner, env


def test_initial_action_selection(setup_planner):
    planner, env = setup_planner
    state = {"goal": "monitor"}
    action = planner.select_action(state)

    assert action in env.available_actions


def test_learn_from_feedback(setup_planner):
    planner, _ = setup_planner
    state = {"goal": "scan-network"}
    action = "scan"
    reward = 1.0

    planner.learn(state, action, reward)
    score = planner.q_table.get(str(state), {}).get(action)

    assert score is not None
    assert score > 0


def test_action_update_with_low_reward(setup_planner):
    planner, _ = setup_planner
    state = {"goal": "scan-network"}
    action = "scan"
    planner.learn(state, action, reward=0.1)
    planner.learn(state, action, reward=-0.5)

    score = planner.q_table.get(str(state), {}).get(action)
    assert score < 0.2
