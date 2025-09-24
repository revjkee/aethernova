# genius-core/generative-defense/graph_policy_generator.py

import networkx as nx
import torch
from torch import nn
from typing import List, Dict, Any

class GraphPolicyGenerator(nn.Module):
    """
    Генератор политик безопасности на основе графов и LLM.
    Использует графовую структуру для моделирования взаимодействий компонентов системы
    и генерирует политики для защиты на основе анализа связей.
    """

    def __init__(self, node_feature_dim: int, hidden_dim: int, output_dim: int):
        super().__init__()
        self.graph_encoder = GraphEncoder(node_feature_dim, hidden_dim)
        self.policy_decoder = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, output_dim),
            nn.Sigmoid()
        )

    def forward(self, graph_data: Dict[str, Any]) -> torch.Tensor:
        """
        Входные данные — граф в формате dict с 'nodes' и 'edges'.
        Возвращает сгенерированные политики в виде тензора вероятностей.
        """
        node_features = graph_data['node_features']  # Tensor [num_nodes, node_feature_dim]
        edge_index = graph_data['edge_index']        # Tensor [2, num_edges]

        graph_embedding = self.graph_encoder(node_features, edge_index)
        policy = self.policy_decoder(graph_embedding)
        return policy

class GraphEncoder(nn.Module):
    """
    Простая графовая нейросеть (Graph Neural Network) для кодирования узлов.
    """

    def __init__(self, input_dim: int, hidden_dim: int):
        super().__init__()
        self.conv1 = GraphConvLayer(input_dim, hidden_dim)
        self.conv2 = GraphConvLayer(hidden_dim, hidden_dim)
        self.pool = nn.AdaptiveAvgPool1d(1)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        x: [num_nodes, input_dim]
        edge_index: [2, num_edges]
        """
        x = self.conv1(x, edge_index)
        x = torch.relu(x)
        x = self.conv2(x, edge_index)
        x = torch.relu(x)
        # Глобальный pooling: усреднение по всем узлам
        x = x.transpose(0,1).unsqueeze(0)  # [1, hidden_dim, num_nodes]
        pooled = self.pool(x).squeeze()    # [hidden_dim]
        return pooled

class GraphConvLayer(nn.Module):
    """
    Простая реализация графовой сверточной операции (Graph Convolution Layer).
    """

    def __init__(self, in_channels: int, out_channels: int):
        super().__init__()
        self.linear = nn.Linear(in_channels, out_channels)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        x: [num_nodes, in_channels]
        edge_index: [2, num_edges]
        """
        num_nodes = x.size(0)
        agg = torch.zeros_like(x)

        src, dst = edge_index
        # Агрегация сообщений от соседей
        agg.index_add_(0, dst, x[src])

        out = self.linear(agg)
        return out

