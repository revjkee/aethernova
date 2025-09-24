import unittest
from graph_core.graph import Graph
from graph_core.storage import GraphStorage
from graph_core.analytics import GraphAnalytics

class TestGraphCore(unittest.TestCase):

    def setUp(self):
        self.storage = GraphStorage()
        self.analytics = GraphAnalytics(self.storage)
        # Создаём простой граф для тестов
        self.storage.add_edge("A", "B")
        self.storage.add_edge("A", "C")
        self.storage.add_edge("B", "D")
        self.storage.add_edge("C", "D")
        self.storage.add_edge("D", "E")

    def test_add_edge(self):
        self.storage.add_edge("E", "F")
        neighbors = self.storage.get_neighbors("E")
        self.assertIn("F", neighbors)

    def test_bfs(self):
        bfs_order = self.analytics.bfs("A")
        expected_order = ["A", "B", "C", "D", "E"]
        self.assertEqual(bfs_order, expected_order)

    def test_dfs(self):
        dfs_order = self.analytics.dfs("A")
        # DFS может иметь несколько валидных порядков,
        # проверяем, что все узлы посещены и первый - A
        self.assertIn("A", dfs_order)
        self.assertEqual(dfs_order[0], "A")
        self.assertCountEqual(dfs_order, ["A", "B", "C", "D", "E"])

    def test_shortest_path(self):
        path = self.analytics.shortest_path("A", "E")
        expected_path = ["A", "B", "D", "E"]
        self.assertEqual(path, expected_path)

        no_path = self.analytics.shortest_path("E", "A")
        self.assertEqual(no_path, [])

    def test_node_degrees(self):
        degrees = self.analytics.node_degrees()
        expected_degrees = {
            "A": 2,
            "B": 1,
            "C": 1,
            "D": 1,
            "E": 0
        }
        self.assertEqual(degrees, expected_degrees)

    def test_nonexistent_node(self):
        self.assertEqual(self.analytics.bfs("Z"), [])
        self.assertEqual(self.analytics.dfs("Z"), [])
        self.assertEqual(self.analytics.shortest_path("A", "Z"), [])
        self.assertEqual(self.analytics.shortest_path("Z", "A"), [])

if __name__ == "__main__":
    unittest.main()
