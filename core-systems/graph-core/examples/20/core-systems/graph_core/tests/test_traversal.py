import unittest
from graph_core.traversal import bfs, dfs
from graph_core.storage import GraphStorage

class TestTraversal(unittest.TestCase):

    def setUp(self):
        self.storage = GraphStorage()
        # Формируем тестовый граф
        self.storage.add_edge("1", "2")
        self.storage.add_edge("1", "3")
        self.storage.add_edge("2", "4")
        self.storage.add_edge("3", "4")
        self.storage.add_edge("4", "5")

    def test_bfs_traversal(self):
        result = bfs(self.storage, "1")
        expected = ["1", "2", "3", "4", "5"]
        self.assertEqual(result, expected)

    def test_bfs_nonexistent_start(self):
        result = bfs(self.storage, "X")
        self.assertEqual(result, [])

    def test_dfs_traversal(self):
        result = dfs(self.storage, "1")
        # DFS может иметь разный порядок, проверяем содержимое и начальный элемент
        self.assertIn("1", result)
        self.assertCountEqual(result, ["1", "2", "3", "4", "5"])

    def test_dfs_nonexistent_start(self):
        result = dfs(self.storage, "X")
        self.assertEqual(result, [])

if __name__ == "__main__":
    unittest.main()
