# genius-core/code-context/tests/test_sync.py

import os
import time
import pytest
import tempfile
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from code_context.sync.file_change_watcher import start_watch, FileChangeCollector
from code_context.sync.dag_tracker import MerkleDAGTracker
from code_context.sync.delta_indexer import DeltaIndexer


# === FILE WATCHER TESTS ===

def test_file_change_collector_event_handling():
    collector = FileChangeCollector()
    dummy_event = type("Dummy", (), {"src_path": "/tmp/dummy.py"})()
    collector.on_modified(dummy_event)
    assert "/tmp/dummy.py" in collector.changed_files


def test_file_watcher_with_temp_file():
    collector = FileChangeCollector()
    tmpdir = tempfile.TemporaryDirectory()
    file_path = os.path.join(tmpdir.name, "testfile.txt")

    observer = Observer()
    observer.schedule(collector, tmpdir.name, recursive=True)
    observer.start()

    try:
        with open(file_path, "w") as f:
            f.write("test123")
        time.sleep(0.2)
        assert file_path in collector.changed_files
    finally:
        observer.stop()
        observer.join()
        tmpdir.cleanup()


# === DAG TRACKER TESTS ===

def test_merkle_dag_tracker_basic_flow():
    tracker = MerkleDAGTracker()
    tracker.add_file("src/foo.py", "print('hello')")
    tracker.add_file("src/bar.py", "x = 123")

    dag = tracker.get_dag()
    assert "src/foo.py" in dag
    assert "src/bar.py" in dag
    assert isinstance(dag["src/foo.py"]["hash"], str)


def test_merkle_dag_diff():
    tracker = MerkleDAGTracker()
    tracker.add_file("a.py", "one")
    snapshot1 = tracker.get_dag()
    
    tracker.add_file("a.py", "two")
    tracker.add_file("b.py", "new")
    diffs = tracker.get_diff(snapshot1)

    assert "a.py" in diffs["modified"]
    assert "b.py" in diffs["added"]


# === DELTA INDEXER TESTS ===

@pytest.fixture
def mock_file_map():
    return {
        "src/main.py": "print('hi')",
        "src/utils.py": "def f(): pass",
        "README.md": "# readme"
    }

def test_delta_indexer_index_creation(mock_file_map):
    indexer = DeltaIndexer()
    index = indexer.build_index(mock_file_map)

    assert isinstance(index, dict)
    assert "src/main.py" in index
    assert "tokens" in index["src/main.py"]


def test_delta_indexer_diff(mock_file_map):
    indexer = DeltaIndexer()
    base_index = indexer.build_index(mock_file_map)

    modified_map = mock_file_map.copy()
    modified_map["src/main.py"] = "print('hello world')"
    modified_map["LICENSE"] = "MIT"

    delta = indexer.diff_index(base_index, modified_map)
    assert "src/main.py" in delta["modified"]
    assert "LICENSE" in delta["added"]
    assert "README.md" not in delta["deleted"]


# === EDGE CASES & ERROR CONDITIONS ===

def test_dag_tracker_empty_init():
    tracker = MerkleDAGTracker()
    assert tracker.get_dag() == {}


def test_delta_indexer_empty_input():
    indexer = DeltaIndexer()
    delta = indexer.diff_index({}, {})
    assert delta == {"added": [], "modified": [], "deleted": []}
