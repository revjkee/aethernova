# genius-core/code-context/scripts/watch_repo.py

import asyncio
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from code_context.sync.file_change_watcher import get_tracked_files
from code_context.sync.dag_tracker import MerkleDAGTracker
from code_context.sync.delta_indexer import DeltaIndexer
from code_context.indexer.index_engine import CodeContextIndexer
from code_context.config.loader import load_config

from code_context.api.websocket_handler import broadcast_reload_message


class RepoEventHandler(FileSystemEventHandler):
    def __init__(self, repo_root: Path, config_path: Path, index_output_path: Path):
        self.repo_root = repo_root
        self.config = load_config(config_path)
        self.dag_tracker = MerkleDAGTracker()
        self.indexer = CodeContextIndexer(config=self.config)
        self.delta_indexer = DeltaIndexer()
        self.index_output_path = index_output_path

    def on_any_event(self, event: FileSystemEvent):
        if not event.is_directory and event.src_path.endswith(('.py', '.js', '.ts', '.cpp', '.go', '.rs')):
            logging.info(f"[WATCH] Change detected: {event.src_path}")
            asyncio.run(self.handle_change(Path(event.src_path)))

    async def handle_change(self, changed_file: Path):
        try:
            code = changed_file.read_text(encoding="utf-8", errors="ignore")
            file_map = {str(changed_file): code}
            self.dag_tracker.update_file(str(changed_file), code)

            context_index = self.indexer.build_index(file_map)
            self.indexer.save_index(context_index, self.index_output_path, merge=True)

            logging.info(f"[INDEX] Updated index with {changed_file.name}")
            await broadcast_reload_message({
                "type": "reload",
                "file": str(changed_file),
                "status": "indexed"
            })
        except Exception as e:
            logging.error(f"[ERROR] Failed to index {changed_file}: {e}")


def watch(repo_path: str, config_path: str, output_path: str):
    path = Path(repo_path).resolve()
    config = Path(config_path).resolve()
    output = Path(output_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Repo directory not found: {path}")

    logging.info(f"Watching repository: {path}")

    event_handler = RepoEventHandler(path, config, output)
    observer = Observer()
    observer.schedule(event_handler, str(path), recursive=True)
    observer.start()

    try:
        while True:
            asyncio.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def main():
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Watch repo and trigger live index updates")
    parser.add_argument("--repo", type=str, default=".", help="Root of code repository")
    parser.add_argument("--config", type=str, default="code-context/config/config.yaml", help="Path to YAML config")
    parser.add_argument("--out", type=str, default="code-context/data/code_context_index.json", help="Index output path")

    args = parser.parse_args()
    watch(args.repo, args.config, args.out)


if __name__ == "__main__":
    main()
