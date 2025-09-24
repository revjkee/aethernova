# genius-core/code-context/sync/file_change_watcher.py

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Callable, Optional, List, Dict

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

logger = logging.getLogger("FileChangeWatcher")


class FileHasher:
    @staticmethod
    def hash_file(path: Path) -> str:
        h = hashlib.sha256()
        try:
            with path.open("rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.warning(f"Hashing failed: {e}")
            return ""


class ChangeTracker:
    def __init__(self):
        self.known_hashes: Dict[str, str] = {}

    def has_changed(self, path: Path) -> bool:
        new_hash = FileHasher.hash_file(path)
        old_hash = self.known_hashes.get(str(path), None)
        if new_hash and new_hash != old_hash:
            self.known_hashes[str(path)] = new_hash
            return True
        return False


class ChangeHandler(FileSystemEventHandler):
    def __init__(
        self,
        tracker: ChangeTracker,
        on_change: Callable[[Path], None],
        include_exts: Optional[List[str]] = None,
        exclude_dirs: Optional[List[str]] = None,
    ):
        self.tracker = tracker
        self.on_change = on_change
        self.include_exts = include_exts or [".py"]
        self.exclude_dirs = exclude_dirs or [".git", "venv", "__pycache__"]

    def _should_track(self, path: Path) -> bool:
        if not path.suffix in self.include_exts:
            return False
        for excl in self.exclude_dirs:
            if excl in path.parts:
                return False
        return path.is_file()

    def on_modified(self, event: FileSystemEvent):
        path = Path(event.src_path)
        if self._should_track(path) and self.tracker.has_changed(path):
            logger.info(f"File changed: {path}")
            self.on_change(path)

    def on_created(self, event: FileSystemEvent):
        path = Path(event.src_path)
        if self._should_track(path) and self.tracker.has_changed(path):
            logger.info(f"New file created: {path}")
            self.on_change(path)


class FileChangeWatcher:
    def __init__(
        self,
        path: Path,
        on_change: Callable[[Path], None],
        include_exts: Optional[List[str]] = None,
        exclude_dirs: Optional[List[str]] = None,
    ):
        self.path = path
        self.on_change = on_change
        self.tracker = ChangeTracker()
        self.handler = ChangeHandler(
            self.tracker,
            self.on_change,
            include_exts=include_exts,
            exclude_dirs=exclude_dirs
        )
        self.observer = Observer()

    def start(self):
        self.observer.schedule(self.handler, str(self.path), recursive=True)
        self.observer.start()
        logger.info(f"Watching for changes in {self.path}")

    def stop(self):
        self.observer.stop()
        self.observer.join()


async def run_async_watcher(
    path: Path,
    on_change: Callable[[Path], None],
    poll_interval: float = 1.0
):
    watcher = FileChangeWatcher(path, on_change)
    watcher.start()

    try:
        while True:
            await asyncio.sleep(poll_interval)
    except KeyboardInterrupt:
        pass
    finally:
        watcher.stop()


# Example usage:
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    def on_file_changed(path: Path):
        print(f"[TRIGGERED] File changed: {path}")

    asyncio.run(run_async_watcher(Path("./"), on_file_changed))
