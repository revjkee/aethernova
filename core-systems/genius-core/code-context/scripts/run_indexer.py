# genius-core/code-context/scripts/run_indexer.py

import argparse
import logging
from pathlib import Path

from code_context.indexer.index_engine import CodeContextIndexer
from code_context.indexer.language_detectors import detect_language
from code_context.sync.dag_tracker import MerkleDAGTracker
from code_context.sync.delta_indexer import DeltaIndexer
from code_context.config.loader import load_config


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Run Code Context Indexer.")
    parser.add_argument(
        "--config", type=str, default="code-context/config/config.yaml",
        help="Path to global config file"
    )
    parser.add_argument(
        "--root", type=str, default=".",
        help="Path to root directory to index"
    )
    parser.add_argument(
        "--save", type=str, default="code-context/data/code_context_index.json",
        help="Path to save output index JSON"
    )
    return parser.parse_args()


def main():
    setup_logging()
    args = parse_args()

    logging.info(f"Loading configuration from: {args.config}")
    config = load_config(args.config)

    root_path = Path(args.root).resolve()
    if not root_path.exists():
        logging.error(f"Directory not found: {root_path}")
        return

    logging.info(f"Indexing path: {root_path}")

    dag_tracker = MerkleDAGTracker()
    indexer = CodeContextIndexer(config=config)
    delta_indexer = DeltaIndexer()

    file_map = {}

    for path in root_path.rglob("*.*"):
        if path.is_file():
            try:
                code = path.read_text(encoding="utf-8", errors="ignore")
                lang = detect_language(path.name, code)
                dag_tracker.add_file(str(path), code)
                file_map[str(path)] = code
                logging.debug(f"Indexed {path.name} as {lang}")
            except Exception as e:
                logging.warning(f"Failed to read {path}: {e}")

    # Create embedding-based context index
    context_index = indexer.build_index(file_map)

    # Save to JSON
    out_path = Path(args.save)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    indexer.save_index(context_index, out_path)

    logging.info(f"Saved context index to {out_path}")

    # Optional: Print summary DAG hash
    dag_hashes = dag_tracker.get_dag()
    logging.info(f"Total files tracked in DAG: {len(dag_hashes)}")
    logging.debug(f"DAG snapshot: {dag_hashes}")


if __name__ == "__main__":
    main()
