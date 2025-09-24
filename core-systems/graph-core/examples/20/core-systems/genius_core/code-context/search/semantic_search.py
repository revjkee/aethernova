# genius-core/code-context/search/semantic_search.py

import json
import numpy as np
from typing import List, Dict, Tuple
from pathlib import Path
from sklearn.metrics.pairwise import cosine_similarity

try:
    from sentence_transformers import SentenceTransformer
    LOCAL_MODEL = SentenceTransformer("BAAI/bge-small-en-v1.5")
except ImportError:
    LOCAL_MODEL = None

INDEX_PATH = Path("genius-core/code-context/data/code_context_index.json")


def load_index(path: Path = INDEX_PATH) -> Dict[str, Dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def embed_code_snippet(snippet: str, method: str = "bge") -> List[float]:
    if method == "openai":
        import openai
        response = openai.Embedding.create(
            model="text-embedding-ada-002",
            input=snippet
        )
        return response["data"][0]["embedding"]

    elif method == "bge":
        if not LOCAL_MODEL:
            raise RuntimeError("BGE model not loaded")
        return LOCAL_MODEL.encode(snippet, normalize_embeddings=True).tolist()

    else:
        raise ValueError(f"Unsupported embedding method: {method}")


def semantic_search(query: str, index_data: Dict[str, Dict], top_k: int = 5) -> List[Tuple[str, float]]:
    query_vec = np.array(embed_code_snippet(query))
    candidates = []

    for file_path, meta in index_data.items():
        vec = np.array(meta.get("embedding"))
        if vec.shape != query_vec.shape:
            continue
        sim = float(cosine_similarity([query_vec], [vec])[0][0])
        candidates.append((file_path, sim))

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[:top_k]


def search_snippets(query: str, top_k: int = 5) -> List[Tuple[str, float]]:
    index = load_index()
    return semantic_search(query, index, top_k)
