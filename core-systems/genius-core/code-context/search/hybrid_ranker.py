# genius-core/code-context/search/hybrid_ranker.py

import json
import numpy as np
from typing import List, Dict, Tuple
from pathlib import Path
from sklearn.metrics.pairwise import cosine_similarity
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer

from genius_core.code_context.search.semantic_search import embed_code_snippet

INDEX_PATH = Path("genius-core/code-context/data/code_context_index.json")
MODEL = SentenceTransformer("BAAI/bge-small-en-v1.5")


def load_index(index_path: Path = INDEX_PATH) -> Dict[str, Dict]:
    with open(index_path, "r", encoding="utf-8") as f:
        return json.load(f)


def bm25_candidates(query: str, index_data: Dict[str, Dict], top_k: int = 20) -> List[str]:
    corpus = [item.get("raw_code", "") for item in index_data.values()]
    tokenized_corpus = [doc.split() for doc in corpus]
    bm25 = BM25Okapi(tokenized_corpus)
    tokenized_query = query.split()
    scores = bm25.get_scores(tokenized_query)

    file_paths = list(index_data.keys())
    ranked = sorted(zip(file_paths, scores), key=lambda x: x[1], reverse=True)
    return [path for path, _ in ranked[:top_k]]


def hybrid_rank(
    query: str,
    index_data: Dict[str, Dict],
    top_k_bm25: int = 20,
    final_k: int = 5,
    alpha: float = 0.5
) -> List[Tuple[str, float]]:
    candidates = bm25_candidates(query, index_data, top_k=top_k_bm25)
    query_emb = np.array(embed_code_snippet(query))

    results = []
    for path in candidates:
        item = index_data[path]
        emb = np.array(item.get("embedding"))
        bm25_score = 1.0  # упрощённо, можно нормализовать отдельно
        cos_sim = float(cosine_similarity([query_emb], [emb])[0][0])
        hybrid_score = alpha * cos_sim + (1 - alpha) * bm25_score
        results.append((path, hybrid_score))

    results.sort(key=lambda x: x[1], reverse=True)
    return results[:final_k]


def hybrid_search(query: str, top_k: int = 5) -> List[Tuple[str, float]]:
    index = load_index()
    return hybrid_rank(query, index, top_k_bm25=20, final_k=top_k, alpha=0.7)
