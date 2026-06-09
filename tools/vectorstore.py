"""
DFIRLlamaStore — lightweight BM25 vector store for NL→SQL retrieval.

Uses SQLite + Okapi BM25 instead of ChromaDB. No external dependencies,
no embeddings, no GPU. For the few thousand Q-SQL training pairs used in
forensic NL→SQL this is faster and more predictable than vector similarity.
"""

import math
import re
import sqlite3


class DFIRLlamaStore:
    """
    Stores DDL schemas, DFIR documentation, and question-SQL pairs.
    Retrieves the most relevant items for a given query using BM25.
    """

    def __init__(self, store_path: str):
        self.db = sqlite3.connect(store_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS training_items (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                kind     TEXT NOT NULL,
                question TEXT,
                sql      TEXT,
                content  TEXT NOT NULL,
                added_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_kind ON training_items(kind);
        """)
        self.db.commit()

    def add_qa(self, question: str, sql: str) -> None:
        self.db.execute(
            "INSERT INTO training_items (kind, question, sql, content) VALUES ('qa',?,?,?)",
            (question, sql, f"{question} {sql}")
        )
        self.db.commit()

    def add_doc(self, doc: str) -> None:
        self.db.execute(
            "INSERT INTO training_items (kind, content) VALUES ('doc',?)", (doc,)
        )
        self.db.commit()

    def add_ddl(self, ddl: str) -> None:
        self.db.execute(
            "INSERT INTO training_items (kind, content) VALUES ('ddl',?)", (ddl,)
        )
        self.db.commit()

    def count(self, kind: str | None = None) -> int:
        if kind:
            return self.db.execute(
                "SELECT COUNT(*) FROM training_items WHERE kind=?", (kind,)
            ).fetchone()[0]
        return self.db.execute("SELECT COUNT(*) FROM training_items").fetchone()[0]

    def get_all_ddl(self) -> list[str]:
        rows = self.db.execute(
            "SELECT content FROM training_items WHERE kind='ddl'"
        ).fetchall()
        return [r[0] for r in rows]

    def get_all_docs(self) -> list[str]:
        rows = self.db.execute(
            "SELECT content FROM training_items WHERE kind='doc'"
        ).fetchall()
        return [r[0] for r in rows]

    def get_similar_qa(self, query: str, top_k: int = 5) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, question, sql, content FROM training_items WHERE kind='qa'"
        ).fetchall()
        if not rows:
            return []
        corpus  = [r[3] for r in rows]
        scores  = _bm25_scores(query, corpus)
        ranked  = sorted(zip(scores, rows), key=lambda x: x[0], reverse=True)
        return [
            {"question": r[1], "sql": r[2], "score": s}
            for s, r in ranked[:top_k] if s > 0
        ]

    def close(self):
        self.db.close()


# ── BM25 (Okapi BM25) ─────────────────────────────────────────────────────────

def _tokenize(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def _bm25_scores(query: str, corpus: list[str],
                 k1: float = 1.5, b: float = 0.75) -> list[float]:
    if not corpus:
        return []
    q_tokens = _tokenize(query)
    docs     = [_tokenize(d) for d in corpus]
    n        = len(docs)
    avg_dl   = sum(len(d) for d in docs) / n

    idf: dict[str, float] = {}
    for term in set(q_tokens):
        df         = sum(1 for d in docs if term in d)
        idf[term]  = math.log((n - df + 0.5) / (df + 0.5) + 1)

    scores = []
    for doc in docs:
        dl        = len(doc)
        tf_map: dict[str, int] = {}
        for t in doc:
            tf_map[t] = tf_map.get(t, 0) + 1
        score = 0.0
        for term in q_tokens:
            tf = tf_map.get(term, 0)
            if tf == 0:
                continue
            score += idf.get(term, 0) * tf * (k1 + 1) / (
                tf + k1 * (1 - b + b * dl / avg_dl)
            )
        scores.append(score)
    return scores


def bm25_top_k(query: str, docs: list[str], k: int = 5) -> list[str]:
    """Return the top-k most relevant docs for query using BM25."""
    scores = _bm25_scores(query, docs)
    ranked = sorted(zip(scores, docs), key=lambda x: x[0], reverse=True)
    return [doc for score, doc in ranked[:k] if score > 0]
