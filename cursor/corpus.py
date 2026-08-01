"""corpus.py -- the retrieval layer, and the second untrusted input.

Dense cosine over a numpy array. That is the entire thing: no vector DB, no
BM25, no re-ranking, no persistence (spec section 5). It is a toy on purpose --
the point is that a toy is already enough to demonstrate the attack.

    load_corpus()          -> ~50 KEV docs
    build_index(docs)      -> embed, cache in memory
    retrieve(query, k=3)   -> top-k by cosine similarity
    inject_doc(doc)        -> add one poisoned doc and embed it
"""

import json
import os

import numpy as np

KEV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kev.json")
EMBED_MODEL = "all-MiniLM-L6-v2"
CORPUS_SIZE = 50

# CVEs the poisoned docs target. Pinned so the demo cannot silently lose its
# target when the KEV feed shifts.
#
# Deliberately obscure-but-real KEV entries, NOT household names like Log4Shell.
# Measured finding: the models carry strong parametric priors for famous CVEs and
# escalate them no matter what any retrieved advisory says -- so poisoning cannot
# move them. Real corpus poisoning targets the long tail the model has no memory
# of, which forces the agent to rely on the retrieved doc. Recognisable *vendors*
# (Splunk, Cisco, Microsoft, LiteLLM) keep the stakes legible to judges.
PINNED = [
    "CVE-2026-20253",  # Splunk Enterprise -- missing auth (hero: SOC's own SIEM)
    "CVE-2026-42208",  # BerriAI LiteLLM -- SQL injection (AI-security angle)
    "CVE-2026-20122",  # Cisco Catalyst SD-WAN Manager -- privilege issue
    "CVE-2025-30400",  # Microsoft Windows DWM -- use-after-free
    "CVE-2026-21533",  # Microsoft Windows -- privilege management
]

_model = None
_docs: list[dict] = []
_emb: np.ndarray | None = None


def _get_model():
    """Lazy: importing sentence_transformers costs ~36s cold. Do it once."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer(EMBED_MODEL)
    return _model


def _to_doc(entry: dict, n: int) -> dict:
    """Flatten a KEV entry into the section 4 doc schema."""
    text = (
        f"{entry['cveID']} -- {entry['vulnerabilityName']}. "
        f"Affected: {entry['vendorProject']} {entry['product']}. "
        f"{entry['shortDescription']} "
        f"Required action: {entry['requiredAction']} "
        f"Known ransomware campaign use: {entry['knownRansomwareCampaignUse']}. "
        f"Added {entry['dateAdded']}."
    )
    return {
        "doc_id": f"kev-{n:04d}",
        "cve": entry["cveID"],
        "text": text,
        "source": "cisa-kev",
        "poisoned": False,
    }


def load_corpus() -> list[dict]:
    """~50 genuine KEV advisories, with the pinned targets guaranteed present."""
    with open(KEV_PATH, encoding="utf-8") as fh:
        entries = json.load(fh)["vulnerabilities"]

    by_cve = {e["cveID"]: e for e in entries}
    chosen = [by_cve[c] for c in PINNED if c in by_cve]

    # Fill the rest with the most recently added, deterministically.
    rest = sorted(
        (e for e in entries if e["cveID"] not in PINNED),
        key=lambda e: (e["dateAdded"], e["cveID"]),
        reverse=True,
    )
    chosen += rest[: CORPUS_SIZE - len(chosen)]

    return [_to_doc(e, i + 1) for i, e in enumerate(chosen)]


def build_index(docs: list[dict]) -> None:
    """Embed every doc once. Unit-normalised, so cosine is just a dot product."""
    global _docs, _emb
    _docs = list(docs)
    _emb = _get_model().encode(
        [d["text"] for d in _docs], normalize_embeddings=True, show_progress_bar=False
    )


def retrieve(query: str, k: int = 3) -> list[dict]:
    """Top-k by cosine similarity. Scores are attached for the UI to display."""
    if _emb is None:
        raise RuntimeError("call build_index() first")
    q = _get_model().encode([query], normalize_embeddings=True)[0]
    sims = _emb @ q
    return [{**_docs[i], "score": float(sims[i])} for i in np.argsort(-sims)[:k]]


def inject_doc(doc: dict) -> None:
    """Plant one document in the corpus. This is the whole of Channel B.

    Note what is absent: no provenance check, no authority weighting, no
    recency arbitration. Retrieval ranks on topic similarity alone, so a
    fabricated advisory about CVE-X competes on equal terms with the real one.
    """
    global _docs, _emb
    if _emb is None:
        raise RuntimeError("call build_index() first")
    vec = _get_model().encode([doc["text"]], normalize_embeddings=True)
    _docs.append(doc)
    _emb = np.vstack([_emb, vec])


def corpus_size() -> int:
    return len(_docs)


if __name__ == "__main__":
    docs = load_corpus()
    print(f"loaded {len(docs)} docs; pinned present: "
          f"{sum(d['cve'] in PINNED for d in docs)}/{len(PINNED)}")
    build_index(docs)
    hits = retrieve("Anomalous session activity on netscaler-gw-01, tokens reused "
                    "from multiple geographies")
    for h in hits:
        print(f"  {h['score']:.3f}  {h['doc_id']}  {h['cve']}  {h['text'][:60]}")
