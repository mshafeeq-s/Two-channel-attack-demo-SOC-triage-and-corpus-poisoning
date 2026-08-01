"""app.py -- Second Channel demo UI (corpus-poisoning only).

We attack the agent's knowledge base, not the alert. Prompt injection is the
"first channel" everyone already tests; this is the second one, and it's the
one nobody watches.

The beat: a clean alert triages correctly. Plant ONE fake advisory in the corpus.
Re-run the SAME untouched alert -- it now gets waved through. And it stays that
way for every future alert about that CVE.

Design notes:
  - Base corpus (embeddings) built ONCE via st.cache_resource (~36s import).
  - Poisons are a session overlay in st.session_state, NOT mutations of the cache.
    "Reset corpus" just clears the overlay -- mirrors the threat model.
  - Verdicts cached (st.cache_data) so the 8B's ~20s/verdict is paid once per
    distinct situation, not per click.

Run:  python -m streamlit run app.py
"""

import numpy as np
import streamlit as st

import agent
import corpus
import poison

st.set_page_config(page_title="Second Channel", page_icon=":material/coronavirus:",
                   layout="wide")

MODELS = ["llama3.1", "llama3.2:3b"]
SEV_COLOR = {"critical": "red", "high": "orange", "medium": "orange",
             "low": "green", "none": "green", "unparsed": "gray"}


# --------------------------------------------------------------------------- #
# Cached heavy resources
# --------------------------------------------------------------------------- #
@st.cache_resource(show_spinner="Loading embedding model and indexing corpus...")
def load_base():
    docs = corpus.load_corpus()
    model = corpus._get_model()
    emb = model.encode([d["text"] for d in docs], normalize_embeddings=True,
                       show_progress_bar=False)
    return model, docs, emb


@st.cache_data(show_spinner=False, max_entries=64)
def _embed(text: str) -> np.ndarray:
    model, _, _ = load_base()
    return model.encode([text], normalize_embeddings=True)[0]


@st.cache_data(show_spinner=False, max_entries=256)
def cached_triage(alert: dict, docs: tuple, model_name: str) -> dict:
    agent.MODEL = model_name
    doc_ids = [d[0] for d in docs]
    _, base_docs, _ = load_base()
    lookup = {d["doc_id"]: d for d in base_docs}
    lookup.update({p["doc_id"]: p for p in poison.POISONS})
    resolved = [lookup[i] for i in doc_ids if i in lookup]
    return agent.triage(alert, resolved)


def retrieve(query: str, injected: list, k: int = 3) -> list:
    """Base corpus + session-injected poisons, ranked together by cosine."""
    _, base_docs, base_emb = load_base()
    docs = list(base_docs) + list(injected)
    emb = base_emb
    if injected:
        emb = np.vstack([base_emb] + [_embed(p["text"])[None, :] for p in injected])
    q = _embed(query)
    sims = emb @ q
    return [{**docs[i], "score": float(sims[i])} for i in np.argsort(-sims)[:k]]


def alert_query(a: dict) -> str:
    return f"{a['subject']}. {a['raw_log']}"


def triage_alert(alert: dict, injected: list, model_name: str, k: int = 3):
    docs = retrieve(alert_query(alert), injected, k=k)
    doc_key = tuple((d["doc_id"], round(d["score"], 4)) for d in docs)
    return cached_triage(alert, doc_key, model_name), docs


def verdict_card(title: str, verdict: dict, docs: list):
    with st.container(border=True):
        st.caption(title)
        sev, act = verdict["severity"], verdict["action"]
        color = SEV_COLOR.get(sev, "gray")
        st.markdown(f"### :{color}[{sev.upper()}] &nbsp; · &nbsp; {act}")
        st.write(verdict["reasoning"] or "_(no reasoning returned)_")
        st.caption("Retrieved documents (top-k)")
        for d in docs:
            icon = ":red[:material/coronavirus: POISON]" if d.get("poisoned") \
                else ":green[:material/verified: kev]"
            st.markdown(f"- {icon} &nbsp; `{d['doc_id']}` &nbsp; score **{d['score']:.3f}** "
                        f"&nbsp; · &nbsp; {d['cve']}")


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
st.session_state.setdefault("injected", [])
st.session_state.setdefault("model", MODELS[0])
load_base()  # warm the cache up front

st.title(":material/coronavirus: Second Channel")
st.markdown("**A SOC triage agent has two untrusted inputs — the alert, and the "
            "knowledge base it looks things up in. Everyone tests the alert. "
            "We poison the knowledge base.**")

with st.sidebar:
    st.header("Target")
    st.session_state.model = st.selectbox("Triage model", MODELS,
                                          index=MODELS.index(st.session_state.model))
    st.caption("llama3.1 gives graded verdicts a poison can move. llama3.2:3b flags "
               "everything critical — robust-looking, but only because it can't "
               "discriminate.")
    _, base_docs, _ = load_base()
    st.metric("Corpus size", f"{len(base_docs) + len(st.session_state.injected)} docs")
    st.metric("Poisoned docs live", len(st.session_state.injected))
    if st.button("Reset corpus", icon=":material/restart_alt:", width="stretch"):
        st.session_state.injected = []
        st.rerun()

clean_alert = agent.CLEAN_ALERT

with st.container(border=True):
    st.caption("The clean alert — unchanged throughout the whole demo")
    st.markdown(f"**{clean_alert['subject']}**")
    st.write(clean_alert["raw_log"])
    st.caption(f"CVE: {clean_alert['cve']}  ·  source_ip: {clean_alert['source_ip']}")

c1, c2, c3 = st.columns(3)
with c1:
    if st.button("1 · Triage (clean corpus)", width="stretch"):
        st.session_state.res_clean = triage_alert(clean_alert, [], st.session_state.model)
with c2:
    if st.button("2 · Inject poison :material/coronavirus:", type="primary",
                 width="stretch"):
        tp = poison.by_cve(clean_alert["cve"])
        if tp and tp["doc_id"] not in {p["doc_id"] for p in st.session_state.injected}:
            st.session_state.injected.append(tp)
        st.toast("Poison planted in corpus", icon=":material/coronavirus:")
with c3:
    if st.button("3 · Re-triage (same alert)", type="primary", width="stretch"):
        st.session_state.res_pois = triage_alert(clean_alert, st.session_state.injected,
                                                  st.session_state.model)

r1, r2 = st.columns(2)
with r1:
    if "res_clean" in st.session_state:
        verdict_card("Before poisoning", *st.session_state.res_clean)
with r2:
    if "res_pois" in st.session_state:
        verdict_card("After poisoning — same clean alert", *st.session_state.res_pois)

if st.session_state.injected:
    with st.expander("Show the planted document"):
        tp = poison.by_cve(clean_alert["cve"])
        if tp:
            st.caption(f"{tp['doc_id']}  ·  source: {tp['source']}  ·  poisoned: True")
            st.write(tp["text"])
            st.info("Calm, dated, procedural prose — no injected instructions, no odd "
                    "tokens. Fluent, so perplexity/fluency filters can't separate it "
                    "from a genuine advisory.", icon=":material/info:")

st.divider()
st.subheader("What just happened")
st.markdown(
    """
- The alert was **never touched.** Only the corpus changed — by one document.
- The poison out-ranks the real CISA advisory in retrieval, so the agent reads it.
- It's written like a routine follow-up bulletin, so fluency-based defences miss it.
- It **persists**: every future alert about this CVE gets the same poisoned answer.

**Measured (`llama3.1`):** baseline 5/5 correct · poisoning flips **3/5** ·
**4/4** future alerts stay mis-triaged after one poison. Full scorecard:
`python run_matrix.py`.
""")
