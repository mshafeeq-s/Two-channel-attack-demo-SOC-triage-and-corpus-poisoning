# Second Channel

A minimal RAG-backed SOC triage agent, and an attack on the input nobody tests.

An AI triage agent has **two** untrusted inputs: the **alert** it reads, and the
**knowledge base** it looks things up in. Prompt injection — attacking the alert —
is the *first channel*, and the whole industry is already defending it. We go after
the **second channel**: the corpus the agent retrieves from.

**Corpus poisoning:** plant one fluent fake advisory in the knowledge base. The
alert is never touched. The poison fires on every future alert that retrieves it —
silent, persistent, and invisible from the alert side.

---

## Result (measured, `llama3.1`, temp 0, seed 42)

- **Baseline:** 5/5 clean alerts triaged correctly *before* poisoning.
- **Poisoning:** flips **3/5** clean alerts (60% attack success).
- **Persistence:** one poison injection leaves **4/4** subsequent, distinct, clean
  alerts about the same CVE mis-triaged.

**Hero beat:** same untouched Splunk alert, run twice —
`HIGH / investigate` → plant one doc → `LOW / close`. The poison out-ranks the real
CISA advisory in retrieval (0.745 vs 0.527).

---

## Two findings that shaped the build

1. **Famous CVEs can't be poisoned; obscure ones can.** The model carries strong
   priors for Log4Shell / Citrix Bleed and escalates them no matter what any
   advisory says. Targets are five *obscure-but-real* KEV entries (Splunk, LiteLLM,
   Cisco, Windows ×2) the model has no memory of — which forces it to rely on the
   retrieved doc. This is also the realistic threat model: poison the long tail.

2. **The capable model is the vulnerable one.** `llama3.1` (8B) gives graded
   verdicts a poison can move. `llama3.2:3b` flags almost everything `critical`: it
   looks robust, but only because it can't discriminate — no judgment to corrupt.

---

## Architecture

```
   alert  ───────────────────┐
                             ├──►  llama3.1 triage  ──►  verdict
   corpus ──►  retrieve(top-k)┘        (temp 0)
   (attack here)
```

Dense cosine over a numpy array. No vector DB, no re-ranking, no persistence — 50
real CISA KEV docs embedded once in memory. Retrieval matches on *topic*, not
*truth*: that's the gap the poison walks through.

## Files

| File | Role |
|---|---|
| `agent.py`   | The triage agent. `triage(alert, docs)` → verdict. The target. |
| `corpus.py`  | KEV load, embed (MiniLM), cosine retrieve, `inject_doc()`. |
| `poison.py`  | 5 hand-written poisoned advisories. |
| `run_matrix.py` | Headless scorer + persistence probe (demo backup). |
| `app.py`     | Streamlit UI — the live poison beat. |
| `inject.py`  | *(archived — prompt-injection payloads, not used in this demo)* |

---

## Run it

Prereqs: Ollama with `llama3.1` pulled; `pip install -r requirements.txt`;
`kev.json` present (cached CISA KEV feed).

**Headless scorecard (unkillable backup):**
```bash
python run_matrix.py
```

**The UI:**
```bash
python -m streamlit run app.py
```
Open http://localhost:8501. `llama3.1` is ~20s/verdict on a 4 GB-VRAM laptop;
verdicts are cached, so a repeat is instant.

**Fallback backend** (if Ollama dies at the venue):
```bash
LLM_BACKEND=openrouter OPENROUTER_API_KEY=sk-... python run_matrix.py
```

---

## Demo script (2 min)

| Time | Beat |
|---|---|
| 0:00 | "SOC agents don't just read alerts — they look things up. Everyone attacks the alert with prompt injection. Nobody tests the lookup." |
| 0:20 | Clean Splunk alert → **HIGH / investigate**. Establish it works. |
| 0:45 | **Inject poison** — one document into the corpus. |
| 1:00 | Re-triage the **same untouched alert → LOW / close.** |
| 1:20 | "We never touched the alert. We poisoned its memory — and it stays poisoned for every future alert on this CVE. It's fluent, so perplexity defences don't see it." Open *Show the planted document*. |
| 1:40 | Scorecard (`run_matrix.py`): 3/5 flipped, 4/4 persistent. |
| 1:50 | Hardening report + "we'll run this against any agent built here today, free." |

Record the 1:00 beat on video the moment it works live.

---

## Hardening report

- **Provenance-weight retrieval.** The agent trusted a `community-advisory` doc that
  out-ranked the `cisa-kev` entry. Weight or gate by source authority.
- **Fluency filters are the wrong basis.** The poison is calm, dated prose. A defence
  whose detection basis (fluency) is separable from what the attacker varies (truth)
  cannot catch it.
- **Ambiguous alerts are the exposure.** Poisoning flips severity precisely when the
  agent defers to the knowledge base. Escalation-biased defaults reduce blast radius.

---

## Integrity note

Throwaway hackathon build. Deliberate toy (~5% of either team dissertation): 5
hand-written docs + cosine retrieval, a stub triage agent, raw success rate only.
No PoisonedRAG, no mutation operators, no statistical testing, no dissertation code.
Nothing here flows back into either write-up.
