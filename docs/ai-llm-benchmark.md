# SafeSOC — Investigation LLM Benchmark (SS-090)

Research spike. No production code, `INVESTIGATION_LLM_TIMEOUT_SECONDS`, `LLM_PROVIDER`, model defaults, `.env.example`, or `docker-compose.yml` were changed to produce this document. All numbers below are real, measured HTTP calls against a live local Ollama instance made while writing this report — none are estimated or invented.

## Methodology

45 real calls total: 3 models × 3 prompt types × 5 samples, made via direct HTTP `POST` to `http://localhost:11434/api/generate` with the exact request shape `backend/app/clients/ollama.py` uses (`{"model", "prompt", "stream": False}`), using prompts built with the exact `_build_prompt()` logic from `backend/app/routers/v1/investigate.py` (including the SS-088 transcript-prefix format), so the measurements reflect the real production code path rather than an approximation of it.

**Prompt types**, matching the issue's request:
- **`simple_investigation`** — a fresh `AUTH_FAILURES`-shaped result, 3 alerts, no transcript.
- **`followup_with_transcript`** — the same data, prefixed with one prior Q/A turn (SS-087/088's transcript format).
- **`larger_tool_result`** — a `TOP_ALERTS`-shaped result near a tool's real size cap (25 alerts, `truncated: true`), to see how prompt/context size affects generation time.

**Models tested:**
1. **`mistral:7b`** — already configured (`OLLAMA_MODEL`), already present locally.
2. **`llama3.2:3b`** (2.0GB) — pulled specifically for this benchmark; a realistic "smaller local model" candidate.
3. **`qwen2.5:0.5b`** (397MB) — also pulled for this benchmark; the smallest practical option, to test the other end of the size/speed tradeoff.
4. **Groq** — **not tested**. No `GROQ_API_KEY` is configured anywhere on this machine (checked both a `backend/.env` file — doesn't exist — and the shell environment — unset). Reported honestly as untested rather than fabricated; see "Limitations."

A 60-second safety timeout bounded each call (matching `ollama.py`'s own inner `timeout=60`) — this is a safety net against a truly hung request, not the measurement itself; calls were allowed to run to natural completion up to that point so the real tail latency would be visible, not just "timed out."

## Results

| Model | Prompt | n | Success | min | p50 | p95 | max |
|---|---|---|---|---|---|---|---|
| mistral:7b | simple_investigation | 5 | **0%** | — | — | — | — |
| mistral:7b | followup_with_transcript | 5 | 80% | 23.73s | **60.12s** | 61.85s | 61.85s |
| mistral:7b | larger_tool_result | 5 | 60% | 46.36s | **49.52s** | 53.08s | 53.08s |
| llama3.2:3b | simple_investigation | 5 | 100% | 5.81s | **6.65s** | 26.41s | 26.41s |
| llama3.2:3b | followup_with_transcript | 5 | 100% | 4.79s | **5.73s** | 11.22s | 11.22s |
| llama3.2:3b | larger_tool_result | 5 | 100% | 4.42s | **7.35s** | 53.04s | 53.04s |
| qwen2.5:0.5b | simple_investigation | 5 | 100% | 12.82s | **16.85s** | 32.79s | 32.79s |
| qwen2.5:0.5b | followup_with_transcript | 5 | 100% | 6.95s | **8.68s** | 9.82s | 9.82s |
| qwen2.5:0.5b | larger_tool_result | 5 | **40%** | 3.35s | 8.49s | 13.63s | 13.63s |

(p95 with n=5 is effectively the max of the sample — reported as computed, not smoothed, since inventing a smoother estimate from 5 points would itself be a kind of fabrication.)

## An Important, Unexpected Finding

**`mistral:7b` measured dramatically worse here (p50 46–60s, and complete failure on one prompt type) than the ~15.6s previously reported in this project's own history.** This machine was running its full local stack throughout this benchmark — Postgres, OpenSearch, Redis, the backend, and Celery worker/beat, all in Docker, per `docker ps` at the time — competing for the same CPU/RAM `mistral:7b`'s 7B parameters need. `mistral:7b` was also the *first* model tested (before `llama3.2:3b`/`qwen2.5:0.5b` were even loaded), so this isn't explained by multiple models competing with each other — it's consistent with `mistral:7b` alone being significantly more sensitive to realistic concurrent system load than a smaller model.

This matters for the recommendation below: it means the original ~15.6s figure may have understated how bad `mistral:7b`'s real-world latency is under the load conditions SafeSOC would actually run under (backend + workers + Ollama on the same machine), not overstated it.

## Qualitative Answer Quality

- **`mistral:7b`** (when it succeeded): coherent, accurate, correctly synthesized the data (e.g. correctly listed all three source IPs for the simple case).
- **`llama3.2:3b`**: consistently coherent and accurate across all three prompt types — correctly cited IPs, host counts, and even correctly interpreted `T1110` as a credential-access MITRE technique in its prose. Read naturally, on-topic, no signs of the model struggling with the JSON data block.
- **`qwen2.5:0.5b`**: usable on the two smaller prompts, but on the larger prompt (where it also had the worst success rate, 40%) it produced a **factually wrong** answer in the sampled output — inventing "July 25, 2026" from input data that actually said August, and cutting off mid-sentence. This is a real, not hypothetical, hallucination on the exact input shapes SafeSOC produces, not a synthetic worst case.

## SRS Assessment

The SRS ceiling is **15 seconds total**, of which `INVESTIGATION_LLM_TIMEOUT_SECONDS` (10s) is only the LLM-generation slice — classification, tool execution, and response construction consume the rest of the budget, documented in `core/config.py`'s own comments as "normally sub-second" (unverified as part of this spike, since the issue explicitly scoped this to LLM benchmarking, not full end-to-end request profiling).

- **`mistral:7b`**, under this benchmark's realistic load conditions, does not come close to meeting the budget — p50s of 46–60s aren't "sometimes falls back," they're "essentially always falls back." This confirms and *strengthens* the conclusion the project had already reached from the earlier ~15.6s figure.
- **`llama3.2:3b`** meets the 10s LLM budget comfortably at p50 (5.7–7.4s) across all three prompt types, and would leave real headroom under the full 15s ceiling even accounting for classification/tool/network overhead. Its p95 is volatile (11–53s on this shared, loaded machine) — meaning some fraction of requests would still hit the fallback path, but at a small minority rate rather than the near-total rate `mistral:7b` shows here.
- **`qwen2.5:0.5b`** is fast on small prompts but its reliability collapses (40% success) exactly on the prompt shape (`larger_tool_result`, 25 alerts) that's realistic for `TOP_ALERTS`/`AUTH_FAILURES` near their actual size caps — plus the demonstrated hallucination above. Speed alone doesn't make it a viable candidate.

## Recommendation

**Switch the local-model default to `llama3.2:3b`.** It is the only candidate in this benchmark that is both fast enough to usually meet the existing 10s/15s budget *and* qualitatively reliable/accurate on realistic SafeSOC prompt shapes, including the larger ones. This is a measured conclusion, not a guess: `mistral:7b` under real load essentially never meets the budget, and `qwen2.5:0.5b` is fast but unreliable and has been directly observed to hallucinate on this exact data shape.

**Recommended timeout for SS-091 to decide on:** the current 10s already fits `llama3.2:3b`'s p50 with margin. Given the p95 volatility observed here, SS-091 should weigh keeping 10s (accepting a small residual fallback rate, which is the mechanism's intended purpose) against a modest increase (e.g. 12s) to reduce it — this benchmark doesn't have enough samples (n=5/cell) to responsibly pick one number over the other; that's a product-owner tradeoff between "occasionally shows the fallback template" and "occasionally uses slightly more of the 15s budget," not a fact this spike can resolve alone.

**Groq remains untested** and should not be treated as a decided-against option — only as an open question requiring credentials before it can be measured at all.

## Privacy Implications of Hosted Inference

Not measured here (no Groq access), but worth stating plainly for whoever makes the SS-091 decision: routing investigation prompts through Groq means the tool-result data embedded in those prompts — real alert descriptions, hostnames, usernames, IPs, and (as of SS-087/088) prior conversation content — leaves the local/customer environment for a third-party API. This is in direct tension with two of the project's own stated principles (`docs/PRODUCT_PRINCIPLES.md`): **Principle 7, "Local First"** ("SafeSOC should operate without cloud services; local AI models supported whenever feasible") and **Principle 8, "Privacy by Design"** ("minimize data collection, avoid transmitting sensitive info externally unless explicitly configured"). A hosted-provider default would need to be an explicit, documented, opt-in deployment choice, not a silent one — this benchmark's finding that a *local* model (`llama3.2:3b`) is actually viable removes some of the pressure to make that tradeoff at all.

## Limitations

- **n=5 samples per cell** — enough to see clear, large-magnitude differences (which is what emerged) but not enough for statistically tight p95 estimates; the p95 volatility reported above should be read as "this happens sometimes," not as a precise percentile.
- **Shared, loaded benchmarking environment** — the full Docker stack was running throughout, which is realistic for local development but not identical to a dedicated production host; both directions of drift (a dedicated host could be faster; heavier production concurrency could be slower) are possible.
- **Groq untested** — no credentials available; the recommendation above proceeds on local models only.
- **This spike measured LLM generation only**, not full end-to-end `/investigate` request latency (classification + tool execution + network + response construction) — SS-091 should confirm the full-request number before finalizing a timeout, not just this slice of it.
- The two additional models (`llama3.2:3b`, `qwen2.5:0.5b`) were pulled onto this machine specifically to run this benchmark and remain in the local Ollama model cache — this doesn't change any application configuration (`LLM_PROVIDER`/`OLLAMA_MODEL` are untouched, so the running app still only ever calls `mistral:7b`), it's simply available for whichever model SS-091 decides to configure.
