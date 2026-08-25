# SafeSOC — Investigation LLM Latency Diagnosis (post-SS-091)

Follow-up to `docs/ai-llm-benchmark.md` (SS-090). After switching the local default to `llama3.2:3b` and verifying it live, a real browser investigation request still logged `"LLM answer generation timed out"` and fell back to the templated summary. This document diagnoses why, with measured evidence, and describes the fix implemented (not yet committed at the time of writing).

## Diagnosis

**SS-090's benchmark tested a synthetic payload (3–25 alerts, a few KB) that does not represent this project's real accumulated data.** A real query against this session's actual demo tenant data returns dramatically more:

| Query | Real total matches | Returned (tool's own cap) | Serialized size |
|---|---|---|---|
| `AUTH_FAILURES`, no host filter, 30-day window | 765 | 100 | **92,716 chars / 2,050 tokens** |
| `TOP_ALERTS`, 30-day window | 2,385 | 20 | 18,751 chars |

Each raw alert dict carries all 32 `NormalizedLog` fields (`~943 chars/alert`), most of them null for a given event — not driven by one oversized field (`raw_log` was small in this data), just breadth of schema × up to 100 items.

**Ollama's own timing breakdown** (`prompt_eval_duration`/`eval_duration` from `/api/generate`'s response) for this real payload, uncapped:

```
wall=19.29s = prompt_eval=7.95s (2050 input tokens) + eval=8.68s (358 output tokens) + ~2.6s other overhead
```

Two independent, additive causes:

1. **`clients/ollama.py` set no output-token limit at all** (`options` was never sent). Ollama defaults to unbounded generation. Measured output length varied 100–364 tokens across otherwise-similar calls with no cap — unpredictable, and often well past what "concise" actually requires.
2. **The prompt embeds the entire raw tool-result JSON**, including all fields of every returned alert (up to 100), regardless of what's needed to answer the question.

A note on methodology: an early pass showed suspiciously fast "cached" prompt-eval times (0.08–0.27s) for prompts that repeated exact content from an immediately preceding call — an Ollama/llama.cpp caching effect, not representative of real traffic where each query's data differs. All numbers reported below use **fresh, distinct queries per measurement** to avoid this confound.

## Fix (implemented, not yet committed)

Two small, independent, additive changes — no evidence sanitization, no fencing removed, no timeout changed:

1. **`INVESTIGATION_LLM_MAX_OUTPUT_TOKENS = 120`** (new setting, `core/config.py`), sent as `options.num_predict` to Ollama and `max_tokens` to Groq (parity between providers). 120 was chosen empirically as the largest value that stayed reliably under budget across repeated real-data tests — 180 measured as high as 10.12s on this hardware.
2. **`_prompt_data()`** in `investigate.py`: replaces a raw `alerts`/`recent_alerts` list — the only large field in any tool output — with aggregate counts (`top_hosts`, `top_users`, `severity_breakdown`, computed from the same up-to-100-item sample the tool already returns) plus a small 8-item sample of trimmed alert dicts. Every other field passes through unchanged. **`InvestigateResponse.data` is built separately from the untouched `tool_result` and is completely unaffected** — the evidence panel shows exactly what it shows today.

The existing `_answer_appears_grounded()` sanity check (SS-093) was updated to validate against `_prompt_data()`'s output (what the model actually saw) rather than the full raw dump — otherwise a correctly-grounded aggregate count like "23" (present in the summary, not present verbatim in the raw per-alert data) would have been flagged as a false-positive fabrication.

## Measured Result

Real 765-failed-login dataset, fresh distinct questions per call, real summarizer + `num_predict=120`:

| # | Wall time | Prompt tokens | Output tokens |
|---|---|---|---|
| 1 | 8.52s | 932 | 100 |
| 2 | 8.18s | 930 | 100 |
| 3 | 7.96s | 933 | 100 |
| 4 | 6.99s | 930 | 56 |
| 5 | 7.40s | 931 | 74 |
| 6 | 8.84s | — | 120 |
| 7 | 8.56s | — | 120 |
| 8 | 7.98s | — | 100 |

Prompt size: **92,716 → ~2,150 chars (43x smaller)**, tokens **2,050 → ~930 (2.2x smaller)**.

**End-to-end, through the real running backend** (not a script — actual `POST /api/v1/investigate` against the live demo tenant, after the fix): 5 consecutive real requests classified to a real intent (`auth_failures`/`top_alerts`) all returned `is_fallback: false` with genuine, grounded LLM prose, at **3.3s–5.9s** wall time each.

## Residual, Known Limitation

The very first request after Ollama's model had gone idle (its keep-alive window elapsed) still timed out at 10.26s and correctly fell back — a one-time cold-start cost (model reload), not a per-request problem; every subsequent warm-state call succeeded well within budget. This is a real, honestly-reported limitation, not solved by this fix, and not in scope for it (it's an Ollama-side deployment/keep-alive configuration question, not an application latency question). Worth a separate decision if it matters in practice — during active analyst usage the model should stay warm.

## What This Does Not Change

- `INVESTIGATION_LLM_TIMEOUT_SECONDS` — untouched, still 10.
- `LLM_PROVIDER`/`OLLAMA_MODEL` — untouched, still `ollama`/`llama3.2:3b` per SS-091.
- SS-093's prompt fencing (`<<<UNTRUSTED_DATA_START/END>>>`, the anti-injection instruction) — untouched, still wraps the (now-summarized) data.
- `InvestigateResponse.data` / the evidence panel — untouched, still the complete, unsummarized tool result.
- No cloud provider introduced.
