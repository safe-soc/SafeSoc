# SafeSOC — Final Research Direction

**Prepared:** 2026-09-08
**Status:** Research direction DECIDED. Hand this to the implementing developer.
**Supersedes:** the "rule-based correlation vs Isolation Forest" comparative study in
`SafeSOC_Research_and_Implementation_Plan.md` §5, and the five-candidate ranking in §24.3.

---

## 0. Executive summary

The previously planned direction (B0/B1/B2 comparative evaluation) and all five §24.3
"strongest candidates" were re-examined against the actual repository and against
current literature. **All six are rejected or downgraded.** The recommended direction is
new, was not in the plan, and was found by inspecting the code rather than the document:

> **Multi-step correlation rules that require events in a specific order are fragile to
> perturbations in observed event order — and SOC pipelines routinely perturb it. We
> quantify how much detection is lost, show the loss is non-deterministic, and identify
> which rule structures are immune.**

It is recommended because it maximises the stated objective — *probability of
first-attempt publication divided by total additional work* — not because it is the most
ambitious idea available.

**Why it wins:** the core experiment is a deterministic offline function test over
already-written detectors. It needs no database, no Docker, no external dataset, no LLM,
no API keys, no human subjects, and no new ML. The mechanism is already present and
verified in the repository. Estimated implementation: **2–4 days**; full experiment:
**1–2 days**.

---

## 1. Repository re-inspection: what the plan got wrong

I verified the plan's technical claims against the code. Four are wrong or outdated, and
one major finding was missed entirely.

| Plan claim | Reality | Evidence |
|---|---|---|
| "IForest is not active by default" | **Wrong.** It is wired and live. `tasks/enrichment.py::_score_anomaly()` calls `services/anomaly.py::score_alert()` on every ingested alert and persists `anomaly_score`. | `app/tasks/enrichment.py:40,57` |
| "The IForest artifact is absent from the repository" | **Half right, and worse than described.** `ml/model/isolation_forest.pkl` (2.9 MB) exists *on this machine* but `ml/model/` is **gitignored**. A clean checkout silently has no model, and `_load_model()` returns `None` → scoring silently no-ops. | `.gitignore:41`; `app/services/anomaly.py:90-107` |
| "z-score … is currently unwired" | **Correct.** `detect_network_volume_spike()` / `check_network_volume_spike()` have **zero callers** outside their own module. Dead code. | grep across `app/` |
| "733+ collected tests" | **Outdated.** 1372 backend tests pass locally; 1347 pass in the Docker overlay. | Phase 4.7 runs |
| *(not mentioned)* | **The correlation window is ordered by processing time, not event time.** | See §2 |

Also worth knowing before anyone opens the repo:

- **`ti_cache` is globally shared across tenants.** It is the only application table with
  no tenant scoping at all (every other table either carries `tenant_id` or transits an
  already-tenant-verified `Incident`). Relevant to the rejected cross-tenant angle (§3.1).
- **Phase 4.8 is mid-edit and uncommitted.** `benchmarks/settlement.py` is new and
  `runner.py`/`probes.py`/`__main__.py` are refactored onto it, but `report.py`'s edit
  aborted on a `UnicodeDecodeError` and `backend/tests/test_benchmark_runner.py` still
  references the removed `runner._runs_settled`. **The benchmark suite will not run
  clean until that is finished.** It is unrelated to this research direction but must be
  resolved or reverted before benchmark reuse.

---

## 2. The finding this direction is built on

`workers/correlation_worker.py` pushes each alert into its host's Redis sliding window:

```python
await add_event(tenant_id, host_id, {"alert_id": ..., "action": ..., ...})
```

`services/correlation.py::add_event()` accepts an optional `timestamp` used as the
sorted-set score, and **defaults it to `time.time()`** when omitted. The worker omits it.
The alert's real `timestamp` is present in `doc` and is never used.

**Consequence:** window order = the order Celery happened to process the alerts, not the
order the events occurred. Each alert is a separate Celery task across a prefork pool, so
under concurrent ingestion the order is effectively scheduler-determined.

Four of the six detectors are **order-sensitive** — they require one event to appear
*before* another in window order:

| Detector | Structure | Order-sensitive? |
|---|---|---|
| `detect_credential_brute_force` | counts `failed_login` ≥ 5 | No |
| `detect_data_exfiltration` | counts `outbound_connection` ≥ 10 | No |
| `detect_successful_compromise` | ≥5 `failed_login` **before** a `login_success` | **Yes** |
| `detect_recon_to_exploitation` | ≥3 `network` **before** a `process` event | **Yes** |
| `detect_privilege_escalation` | `login_success` **then** a `privilege` event | **Yes** |
| `detect_lateral_movement` | `login_success` **then** a private-destination connection | **Yes** |

This gives a **built-in control group**: the two count-based detectors must show exactly
zero sensitivity to order. If they move, the experiment is broken. That internal control
is worth a great deal to a reviewer.

**Critically, this is not merely a SafeSOC bug.** Order perturbation also arises from
causes no implementation can eliminate: clock skew between hosts, late arrival past a
watermark, batch uploads, and ties. Industry guidance states plainly that "a few minutes
of skew is enough to change the apparent sequence of logins, configuration changes,
alerts and containment steps." The paper is framed around **order perturbation as a
general condition**, with processing-time windowing as its most extreme instance.

---

## 3. Why the five prior candidates were rejected

Searches spanned arXiv, ACM DL, IEEE, Wiley, Springer, Elsevier, NDSS, and practitioner
sources. **"Not found" was never treated as proof of novelty** — each rejection below
names the specific work or the specific structural weakness that kills it.

### 3.1 Cross-tenant isolation in SOC analytics — REJECTED (prior-art saturated)

The plan rated this #1 on the basis that multi-tenant isolation SoKs cover FPGAs/VMs but
not SOC analytics. That framing does not survive contact with the mechanism.

The concrete leak SafeSOC actually offers is the globally shared `ti_cache`: tenant A can
infer that tenant B looked up indicator X, via cache-hit timing or row existence. **That
is a shared-cache timing side channel, and it is one of the most saturated attack classes
in security.** Multi-tenant KV-cache timing attacks on LLM inference alone produced
PROMPTPEEK, EarlyBird, InputSnatch, SafeKV and KVGov (arXiv:2508.08438, arXiv:2608.09225,
NDSS 2025), on top of a decade of cloud cache side-channel work. The mechanism is
identical; only the cached object differs. A reviewer will call it DNS cache snooping
applied to VirusTotal results.

The pooled-ML-model variant fares no better: federated anomaly detection for multi-tenant
clouds (arXiv:2508.10255) already frames and *solves* cross-tenant privacy in shared
anomaly models, so our contribution would be measuring the harm its solution already
assumes.

**Irreducible difference: none that survives review.**

### 3.2 Synthetic→real generalization gap — REJECTED (cost, not novelty)

The gap is real and the novelty argument holds up better than the others. It fails on
**effort and risk**: it requires sourcing a public multi-step host-log dataset and
writing a `NormalizedLog` adapter. The plan's own §10 S5 says to abandon this if the
adapter exceeds 1–2 days — and an adapter for multi-step host telemetry with the
`action`/`log_type` vocabulary SafeSOC's detectors need is very likely to exceed that.
The result would also be a single-dataset study, which invites "weak external validity"
on its own. **Kept as a possible strengthening experiment, not the core.**

### 3.3 Evasion of rule-based multi-step correlators — REJECTED (obvious result + prior art)

The plan claims arXiv is "empty" here. **That is incorrect.** StealthCup
(arXiv:2511.17761) is a realistic, multi-stage, *evasion-focused* IDS benchmark;
arXiv:2306.05494 argues evasion attacks on ML NIDS are impractical; kill-chain state
machines (arXiv:2103.14628) cover the detection side.

The fatal problem is not prior art but **triviality**: the finding ("send 4 failed logins
instead of 5, or space them past the window") is derivable by reading the rule. Practitioner
material already states it flatly. A reviewer can predict every number in the results
table before reading it.

### 3.4 Incident merge/dedup characterization — REJECTED as a headline (retained as a minor result)

Genuinely under-measured, genuinely cheap, and genuinely too narrow to carry a paper. The
plan's own assessment agrees. It is an engineering characterization of one function.

### 3.5 Threat-intel feed disagreement — REJECTED (saturated + operationally blocked)

VirusTotal label noise is thoroughly established (arXiv:2210.15973; Maat arXiv:2007.00510;
MISP scoring arXiv:1902.03914). The remaining sliver — two-feed agreement plus propagation
into one scoring pipeline — is bounded.

**Additionally it is currently impossible to run here:** both providers return `401
Unauthorized` in this environment (observed repeatedly throughout Phase 4.6/4.7 load
testing). The study needs paid/valid API keys and a live indicator corpus.

---

## 4. Strict novelty test for the selected direction

> **"If I were a reviewer, what exact paper could I cite to say this has already been done?"**

The four closest candidates, and the irreducible difference in each case:

| Closest prior work | What it does | Irreducible difference |
|---|---|---|
| Apache Flink / Confluent event-time & watermark literature; out-of-order CEP | Defines event-time vs processing-time and solves out-of-order windowing **for correctness of aggregation** | Solves the mechanism generically; never measures **security detection outcomes**. No detection rate, no missed-attack count, no per-rule fragility. Our dependent variable does not appear in that literature. |
| *On the Reproducibility of Provenance-based Intrusion Detection that uses Deep Learning* (ACM REP 2025, 10.1145/3736731.3746140) | Reproducibility of provenance IDS | Concerns **ML training** reproducibility — seeds, configs, missing artifacts. Ours concerns **input-ordering** nondeterminism in rule evaluation, which is orthogonal and affects non-ML detectors. |
| Shaukat et al., *Event Log Correlation for Multi-Step Attack Detection* (Wiley S&P, 2026, 10.1002/spy2.70151) | Survey of five correlation families | A survey. Notes ordered vs unordered correlation exists as a **design choice**; does not measure the consequence of order perturbation on either. |
| Digital-forensics timestamp work (DFRWS; SoK arXiv:2504.18131) | Clock skew and timestamp interpretation for **forensic timeline reconstruction** | Optimises a timeline for a **human investigator after the fact**. Never asks whether an **automated detection rule fires**. Different dependent variable, different consumer. |

**None of the disqualified arguments are used.** The claim is not "we implement it
differently", "we use SafeSOC", or "we target SMEs". The claim is that a specific
dependent variable — *whether an order-sensitive correlation rule fires, as a function of
event-order perturbation* — has not been measured, in a setting where the perturbation is
known to occur and the rule class is standardised.

**External validity anchor (this is what makes it more than one system's bug):** Sigma,
the de-facto open detection-rule standard, formally separates order-invariant correlation
(`event_count`, `value_count`, `temporal`) from order-sensitive correlation
(`temporal_ordered`). SafeSOC's six detectors map exactly onto that split, 2 to 4. The
Sigma specification even warns that unordered relationships "could cause false positives
by differently ordered events" — the concern is acknowledged in the standard and
unquantified in the literature. Any finding about `temporal_ordered` fragility transfers
to every Sigma-compatible SIEM.

⚠️ **Verify before submission.** These searches were broad but not exhaustive, and "not
found" is not proof. Re-run the prior-art search immediately before submitting, with
particular attention to: stream-processing venues (DEBS, VLDB) for out-of-order + detection;
RAID/DIMVA/ESORICS for correlation robustness; and any 2026–2027 Sigma-correlation papers.

---

## 5. Candidate scoring

Scale: Very Low / Low / Medium / High / Very High.

| Criterion | **Order-sensitivity (SELECTED)** | Cross-tenant | Synthetic→real | Evasion | Merge/dedup | TI feeds |
|---|---|---|---|---|---|---|
| Novelty potential | **Medium-High** | Medium | Medium-High | Low-Medium | Low | Low-Medium |
| Prior-art risk | **Low-Medium** | **Very High** | Low-Medium | High | Medium | **Very High** |
| Engineering effort | **Very Low** | Medium | Medium | Low | Low | Low |
| Experiment effort | **Low** | Medium | Medium-High | Low | Low | Medium |
| Data difficulty | **Very Low** | Low | **High** | Low | Low | **High** (keys) |
| Reproducibility | **Very High** | Medium | Medium | High | High | Low |
| Reviewer rejection risk | **Medium** | High | Medium-High | **Very High** | High | High |
| First-attempt acceptance | **Medium-High** | Low | Medium | Low | Low | Low |
| SafeSOC reuse | **Very High** | High | High | High | High | Medium |
| Human subjects | **None** | None | None | None | None | None |
| External compute/API cost | **None** | None | Low | None | None | **High** |
| Proprietary data | **None** | None | None | None | None | Low |
| Time to paper-ready results | **~1 week** | 3–4 weeks | 4–6 weeks | 1–2 weeks | ~1 week | 3+ weeks |

**Ranking by (first-attempt publication probability × defensibility) ÷ effort:**
1. **Order-sensitivity of multi-step correlation** ← selected
2. Synthetic→real gap (viable but 4–6× the work, dataset risk)
3. Merge/dedup (too small alone; folded in as a secondary result)
4. Evasion (result too obvious)
5. Cross-tenant (prior art fatal)
6. TI feeds (prior art fatal + cannot run without keys)

---

## 6. Missing research infrastructure

Issues that would invalidate the experiment if left unaddressed.

| # | Issue | Why it matters | Must fix? | Minimum fix | Effort |
|---|---|---|---|---|---|
| 1 | Worker ignores event timestamps | This *is* the object of study, but the event-time condition must also be runnable to form the comparison arm | **Yes** | Pass `timestamp=doc["timestamp"].timestamp()` to `add_event()` behind a config flag, default preserving current behaviour | 1 hour |
| 2 | Benchmark circularity | Injector scenarios were built to satisfy these detectors; measuring them on their own scenarios is circular for *detection rate* | **Yes** | Order-perturbation is a *within-scenario* manipulation — each scenario is its own control, so circularity does not affect the dependent variable. State this explicitly in the paper | 0 (argument, not code) |
| 3 | Phase 4.8 left mid-edit | Benchmark suite will not run clean | **Yes** (if reusing benchmarks/) | Finish or revert the Phase 4.8 settlement refactor | 2–4 hours |
| 4 | `ml/model/` gitignored | Any IForest result is unreproducible from a clean checkout | Only if IForest is used | Not needed for the selected direction — IForest is **out of scope** | 0 |
| 5 | No seeded event-order generator | Permutations must be deterministic and reported | **Yes** | Seeded permutation helper in the benchmark package | 2 hours |
| 6 | Detection is measured through Redis in live mode | Redis state leaks between runs and adds nondeterminism unrelated to the hypothesis | **Yes** for live mode | Unique host id per run (already the established pattern) + flush window keys between runs | 1 hour |
| 7 | Wall-clock dependence | `add_event` defaults to `time.time()`; tests must not depend on real time | **Yes** | `add_event` already accepts an explicit `timestamp` — use it | 0 (already supported) |

**Nothing here requires new models, new endpoints, new migrations, or schema changes.**

---

## 7. Mock peer review of the top 3

Written pessimistically, as instructed.

### 7.1 Order-sensitivity of multi-step correlation — **WEAK ACCEPT**

*Decisive reason:* the experiment is unusually clean for this class of work — a within-subject
manipulation with an internal control group (the two count-based detectors must show a
null effect), fully deterministic and seeded, on rule structures that map onto a public
standard (Sigma). The finding is not derivable by inspection: everyone expects ordered
rules to depend on order, but nobody has published *how much* detection is lost at a given
perturbation level, nor that the loss manifests as **run-to-run nondeterminism**, which is
a measurement-validity problem for every benchmark run on such a pipeline.

*Residual risk that keeps it off "Accept":* a reviewer who believes mature SIEMs already
sort by event time may see the processing-time condition as a straw man. **This is the
objection to defend against (§8.9).**

### 7.2 Synthetic→real generalization gap — **BORDERLINE**

*Decisive reason:* the contribution is real and needed, but a single public dataset yields
a single number, and the reviewer's first question — "does the gap generalise beyond this
one dataset and one system?" — has no good answer at this scale. Also 4–6 weeks of work
with dataset-adapter risk at the front.

### 7.3 Cross-tenant isolation in SOC analytics — **REJECT**

*Decisive reason:* the mechanism is a shared-cache timing side channel. That class is
extremely well covered, most recently and most visibly in multi-tenant LLM KV-cache
attacks. Changing the cached object from a prompt prefix to a VirusTotal verdict is not a
research contribution. Reviewers with side-channel background will reject on sight.

---

## 8. THE FINAL RESEARCH DIRECTION

### 8.1 Research question

> **How sensitive are multi-step attack-correlation rules to perturbations in observed
> event order, and which rule structures remain reliable when a SOC pipeline delivers
> events out of the order in which they occurred?**

### 8.2 Hypotheses (falsifiable)

- **H1** — Order-invariant detectors (`event_count`-shaped: brute force, data
  exfiltration) show **no** change in detection rate under any order perturbation.
  *Falsified if their detection rate moves at all.* This is the control.
- **H2** — Order-sensitive detectors (`temporal_ordered`-shaped: successful compromise,
  recon→exploitation, privilege escalation, lateral movement) lose detection
  monotonically as order perturbation increases.
- **H3** — Under concurrent ingestion with processing-time windowing, the **same attack
  produces different verdicts across repeated identical runs** (non-zero run-to-run
  variance in detection).
- **H4** — Switching the window to event-time ordering restores order-sensitive detection
  to the order-invariant baseline, eliminating the variance in H3.
- **H5** *(secondary)* — Fragility scales with the number of ordering constraints and the
  separation between constrained events, so detectors requiring a long prefix (≥5 failed
  logins before a success) degrade faster than those requiring a single precedence.

Report results that contradict these. **Do not tune the experiment to produce them.**

### 8.3 Contribution

1. An **order-sensitivity taxonomy** of multi-step correlation rules, aligned to the Sigma
   correlation specification, that lets any practitioner classify their own rules.
2. The first **quantitative measurement** of detection loss as a function of event-order
   perturbation, per rule structure, with an internal null-effect control.
3. Demonstration that ordering-induced loss appears as **run-to-run nondeterminism** in an
   asynchronous pipeline — a validity threat to any detection benchmark measured on one.
4. A measured **remediation**: event-time windowing, with before/after numbers.
5. A **seeded, reproducible harness** that others can run against their own detectors.

### 8.4 What must NOT be claimed

- Not a novel detection algorithm.
- Not that out-of-order processing is a new discovery (it is textbook in stream processing).
- Not that real SOCs are broken — only that this rule class is fragile under a condition
  that demonstrably occurs.
- Not real-world generalisation from synthetic telemetry.
- Not statistical significance beyond what the seed count supports.

### 8.5 Required SafeSOC modifications (exhaustive)

| # | File | Change | Constraint |
|---|---|---|---|
| M1 | `backend/app/services/correlation.py` | Expose `window_minutes` and detector thresholds as parameters | Defaults byte-identical to today |
| M2 | `backend/app/workers/correlation_worker.py` | Optionally pass the alert's own timestamp to `add_event()` | Behind a setting, **default = current behaviour** |
| M3 | `backend/app/core/config.py` | One setting, e.g. `CORRELATION_USE_EVENT_TIME: bool = False` | Default False preserves production behaviour |
| M4 | `benchmark/` (new) | Generator, permutation harness, metrics, plots | No application code |

That is the complete list. **No migrations. No schema changes. No new endpoints. No new
workers. No SOAR changes. No frontend.**

### 8.6 Minimum publishable experiment

**Offline, deterministic, no infrastructure.** Call the six real detector functions
directly with permuted event sequences.

1. Generate scenario event sequences (reuse `injector/injector.py`'s six scenarios plus
   held-out variants).
2. For perturbation level *p* ∈ {0.0, 0.1, 0.25, 0.5, 0.75, 1.0}, where *p* is the
   fraction of adjacent-pair swaps applied (or displacement drawn from a skew
   distribution), generate *N* permutations per scenario per seed.
3. Run all six detectors on each permuted sequence.
4. Record: detection rate per detector per *p*; confidence when detected; variance across
   permutations.
5. Seeds: ≥5. Report mean ± SD, and 95% CI for headline numbers.

**Expected core figure:** detection rate vs perturbation level, six lines, two of them
flat at 1.0 (the control).

### 8.7 High-ROI strengthening experiments

Ranked by acceptance benefit per unit effort.

- **S1 — Sigma rule survey (highest ROI, ~half a day).** Classify a sample of public
  SigmaHQ correlation rules as order-invariant vs `temporal_ordered`. Reporting "X% of
  public multi-event Sigma rules are order-sensitive and therefore in the fragile class"
  converts a single-system result into a statement about the ecosystem. **Do this one.**
- **S2 — Live end-to-end nondeterminism (~1 day).** Inject the same scenario *K* times at
  a fixed concurrency through the real Docker pipeline; report the distribution of
  detection outcomes. This is the H3 evidence and the most striking result in the paper.
  SafeSOC's benchmark harness already does injection and polling.
- **S3 — Event-time fix ablation (~2 hours).** Re-run S2 with `CORRELATION_USE_EVENT_TIME=True`.
  Before/after in one table. This is H4.
- **S4 — Clock-skew parameterisation (~half a day).** Instead of abstract swap counts,
  express perturbation as seconds of inter-host clock skew, so the x-axis is operationally
  meaningful ("at 30s of skew you lose Y% of lateral-movement detections").
- **S5 — Merge/dedup side result (~half a day).** Whether ordering perturbation also
  changes incident *aggregation* (§3.4 folded in here rather than as its own paper).

**Do S1 and S3 at minimum.** S2 and S4 substantially strengthen it.

### 8.8 Metrics

Per detector, per perturbation level, per seed: detection rate; false negatives introduced
by perturbation; run-to-run variance / entropy of the verdict; detection confidence
distribution; and (live mode only) end-to-end detection latency. Aggregate: mean ± SD
across seeds, 95% CI on headline numbers. **Accuracy alone is not reported.**

### 8.9 Main reviewer objection, and the defense

> *"Well-engineered SIEMs sort by event time. You are measuring a bug in your own system."*

This is the objection most likely to cause rejection. Three-part defense, all cheap:

1. **Reframe the independent variable.** The study is about *observed order perturbation*,
   not about one implementation's windowing choice. Processing-time windowing is the
   extreme case; **clock skew and late arrival perturb order even with correct event-time
   windowing**, and both are ubiquitous. S4 makes this concrete by expressing the x-axis in
   seconds of skew.
2. **Show the rule class is standard, not homegrown.** S1's Sigma survey demonstrates that
   order-sensitive correlation is a first-class construct in the dominant open rule
   standard, and quantifies how much of the public corpus sits in the fragile class.
3. **Include the fix and its measurement.** A paper that identifies a fragility, measures
   it, applies the standard remedy, and measures the remedy is an engineering-science
   contribution — not a bug report.

---

## 9. Does this replace the existing paper plan?

**Yes — explicitly.** The B0/B1/B2 comparative study (§5 of the plan) should be dropped.

Reasons: the plan's own §4 concedes that rule correlation, Isolation Forest, and risk
scoring are all established, so the comparative study's contribution rests entirely on
the benchmark being novel — which §24.3 then rates as "partially invalidated" by S-DAPT
and existing log-dataset work. It also depends on the IForest path, which needs a
gitignored artifact regenerated to be reproducible at all (§1). The comparison would
answer a question whose expected answer ("rules catch what they encode; IForest is noisier")
is already the field's default assumption.

The selected direction reuses more of SafeSOC, needs less new work, and asks a question
whose answer is not already assumed.

---

## 10. Publication venues

Hard constraint: **no physical travel outside Bengaluru.** Verified against current sources
on 2026-09-08.

**Timing note that drives the ladder:** IEEE CONECCT 2026 was held 2–5 July 2026 in
Bengaluru and has passed. CONECCT 2027 is not yet announced (CFPs historically open around
December–January). So the only near-term routes are journals.

| Rank | Venue | Publisher | Travel | Fit | Notes / what to verify |
|---|---|---|---|---|---|
| 1 | **SECURITY AND PRIVACY** | Wiley | None (journal) | **Strongest** — published Shaukat's multi-step correlation survey (2026, `10.1002/spy2.70151`), so the editor pool knows this exact area | IF 2.9, JCR Q3. **Verify whether hybrid (free subscription route) or fully OA** — the listed OA APC is ~US$3,140, which is likely prohibitive. Do not submit before confirming a no-fee route. |
| 2 | **SN Computer Science** | Springer | None | Good — broad CS/security, accustomed to systems-measurement papers | Verify current indexing, article type, and fees. Hybrid → confirm the no-APC option. |
| 3 | **Journal of Information Security and Applications (JISA)** | Elsevier | None | Good — applied security, empirical studies welcome | Higher bar than 1–2; verify scope and fees. |
| 4 | **IEEE CONECCT 2027** | IEEE | **Bengaluru — compliant** | Good, and IEEE Xplore indexing | Not yet announced. Watch `ieee-conecct.org` from ~December 2026. Best option if the timeline allows waiting. |
| 5 | **IEEE Access** | IEEE | None | Acceptable — fast, broad | Substantial APC; treat as a fallback, not a first choice. |

**Recommended strategy:** target **Wiley Security and Privacy** first *if and only if* a
no-fee publication route is confirmed; otherwise **SN Computer Science**. Keep **CONECCT
2027** as the Bengaluru in-person option if the schedule permits. Submit to exactly one
venue at a time.

**Do not** treat indexing as evidence of quality, and do not submit anywhere whose current
CFP and peer-review process have not been checked directly on the official site.

---

## 11. Developer specification

### MUST DO

1. **M1** — Parameterise `services/correlation.py`: `window_minutes` and detector
   thresholds as arguments/config. **Defaults must not change behaviour.** Existing tests
   must pass untouched.
2. **M2/M3** — Add `CORRELATION_USE_EVENT_TIME` (default `False`) in `core/config.py`; when
   true, `correlation_worker.py` passes the alert's own timestamp to `add_event()`.
   Default path stays byte-identical.
3. **Build `benchmark/`** (new top-level package, separate from the existing `benchmarks/`
   Phase 4 SOAR harness — do not entangle them):
   - `generator.py` — deterministic, seeded scenario sequences: the six patterns, held-out
     variants (jitter, renamed hosts, interleaved benign events), and near-miss negatives.
     No wall-clock dependence.
   - `perturb.py` — seeded order-perturbation operators: adjacent-swap fraction, and
     clock-skew displacement (for S4).
   - `harness.py` — offline mode calling the six real detectors directly; live mode
     driving the Docker stack.
   - `metrics.py` — detection rate, FN, variance/entropy, CIs.
   - `configs/experiment_matrix.yaml` — seeds, perturbation levels, repetitions.
   - `run.sh` — generate → run → metrics → figures/tables.
4. **Run the minimum experiment** (§8.6): 6 detectors × 6 perturbation levels × ≥5 seeds.
5. **Verify the control holds.** If the two count-based detectors show any sensitivity to
   order, stop — the harness is wrong, not the finding.
6. **Preserve reproducibility:** every reported number must come from a saved result file,
   regenerable from `run.sh` on a clean checkout.

### HIGH-ROI

7. **S1** — Sigma correlation-rule survey (order-invariant vs `temporal_ordered` share).
8. **S3** — Event-time ablation (H4 before/after).
9. **S2** — Live repeated-injection nondeterminism (H3).
10. **S4** — Express perturbation as seconds of clock skew.
11. Finish or revert the **Phase 4.8** settlement refactor before reusing `benchmarks/`.

### DO NOT DO

- Do not train, fix, or ship the Isolation Forest model — **IForest is out of scope**.
- Do not wire up the dead z-score `detect_network_volume_spike` path.
- Do not attempt the TI-feed study (needs paid keys; both providers 401 here).
- Do not build the cross-tenant leakage study (prior art fatal).
- Do not add migrations, endpoints, workers, SOAR changes, or frontend work.
- Do not source a public dataset unless the adapter genuinely fits in 1–2 days.
- Do not change detector defaults, thresholds, or the six rules themselves.
- Do not tune perturbation levels to produce a nicer curve.

### Definition of done

- [ ] Existing backend tests still pass (baseline: 1372 local / 1347 Docker overlay).
- [ ] Correlation window and thresholds overridable; defaults unchanged.
- [ ] `CORRELATION_USE_EVENT_TIME` works in both states; default preserves behaviour.
- [ ] Generator is deterministic and seeded; identical seed → identical events.
- [ ] Positive, held-out, benign, and near-miss cases all exist with ground truth.
- [ ] Offline harness runs all six detectors with no infrastructure.
- [ ] Control detectors show a null effect across all perturbation levels.
- [ ] Metrics, figures, and tables regenerate from saved results via `run.sh`.
- [ ] Live end-to-end validation performed at least once.
- [ ] Prior-art search re-run immediately before submission.
- [ ] One venue selected with its no-fee route confirmed.

---

## 12. Honest limitations to state in the paper

- Synthetic telemetry only; no production SOC data. No real-world generalisation claimed.
- One implementation. External validity rests on the Sigma taxonomy mapping, not on
  having tested multiple SIEMs.
- Six detectors is a small rule sample.
- Processing-time windowing is a deviation from best practice in SafeSOC; the paper must
  say so plainly rather than implying all SOC pipelines share it.
- Seed count supports descriptive statistics, not strong significance claims.

---

## 13. Sources

- [Specification: Sigma Correlations — SigmaHQ](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
- [Correlations | Sigma Detection Format](https://sigmahq.io/docs/meta/correlations.html)
- [On the Reproducibility of Provenance-based Intrusion Detection that uses Deep Learning (ACM REP 2025)](https://dl.acm.org/doi/10.1145/3736731.3746140)
- [Event Log Correlation for Multi-Step Attack Detection (Wiley Security and Privacy, 2026)](https://onlinelibrary.wiley.com/doi/full/10.1002/spy2.70151)
- [SoK: Timeline based event reconstruction for digital forensics (arXiv:2504.18131)](https://arxiv.org/html/2504.18131v1)
- [Was the clock correct? Timestamp interpretation through time anchors (DFRWS)](https://www.sciencedirect.com/science/article/pii/S2666281724000787)
- [Time and Watermarks in Confluent Cloud for Apache Flink](https://docs.confluent.io/cloud/current/flink/concepts/timely-stream-processing.html)
- [StealthCup: Realistic, Multi-Stage, Evasion-Focused CTF for Benchmarking IDS (arXiv:2511.17761)](https://arxiv.org/pdf/2511.17761)
- [Evasion Adversarial Attacks Remain Impractical Against ML-based NIDS (arXiv:2306.05494)](https://arxiv.org/html/2306.05494v5)
- [Multi-Stage Attack Detection via Kill Chain State Machines (arXiv:2103.14628)](https://arxiv.org/pdf/2103.14628)
- [Prompt Leakage via KV-Cache Sharing in Multi-Tenant LLM Serving (NDSS 2025)](https://www.ndss-symposium.org/wp-content/uploads/2025-1772-paper.pdf)
- [Governing the KV Cache: Preventing Timing Side-Channel Leakage in Multi-Tenant LLM Inference (arXiv:2608.09225)](https://arxiv.org/abs/2608.09225)
- [Federated Anomaly Detection for Multi-Tenant Cloud Platforms (arXiv:2508.10255)](https://arxiv.org/abs/2508.10255)
- [A.8.17 Clock Synchronisation — MSP Forensic Time Integrity](https://www.isms.online/managed-service-providers/a-8-17-clock-synchronisation-msp-forensic-time-integrity/)
- [Call for Papers — IEEE CONECCT 2026](https://ieee-conecct.org/cfp.php)
- [Security and Privacy — Wiley](https://www.wiley.com/en-us/journals/Security+and+Privacy-p-24756725)
- [SECURITY AND PRIVACY journal metrics](https://researcher.life/journal/security-and-privacy/34510)
