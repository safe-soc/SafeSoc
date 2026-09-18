"""
SafeSOC — Investigation Session Service Tests
Covers session creation/retrieval/continuation, tenant/incident
authorization (a session_id alone can never bypass it), structured
finding/action/note persistence, confirmed-vs-hypothesis provenance,
grounded question-answering (evidence always live, never a previous
AI answer treated as fact), and fallback behavior.

_FakeSession filters execute() results using the statement's own
compiled bound parameters (see _row_matches) rather than returning
everything unfiltered (test_incidents.py's simpler convention) — this
feature's core security property (a session_id only resolves under
its OWN incident_id) depends on the fake actually finding the RIGHT
row among several, not just "the first row of that type."
"""

import re
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from app.core.enums import FindingCategory, FindingOrigin, InvestigationActionStatus
from app.core.exceptions import IncidentNotFoundError, InvestigationActionNotFoundError, InvestigationFindingNotFoundError, InvestigationSessionNotFoundError
from app.mcp.tools import IncidentNarrativeDataOutput, TimelineEventSummary
from app.models.investigation_session import InvestigationAction, InvestigationFinding, InvestigationNote, InvestigationSession, InvestigationTurn
import app.services.investigation_session as svc


# ── Fake session ───────────────────────────────────────────────────

class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


def _row_matches(row, compiled_params: dict) -> bool:
    for param_name, param_value in compiled_params.items():
        column_name = re.sub(r"_\d+$", "", param_name)
        if hasattr(row, column_name) and getattr(row, column_name) != param_value:
            return False
    return True


class _FakeSession:
    def __init__(self, sessions=None, turns=None, findings=None, actions=None, notes=None):
        self.sessions: list[InvestigationSession] = list(sessions or [])
        self.turns: list[InvestigationTurn] = list(turns or [])
        self.findings: list[InvestigationFinding] = list(findings or [])
        self.actions: list[InvestigationAction] = list(actions or [])
        self.notes: list[InvestigationNote] = list(notes or [])
        self.added: list = []
        self.all_added: list = []
        self.commit_count = 0

    async def execute(self, stmt, params=None):
        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        compiled_params = stmt.compile().params if hasattr(stmt, "compile") else {}

        table = {
            InvestigationSession: self.sessions, InvestigationTurn: self.turns, InvestigationFinding: self.findings,
            InvestigationAction: self.actions, InvestigationNote: self.notes,
        }.get(target, [])
        return _FakeResult([row for row in table if _row_matches(row, compiled_params)])

    def add(self, obj):
        self.added.append(obj)
        self.all_added.append(obj)

    async def commit(self):
        self.commit_count += 1
        for obj in self.added:
            if obj.id is None:
                obj.id = uuid.uuid4()
            if getattr(obj, "created_at", None) is None and hasattr(obj, "created_at"):
                obj.created_at = datetime.now(timezone.utc)
            bucket = {
                InvestigationSession: self.sessions, InvestigationTurn: self.turns, InvestigationFinding: self.findings,
                InvestigationAction: self.actions, InvestigationNote: self.notes,
            }.get(type(obj))
            if bucket is not None and obj not in bucket:
                bucket.append(obj)
        self.added = []

    async def refresh(self, obj):
        pass


# ── Fixtures / helpers ───────────────────────────────────────────────

def _evidence_data(**overrides) -> IncidentNarrativeDataOutput:
    fields = {
        "incident_id": uuid.uuid4(),
        "events": [TimelineEventSummary(type="alert", timestamp="2026-08-26T09:15:42Z", data={"host_id": "DEMO-CRITICAL-01", "user": "leo.chen", "severity": "critical", "action": "privilege_escalation", "mitre_technique": "T1068", "description": "Privilege escalation detected"})],
        "hosts": [{"host_id": "DEMO-CRITICAL-01"}], "ips": [], "users": [{"user": "leo.chen"}],
        "cloud_resources": [], "mitre_techniques": ["T1068", "T1078"], "confidence": 0.95,
    }
    fields.update(overrides)
    return IncidentNarrativeDataOutput(**fields)


def _mock_get_incident(monkeypatch, raises: bool = False):
    if raises:
        mock = AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4()))
    else:
        mock = AsyncMock(return_value=Mock())
    monkeypatch.setattr(svc, "get_incident", mock)
    return mock


def _mock_live_evidence(monkeypatch, data=None):
    mock = AsyncMock(return_value=data or _evidence_data())
    monkeypatch.setattr(svc, "_live_evidence", mock)
    return mock


def _mock_audit(monkeypatch):
    monkeypatch.setattr(svc, "record_event", AsyncMock())


# ── create_session ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_session_checks_incident_authorization_first(monkeypatch):
    """AC: tenant isolation transits through get_incident — a mismatched tenant/incident must be rejected before any session row is created."""
    mock_get_incident = _mock_get_incident(monkeypatch, raises=True)
    _mock_audit(monkeypatch)
    session_db = _FakeSession()

    with pytest.raises(IncidentNotFoundError):
        await svc.create_session(session_db, uuid.uuid4(), uuid.uuid4(), uuid.uuid4())

    mock_get_incident.assert_called_once()
    assert session_db.sessions == []  # nothing persisted


@pytest.mark.asyncio
async def test_create_session_persists_a_new_session_owned_by_the_incident(monkeypatch):
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session_db = _FakeSession()
    incident_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    session = await svc.create_session(session_db, uuid.uuid4(), incident_id, actor_id)

    assert session.incident_id == incident_id
    assert session.created_by_user_id == actor_id
    assert session in session_db.sessions


@pytest.mark.asyncio
async def test_new_session_never_inherits_a_prior_sessions_state(monkeypatch):
    """Phase 3 AC: "New investigation" starts clean — a fresh session has no turns/findings of its own regardless of an older session's history."""
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    incident_id = uuid.uuid4()
    old_session = InvestigationSession(id=uuid.uuid4(), incident_id=incident_id, created_by_user_id=uuid.uuid4())
    old_turn = InvestigationTurn(id=uuid.uuid4(), session_id=old_session.id, asked_by_user_id=uuid.uuid4(), question="q", answer="a", is_fallback=False)
    session_db = _FakeSession(sessions=[old_session], turns=[old_turn])

    new_session = await svc.create_session(session_db, uuid.uuid4(), incident_id, uuid.uuid4())

    assert new_session.id != old_session.id
    # The new session's own turns (queried by its id) are empty — old_turn belongs to old_session.id, not this one.
    turns_for_new_session = [t for t in session_db.turns if t.session_id == new_session.id]
    assert turns_for_new_session == []


# ── list_sessions / get_session ──────────────────────────────────────

@pytest.mark.asyncio
async def test_list_sessions_returns_only_this_incidents_sessions(monkeypatch):
    _mock_get_incident(monkeypatch)
    incident_a, incident_b = uuid.uuid4(), uuid.uuid4()
    session_a = InvestigationSession(id=uuid.uuid4(), incident_id=incident_a, created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc))
    session_b = InvestigationSession(id=uuid.uuid4(), incident_id=incident_b, created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc))
    session_db = _FakeSession(sessions=[session_a, session_b])

    result = await svc.list_sessions(session_db, uuid.uuid4(), incident_a)

    assert [s.id for s in result] == [session_a.id]


@pytest.mark.asyncio
async def test_an_incident_can_have_multiple_sessions_each_independently_addressable(monkeypatch):
    """Phase 3: multiple sessions per incident are allowed — a past session's history stays intact and separately retrievable after a new one starts."""
    _mock_get_incident(monkeypatch)
    incident_id = uuid.uuid4()
    first = InvestigationSession(id=uuid.uuid4(), incident_id=incident_id, created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc))
    second = InvestigationSession(id=uuid.uuid4(), incident_id=incident_id, created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc))
    session_db = _FakeSession(sessions=[first, second])

    all_sessions = await svc.list_sessions(session_db, uuid.uuid4(), incident_id)
    fetched_first = await svc.get_session(session_db, uuid.uuid4(), incident_id, first.id)
    fetched_second = await svc.get_session(session_db, uuid.uuid4(), incident_id, second.id)

    assert {s.id for s in all_sessions} == {first.id, second.id}
    assert fetched_first.id == first.id
    assert fetched_second.id == second.id


@pytest.mark.asyncio
async def test_get_session_returns_the_matching_session(monkeypatch):
    _mock_get_incident(monkeypatch)
    incident_id = uuid.uuid4()
    session = InvestigationSession(id=uuid.uuid4(), incident_id=incident_id, created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    result = await svc.get_session(session_db, uuid.uuid4(), incident_id, session.id)

    assert result.id == session.id


@pytest.mark.asyncio
async def test_get_session_rejects_a_session_id_that_belongs_to_a_different_incident(monkeypatch):
    """
    Root security property (Phase 2): a real, valid session_id must not
    resolve under an incident_id it doesn't actually belong to — this
    is what stops a session_id from being usable as an authorization
    bypass on its own.
    """
    _mock_get_incident(monkeypatch)
    real_incident_id = uuid.uuid4()
    other_incident_id = uuid.uuid4()
    session = InvestigationSession(id=uuid.uuid4(), incident_id=real_incident_id, created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    with pytest.raises(InvestigationSessionNotFoundError):
        await svc.get_session(session_db, uuid.uuid4(), other_incident_id, session.id)


@pytest.mark.asyncio
async def test_get_session_raises_incident_not_found_before_touching_session_data(monkeypatch):
    """Tenant isolation: an incident that doesn't belong to the caller's tenant is rejected before any session lookup happens at all."""
    mock_get_incident = _mock_get_incident(monkeypatch, raises=True)
    session_db = _FakeSession()

    with pytest.raises(IncidentNotFoundError):
        await svc.get_session(session_db, uuid.uuid4(), uuid.uuid4(), uuid.uuid4())

    mock_get_incident.assert_called_once()


@pytest.mark.asyncio
async def test_get_session_404s_for_a_nonexistent_session_id(monkeypatch):
    _mock_get_incident(monkeypatch)
    session_db = _FakeSession()

    with pytest.raises(InvestigationSessionNotFoundError):
        await svc.get_session(session_db, uuid.uuid4(), uuid.uuid4(), uuid.uuid4())


# ── get_session_state / evidence_summary ─────────────────────────────

@pytest.mark.asyncio
async def test_get_session_state_returns_live_evidence_not_a_stored_snapshot(monkeypatch):
    """AC: evidence is always freshly retrieved — this test proves the live-evidence function is actually called on every read, never cached on the session row."""
    _mock_get_incident(monkeypatch)
    incident_id = uuid.uuid4()
    session = InvestigationSession(id=uuid.uuid4(), incident_id=incident_id, created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])
    mock_evidence = _mock_live_evidence(monkeypatch)

    await svc.get_session_state(session_db, uuid.uuid4(), incident_id, session.id)

    mock_evidence.assert_called_once()


@pytest.mark.asyncio
async def test_get_session_state_only_returns_this_sessions_own_findings_actions_notes(monkeypatch):
    """A different session's rows (even for the same incident) must never leak into this session's state."""
    _mock_get_incident(monkeypatch)
    _mock_live_evidence(monkeypatch)
    incident_id = uuid.uuid4()
    session_a = InvestigationSession(id=uuid.uuid4(), incident_id=incident_id, created_by_user_id=uuid.uuid4())
    session_b = InvestigationSession(id=uuid.uuid4(), incident_id=incident_id, created_by_user_id=uuid.uuid4())
    finding_a = InvestigationFinding(id=uuid.uuid4(), session_id=session_a.id, text="A's finding", category=FindingCategory.CONFIRMED, origin=FindingOrigin.ANALYST)
    finding_b = InvestigationFinding(id=uuid.uuid4(), session_id=session_b.id, text="B's finding", category=FindingCategory.CONFIRMED, origin=FindingOrigin.ANALYST)
    session_db = _FakeSession(sessions=[session_a, session_b], findings=[finding_a, finding_b])

    _, _, _, findings, _, _ = await svc.get_session_state(session_db, uuid.uuid4(), incident_id, session_a.id)

    assert [f.text for f in findings] == ["A's finding"]


def test_evidence_summary_extracts_real_hosts_users_techniques_from_live_data():
    data = _evidence_data()
    summary = svc.evidence_summary(data)
    assert summary["hosts"] == ["DEMO-CRITICAL-01"]
    assert summary["users"] == ["leo.chen"]
    assert summary["mitre_techniques"] == ["T1068", "T1078"]
    assert summary["alert_count"] == 1


# ── ask_question (grounded answer + fallback) ────────────────────────

@pytest.mark.asyncio
async def test_ask_question_persists_the_turn_on_success(monkeypatch):
    _mock_get_incident(monkeypatch)
    _mock_live_evidence(monkeypatch)
    _mock_audit(monkeypatch)
    monkeypatch.setattr(svc.ollama, "generate", Mock(return_value="leo.chen and DEMO-CRITICAL-01 were involved."))
    incident_id = uuid.uuid4()
    session = InvestigationSession(id=uuid.uuid4(), incident_id=incident_id, created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])
    actor_id = uuid.uuid4()

    turn = await svc.ask_question(session_db, uuid.uuid4(), incident_id, session.id, "Which host was involved?", actor_id)

    assert turn.question == "Which host was involved?"
    assert turn.answer == "leo.chen and DEMO-CRITICAL-01 were involved."
    assert turn.is_fallback is False
    assert turn.asked_by_user_id == actor_id
    assert turn in session_db.turns


@pytest.mark.asyncio
async def test_ask_question_rejects_a_session_from_a_different_incident(monkeypatch):
    _mock_get_incident(monkeypatch)
    real_incident_id, other_incident_id = uuid.uuid4(), uuid.uuid4()
    session = InvestigationSession(id=uuid.uuid4(), incident_id=real_incident_id, created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    with pytest.raises(InvestigationSessionNotFoundError):
        await svc.ask_question(session_db, uuid.uuid4(), other_incident_id, session.id, "what happened?", uuid.uuid4())

    assert session_db.turns == []


@pytest.mark.asyncio
async def test_ask_question_passes_its_own_dedicated_token_budget(monkeypatch):
    """Regression: this call site must use INVESTIGATION_SESSION_LLM_MAX_OUTPUT_TOKENS, not the incident-narrative or interactive-chat budgets."""
    _mock_get_incident(monkeypatch)
    _mock_live_evidence(monkeypatch)
    _mock_audit(monkeypatch)
    from app.core.config import settings
    monkeypatch.setattr(settings, "INVESTIGATION_LLM_MAX_OUTPUT_TOKENS", 120)
    monkeypatch.setattr(settings, "INCIDENT_NARRATIVE_LLM_MAX_OUTPUT_TOKENS", 350)
    monkeypatch.setattr(settings, "INVESTIGATION_SESSION_LLM_MAX_OUTPUT_TOKENS", 777)
    mock_generate = Mock(return_value="answer")
    monkeypatch.setattr(svc.ollama, "generate", mock_generate)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    await svc.ask_question(session_db, uuid.uuid4(), session.incident_id, session.id, "q", uuid.uuid4())

    assert mock_generate.call_args.args[1] == 777


@pytest.mark.asyncio
async def test_ask_question_falls_back_on_timeout(monkeypatch):
    from app.core.config import settings
    import time
    _mock_get_incident(monkeypatch)
    _mock_live_evidence(monkeypatch)
    _mock_audit(monkeypatch)
    monkeypatch.setattr(settings, "INVESTIGATION_SESSION_LLM_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(svc.ollama, "generate", lambda prompt, *args: (time.sleep(1.0), "too slow")[1])
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    turn = await svc.ask_question(session_db, uuid.uuid4(), session.incident_id, session.id, "q", uuid.uuid4())

    assert turn.is_fallback is True
    assert "host(s)" in turn.answer


@pytest.mark.asyncio
async def test_ask_question_falls_back_on_llm_failure(monkeypatch):
    _mock_get_incident(monkeypatch)
    _mock_live_evidence(monkeypatch)
    _mock_audit(monkeypatch)
    monkeypatch.setattr(svc.ollama, "generate", Mock(side_effect=svc.ollama.OllamaError("connection refused")))
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    turn = await svc.ask_question(session_db, uuid.uuid4(), session.incident_id, session.id, "q", uuid.uuid4())

    assert turn.is_fallback is True


# ── prompt construction: evidence vs confirmed vs hypothesis vs prior answers ──

def _finding(category, text="a finding", origin=FindingOrigin.ANALYST):
    return InvestigationFinding(id=uuid.uuid4(), session_id=uuid.uuid4(), text=text, category=category, origin=origin)


def test_prompt_labels_confirmed_findings_as_established_fact():
    prompt = svc._build_session_prompt(_evidence_data(), [_finding(FindingCategory.CONFIRMED, "leo.chen used compromised creds")], [], "what do we know?")
    assert "Confirmed findings (established fact" in prompt
    assert "leo.chen used compromised creds" in prompt


def test_prompt_explicitly_labels_hypotheses_as_not_established():
    prompt = svc._build_session_prompt(_evidence_data(), [_finding(FindingCategory.HYPOTHESIS, "possible valid-account abuse")], [], "what do we know?")
    assert "Unconfirmed hypotheses (NOT established fact)" in prompt
    assert "possible valid-account abuse" in prompt


def test_prompt_lists_open_questions_separately_from_hypotheses():
    prompt = svc._build_session_prompt(_evidence_data(), [_finding(FindingCategory.OPEN_QUESTION, "initial access vector")], [], "what do we know?")
    assert "Open questions (not yet known)" in prompt
    assert "initial access vector" in prompt


def test_prompt_includes_the_grounding_rule_against_treating_hypotheses_as_fact():
    prompt = svc._build_session_prompt(_evidence_data(), [], [], "q").lower()
    assert "unconfirmed hypotheses and open questions are not established" in prompt
    assert "never treat a prior conversation turn's answer as evidence on its own" in prompt


def test_prompt_frames_prior_turns_as_context_only_not_evidence():
    """Root requirement: the AI must not be able to turn its own previous answer into authoritative evidence."""
    prior_turn = InvestigationTurn(id=uuid.uuid4(), session_id=uuid.uuid4(), asked_by_user_id=uuid.uuid4(), question="what happened?", answer="Possibly a coordinated breach.", is_fallback=False)
    prompt = svc._build_session_prompt(_evidence_data(), [], [prior_turn], "what did we establish earlier?")
    assert "Prior conversation in this session, for context only — not itself evidence" in prompt
    assert "Possibly a coordinated breach." in prompt  # present, but only inside the context-labeled section
    # It must not appear inside the Evidence or Confirmed-findings fenced sections themselves.
    evidence_section = prompt.split("Evidence (established fact):")[1].split("Confirmed findings")[0]
    assert "Possibly a coordinated breach." not in evidence_section


def test_prompt_never_dumps_a_raw_json_envelope():
    prompt = svc._build_session_prompt(_evidence_data(), [], [], "q")
    assert '"type"' not in prompt
    assert '"data":{' not in prompt


def test_prompt_never_encourages_schema_interpretation():
    prompt = svc._build_session_prompt(_evidence_data(), [], [], "q").lower()
    assert "never comment on its structure" in prompt
    assert "to describe and summarize" not in prompt


def test_prompt_instructs_the_exact_insufficient_evidence_phrase():
    prompt = svc._build_session_prompt(_evidence_data(), [], [], "q")
    assert "The available evidence does not establish this." in prompt


# ── findings: creation, provenance, confirm/hypothesis distinction ──

@pytest.mark.asyncio
async def test_create_finding_is_always_origin_analyst(monkeypatch):
    """The AI has no code path to create a finding — only an analyst-authenticated route reaches create_finding."""
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    finding = await svc.create_finding(session_db, uuid.uuid4(), session.incident_id, session.id, "Host confirmed compromised", FindingCategory.HYPOTHESIS, uuid.uuid4())

    assert finding.origin == FindingOrigin.ANALYST


@pytest.mark.asyncio
async def test_create_finding_as_confirmed_stamps_confirmation_immediately(monkeypatch):
    """An analyst directly asserting category=confirmed IS the explicit confirming action."""
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])
    actor_id = uuid.uuid4()

    finding = await svc.create_finding(session_db, uuid.uuid4(), session.incident_id, session.id, "12 linked alerts", FindingCategory.CONFIRMED, actor_id)

    assert finding.confirmed_by_user_id == actor_id
    assert finding.confirmed_at is not None


@pytest.mark.asyncio
async def test_create_finding_as_hypothesis_does_not_stamp_confirmation(monkeypatch):
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    finding = await svc.create_finding(session_db, uuid.uuid4(), session.incident_id, session.id, "possible valid-account abuse", FindingCategory.HYPOTHESIS, uuid.uuid4())

    assert finding.confirmed_by_user_id is None
    assert finding.confirmed_at is None


@pytest.mark.asyncio
async def test_update_finding_category_to_confirmed_requires_the_explicit_call_and_stamps_who(monkeypatch):
    """The only place category=confirmed is ever set on an existing (e.g. AI-suggested) finding — always this explicit analyst action."""
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    finding = InvestigationFinding(id=uuid.uuid4(), session_id=session.id, text="valid-account abuse", category=FindingCategory.HYPOTHESIS, origin=FindingOrigin.AI_SUGGESTED)
    session_db = _FakeSession(sessions=[session], findings=[finding])
    analyst_id = uuid.uuid4()

    updated = await svc.update_finding_category(session_db, uuid.uuid4(), session.incident_id, session.id, finding.id, FindingCategory.CONFIRMED, analyst_id)

    assert updated.category == FindingCategory.CONFIRMED
    assert updated.confirmed_by_user_id == analyst_id
    assert updated.confirmed_at is not None
    assert updated.origin == FindingOrigin.AI_SUGGESTED  # provenance (who first proposed it) is preserved


@pytest.mark.asyncio
async def test_update_finding_category_away_from_confirmed_clears_confirmation(monkeypatch):
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    finding = InvestigationFinding(
        id=uuid.uuid4(), session_id=session.id, text="x", category=FindingCategory.CONFIRMED, origin=FindingOrigin.ANALYST,
        confirmed_by_user_id=uuid.uuid4(), confirmed_at=datetime.now(timezone.utc),
    )
    session_db = _FakeSession(sessions=[session], findings=[finding])

    updated = await svc.update_finding_category(session_db, uuid.uuid4(), session.incident_id, session.id, finding.id, FindingCategory.HYPOTHESIS, uuid.uuid4())

    assert updated.confirmed_by_user_id is None
    assert updated.confirmed_at is None


@pytest.mark.asyncio
async def test_update_finding_category_404s_for_a_finding_from_a_different_session(monkeypatch):
    _mock_get_incident(monkeypatch)
    session_a = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_b = InvestigationSession(id=uuid.uuid4(), incident_id=session_a.incident_id, created_by_user_id=uuid.uuid4())
    finding_in_b = InvestigationFinding(id=uuid.uuid4(), session_id=session_b.id, text="x", category=FindingCategory.HYPOTHESIS, origin=FindingOrigin.ANALYST)
    session_db = _FakeSession(sessions=[session_a, session_b], findings=[finding_in_b])

    with pytest.raises(InvestigationFindingNotFoundError):
        await svc.update_finding_category(session_db, uuid.uuid4(), session_a.incident_id, session_a.id, finding_in_b.id, FindingCategory.CONFIRMED, uuid.uuid4())


# ── actions: distinct from findings, own lifecycle ───────────────────

@pytest.mark.asyncio
async def test_create_action_defaults_to_open(monkeypatch):
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])

    action = await svc.create_action(session_db, uuid.uuid4(), session.incident_id, session.id, "Pull DNS logs for DEMO-CRITICAL-01", uuid.uuid4())

    assert action.status == InvestigationActionStatus.OPEN
    assert action.description == "Pull DNS logs for DEMO-CRITICAL-01"


@pytest.mark.asyncio
async def test_completing_an_action_stamps_who_and_when(monkeypatch):
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    action = InvestigationAction(id=uuid.uuid4(), session_id=session.id, description="x", status=InvestigationActionStatus.OPEN, created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session], actions=[action])
    actor_id = uuid.uuid4()

    updated = await svc.update_action_status(session_db, uuid.uuid4(), session.incident_id, session.id, action.id, InvestigationActionStatus.COMPLETED, actor_id)

    assert updated.completed_by_user_id == actor_id
    assert updated.completed_at is not None


@pytest.mark.asyncio
async def test_update_action_status_404s_for_an_action_from_a_different_session(monkeypatch):
    _mock_get_incident(monkeypatch)
    session_a = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_b = InvestigationSession(id=uuid.uuid4(), incident_id=session_a.incident_id, created_by_user_id=uuid.uuid4())
    action_in_b = InvestigationAction(id=uuid.uuid4(), session_id=session_b.id, description="x", status=InvestigationActionStatus.OPEN, created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session_a, session_b], actions=[action_in_b])

    with pytest.raises(InvestigationActionNotFoundError):
        await svc.update_action_status(session_db, uuid.uuid4(), session_a.incident_id, session_a.id, action_in_b.id, InvestigationActionStatus.IN_PROGRESS, uuid.uuid4())


# ── notes ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_note_persists_the_authors_body(monkeypatch):
    _mock_get_incident(monkeypatch)
    _mock_audit(monkeypatch)
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4())
    session_db = _FakeSession(sessions=[session])
    author_id = uuid.uuid4()

    note = await svc.create_note(session_db, uuid.uuid4(), session.incident_id, session.id, "Called the user; they were on vacation.", author_id)

    assert note.body == "Called the user; they were on vacation."
    assert note.author_user_id == author_id
    assert note in session_db.notes


# ── fallback answer content ───────────────────────────────────────

def test_fallback_answer_reflects_real_evidence_and_confirmed_count():
    data = _evidence_data()
    findings = [_finding(FindingCategory.CONFIRMED), _finding(FindingCategory.OPEN_QUESTION), _finding(FindingCategory.OPEN_QUESTION)]
    answer = svc._fallback_answer(data, findings)
    assert "1 host(s)" in answer
    assert "1 user(s)" in answer
    assert "1 finding(s) confirmed" in answer
    assert "2 open question(s)" in answer
