"""
SafeSOC — Investigation API
POST /api/v1/investigate — accepts a natural-language query and an
optional conversation/session ID, returning the assistant's response
(SS-047). Requires a valid JWT (SS-015); tenant_id is derived from the
token, not the caller (SS-016).

Orchestrates the pieces built across this milestone: classify the
query and resolve conversation context (SS-044/SS-046), call the
matching MCP tool (SS-045), then ask the configured LLM provider
(SS-042/SS-043) to turn the tool's structured result into a
conversational answer.
"""

import asyncio
import uuid
from typing import Optional

from fastapi import APIRouter, Depends
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients import groq, ollama
from app.core.config import settings
from app.core.dependencies import CurrentUser, get_current_user
from app.core.enums import Intent
from app.db.postgresql import get_db
from app.mcp import TOOLS
from app.schemas.investigation import InvestigateRequest, InvestigateResponse
from app.services.investigation import append_turn, get_context, resolve_query
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["investigate"])

_UNKNOWN_INTENT_ANSWER = (
    "I couldn't determine what you're asking. Try asking about failed logins, IP activity, "
    "an endpoint's status, top alerts, user activity, cloud findings, risky endpoints, or "
    "attack chain status."
)


def _fallback_answer(intent: Intent, tool_result: BaseModel) -> str:
    """A simple, deterministic summary used when the LLM is unavailable or too slow to ask."""
    data = tool_result.model_dump()
    label = intent.value.replace("_", " ")
    if "total" in data:
        return f"Found {data['total']} result(s) for your {label} query."
    if "endpoints" in data:
        return f"Found {len(data['endpoints'])} endpoint(s) for your {label} query."
    return f"Here is the data for your {label} query."


def _tool_error_answer(intent: Intent) -> str:
    """
    A safe, explanatory answer used when the matching MCP tool couldn't
    be executed at all (SS-085) — a bad/missing parameter or a
    downstream OpenSearch/Postgres failure. Unlike _fallback_answer,
    there's no tool_result to summarize here, so this can't reuse it.
    """
    label = intent.value.replace("_", " ")
    return (
        f"I understood you're asking about {label}, but ran into a problem retrieving the "
        "underlying data. Please try again in a moment."
    )


def _build_prompt(query: str, tool_result: BaseModel, transcript: list[dict]) -> str:
    """
    Build the LLM prompt, optionally prefixed with recent conversation
    history (SS-088) so a follow-up answer can actually reference what
    was said earlier — not just inherit the same intent/params, which
    is all resolve_query() alone gives the LLM today. Explicitly framed
    as context, not evidence, so the model doesn't treat a prior turn's
    prose as new data to cite.
    """
    transcript_section = ""
    if transcript:
        history = "\n".join(f"Analyst: {turn['query']}\nAssistant: {turn['answer']}" for turn in transcript)
        transcript_section = (
            "Prior conversation, for context only — do not treat this as new evidence:\n"
            f"{history}\n\n"
        )

    return (
        "You are a security operations assistant. Answer the analyst's question "
        "conversationally and concisely, using only the data provided below.\n\n"
        f"{transcript_section}"
        f"Question: {query}\n"
        f"Data (JSON): {tool_result.model_dump_json()}"
    )


async def _generate_answer(
    query: str, intent: Intent, tool_result: BaseModel, transcript: Optional[list[dict]] = None
) -> tuple[str, bool]:
    """
    Ask the configured LLM provider to summarize tool_result in answer
    to `query`. Bounded by INVESTIGATION_LLM_TIMEOUT_SECONDS so a slow
    or unreachable LLM can't blow the SRS's 15-second response target
    (AC) — any failure or timeout degrades to a templated summary of
    the same data rather than failing the request.

    Returns (answer, is_fallback) — is_fallback is True whenever answer
    came from _fallback_answer() rather than the LLM, so callers can
    tell a genuine LLM response apart from a degraded one (SS-084).
    """
    llm_client = groq if settings.LLM_PROVIDER == "groq" else ollama
    prompt = _build_prompt(query, tool_result, transcript or [])

    try:
        # generate() is a blocking `requests` call — run it off the event
        # loop so it can actually be bounded by wait_for.
        answer = await asyncio.wait_for(
            asyncio.to_thread(llm_client.generate, prompt),
            timeout=settings.INVESTIGATION_LLM_TIMEOUT_SECONDS,
        )
        return answer, False
    except asyncio.TimeoutError:
        # asyncio.wait_for's TimeoutError carries no message (str(e) == ""),
        # so log this case explicitly instead of falling through to the
        # generic handler below and reporting an empty, undiagnosable error.
        logger.warning(
            "LLM answer generation timed out, falling back to a templated summary",
            timeout_seconds=settings.INVESTIGATION_LLM_TIMEOUT_SECONDS,
        )
        return _fallback_answer(intent, tool_result), True
    except Exception as e:
        # type(e).__name__ alongside str(e) so an exception with an empty
        # or unhelpful message (as above) still identifies what happened.
        logger.warning(
            "LLM answer generation failed, falling back to a templated summary",
            error_type=type(e).__name__,
            error=str(e),
        )
        return _fallback_answer(intent, tool_result), True


@router.post("/investigate", response_model=InvestigateResponse)
async def investigate(
    payload: InvestigateRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Answer a natural-language security question, scoped to the
    authenticated tenant. `session_id` is optional — omit it to start a
    new conversation (a fresh one is generated and returned); pass a
    previous response's session_id back to ask a follow-up that can
    reference what was already discussed (SS-046).
    """
    session_id = payload.session_id or str(uuid.uuid4())

    intent, params = await resolve_query(str(current_user.tenant_id), session_id, payload.query)

    if intent == Intent.UNKNOWN:
        return InvestigateResponse(
            session_id=session_id,
            intent=Intent.UNKNOWN,
            answer=_UNKNOWN_INTENT_ANSWER,
            data={},
            is_fallback=False,
        )

    try:
        tool_result = await TOOLS[intent].call(db, current_user.tenant_id, params)
    except (ValidationError, OpenSearchException, SQLAlchemyError) as e:
        # A bad/missing tool parameter or a downstream OpenSearch/Postgres
        # failure must still return a proper InvestigateResponse (AC) —
        # not an unhandled 500 — while preserving the classified intent
        # (SS-085). Deliberately narrow: anything else (a real
        # programming bug) is left to propagate and surface as a
        # failure, same as before this change.
        logger.warning(
            "Investigation tool call failed, returning an explanatory response",
            intent=intent.value,
            error_type=type(e).__name__,
            error=str(e),
        )
        return InvestigateResponse(
            session_id=session_id,
            intent=intent,
            answer=_tool_error_answer(intent),
            data={},
            is_fallback=True,
        )

    context = await get_context(str(current_user.tenant_id), session_id)
    transcript = context.transcript if context is not None else []

    answer, is_fallback = await _generate_answer(payload.query, intent, tool_result, transcript)

    # Recorded only on this success path (SS-088) — the UNKNOWN and
    # tool-error-fallback answers above intentionally aren't part of
    # the transcript the LLM prompt draws on.
    await append_turn(str(current_user.tenant_id), session_id, payload.query, answer)

    return InvestigateResponse(
        session_id=session_id,
        intent=intent,
        answer=answer,
        data=tool_result.model_dump(mode="json"),
        is_fallback=is_fallback,
    )
