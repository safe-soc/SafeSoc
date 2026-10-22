"""
SafeSOC — Correlation Worker
Runs SS-028's pattern detectors against a host's sliding window after a
log is accepted by POST /api/v1/ingest, so attack chains are detected
within seconds of ingestion (SRS §3.3), not on a delay. Each detected
chain above the confidence threshold is turned into exactly one
incident (SS-031), deduplicated rather than created per re-detection.

SOAR Phase 2: right after create_or_merge_incident, also evaluates the
static playbook catalog against the same detected chain
(services.soar.evaluate_triggers) and queues any AUTOMATIC actions it
creates for execution (workers.soar_worker) — the integration point
the SOAR architecture calls for, alongside the pre-existing
notify_attack_chain/publish_event calls, not a parallel incident-
creation path.
"""

import asyncio
import time
import uuid
from datetime import datetime

from app.db.opensearch import get_alert_by_id
from app.db.postgresql import worker_session_factory
from app.services import soar as soar_service
from app.services.correlation import add_event, evaluate_host
from app.services.incidents import create_or_merge_incident
from app.services.notifications import notify_attack_chain
from app.services.realtime import publish_event
from app.tasks.celery_app import celery_app
from app.utils.logger import get_logger
from app.workers.soar_worker import execute_soar_action

logger = get_logger(__name__)


def _event_timestamp(doc: dict, alert_id: str) -> float:
    """
    The alert's own event time as unix seconds, for the correlation
    window's sorted-set score.

    Processing time is NOT usable here: queue_post_ingest_tasks queues
    one Celery task per accepted alert and they run concurrently, so
    task-completion order has nothing to do with event order — the
    order-sensitive detectors (privilege escalation, successful
    compromise, recon->exploitation, lateral movement) were effectively
    coin-tossing on a two-event chain. See docs/decisions.md ADR-011.

    Falls back to now if the field is missing or unparseable, which
    degrades to the old behavior for that one event rather than dropping
    it from correlation entirely. Parsing mirrors
    services/incident_timeline.py::_parse_alert_timestamp.
    """
    raw = doc.get("timestamp")
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    logger.warning(
        "Alert has no parseable timestamp — correlating it at processing time instead",
        alert_id=alert_id, timestamp=raw,
    )
    return time.time()


@celery_app.task(name="app.workers.correlation_worker.evaluate_correlation")
def evaluate_correlation(alert_id: str) -> None:
    """Celery entrypoint: add the alert to its host's window, then re-evaluate every pattern detector."""
    asyncio.run(_evaluate_correlation_async(alert_id))


async def _evaluate_correlation_async(alert_id: str) -> None:
    doc = await get_alert_by_id(alert_id)
    if doc is None:
        logger.warning("Correlation task could not find alert", alert_id=alert_id)
        return

    tenant_id = doc["tenant_id"]
    host_id = doc["host_id"]

    await add_event(
        tenant_id,
        host_id,
        {
            "alert_id": doc.get("alert_id"),
            "log_type": doc.get("log_type"),
            "action": doc.get("action"),
            "severity": doc.get("severity"),
            "destination_ip": doc.get("destination_ip"),
        },
        timestamp=_event_timestamp(doc, alert_id),
    )

    chains = await evaluate_host(tenant_id, host_id)
    if not chains:
        return

    # Every AUTOMATIC SOAR action id queued below is collected here and
    # only ever .delay()'d AFTER this task's session has committed and
    # closed — never while it is still open. A queued execute_soar_action
    # task can start within milliseconds on a different Celery prefork
    # subprocess, and it reads the run and actions this session is still
    # writing; queuing early raced that write (observed live as an
    # AWAITING_APPROVAL transition that never persisted).
    #
    # The session comes from worker_session_factory (NullPool) — see
    # db/postgresql.py. Connections no longer outlive the event loop that
    # opened them, which is what the dispose-before-and-after handling
    # here used to be working around.
    queued_action_ids: list[uuid.UUID] = []

    async with worker_session_factory() as db:
        for chain in chains:
            incident = await create_or_merge_incident(db, uuid.UUID(tenant_id), host_id, chain)
            logger.info(
                "Correlation chain detected",
                tenant_id=tenant_id,
                host_id=host_id,
                pattern=chain.pattern.value,
                confidence=round(chain.confidence, 2),
                alert_ids=list(chain.alert_ids),
                mitre_technique_ids=list(chain.mitre_technique_ids),
                mitre_tactic=chain.mitre_tactic,
                incident_id=str(incident.id),
            )
            # Real-time Telegram notification (SS-056) — a no-op if
            # TELEGRAM_BOT_TOKEN/CHAT_ID aren't configured (SS-055),
            # same as the critical-alert path below never blocks anything.
            notify_attack_chain(host_id, chain, incident.id)
            # Live dashboard push (SS-063) — the frontend's open dashboard
            # updates without a manual refresh (AC).
            await publish_event(
                tenant_id,
                "chain_detected",
                {
                    "incident_id": str(incident.id),
                    "host_id": host_id,
                    "pattern": chain.pattern.value,
                    "confidence": round(chain.confidence, 2),
                },
            )
            # SOAR Phase 2: match this detected pattern against the
            # static playbook catalog and queue any AUTOMATIC actions
            # it produces. evaluate_triggers is itself idempotent per
            # (incident, playbook) — a re-detection of the same
            # evolving chain that merges into this same incident
            # again will not create a second run.
            # Phase 3.5: SOAR is a RESPONSE layer bolted onto the
            # detection pipeline — it must never be able to take
            # detection down with it. evaluate_triggers already
            # handles the expected degradations itself (incomplete
            # evidence, unvalidatable parameters) without raising;
            # this guard exists for everything else, so an
            # unforeseen SOAR fault can't cost us the remaining
            # chains in this batch, their notifications, or their
            # dashboard pushes. The rollback matters: without it a
            # failed statement leaves this session unusable and the
            # next chain's create_or_merge_incident would fail too.
            try:
                trigger_result = await soar_service.evaluate_triggers(
                    db, uuid.UUID(tenant_id), incident.id, chain.pattern, chain.confidence
                )
                if trigger_result is not None:
                    run, automatic_action_ids = trigger_result
                    queued_action_ids.extend(automatic_action_ids)
                    logger.info(
                        "SOAR playbook triggered", incident_id=str(incident.id), playbook_id=run.playbook_id,
                        run_id=str(run.id), run_status=run.status.value, queued_actions=len(automatic_action_ids),
                    )
            except Exception as e:
                await db.rollback()
                logger.error(
                    "SOAR trigger evaluation failed — correlation continues",
                    tenant_id=tenant_id, incident_id=str(incident.id), pattern=chain.pattern.value,
                    error_type=type(e).__name__, error=str(e),
                )
    # Deferred to here — see the comment above queued_action_ids: this
    # task's own DB session is fully closed before any queued action is
    # allowed to start.
    for action_id in queued_action_ids:
        execute_soar_action.delay(str(action_id))
