"""
SafeSOC — Celery App Tests
"""

from app.core.config import settings
from app.tasks.celery_app import celery_app


def test_celery_app_broker_and_backend_use_redis_url():
    assert celery_app.conf.broker_url == settings.redis_url
    assert celery_app.conf.result_backend == settings.redis_url


def test_ping_task_is_registered():
    assert "app.tasks.celery_app.ping" in celery_app.tasks


def test_risk_recalculation_task_is_registered():
    assert "app.tasks.scoring.recalculate_all_risk_scores" in celery_app.tasks


def test_risk_recalculation_is_scheduled_at_the_configured_interval():
    schedule_entry = celery_app.conf.beat_schedule["recalculate-risk-scores"]

    assert schedule_entry["task"] == "app.tasks.scoring.recalculate_all_risk_scores"
    assert schedule_entry["schedule"] == settings.RISK_RECALC_INTERVAL_MINUTES * 60
