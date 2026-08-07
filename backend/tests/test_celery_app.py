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


def test_report_generation_task_is_registered():
    assert "app.tasks.reporting.generate_all_tenant_reports" in celery_app.tasks


def test_report_generation_is_scheduled_at_the_configured_day_and_hour():
    """
    Regression test: settings.REPORT_SCHEDULE_DAY documents Python's
    datetime.weekday() convention (0=Monday), but Celery's crontab
    day_of_week uses cron's convention (0=Sunday) — verified live that
    passing REPORT_SCHEDULE_DAY straight through silently scheduled the
    default ("Monday", 0) on a Sunday instead.
    """
    schedule_entry = celery_app.conf.beat_schedule["generate-tenant-reports"]
    crontab_schedule = schedule_entry["schedule"]

    assert schedule_entry["task"] == "app.tasks.reporting.generate_all_tenant_reports"
    assert crontab_schedule.hour == {settings.REPORT_SCHEDULE_HOUR}
    # settings.REPORT_SCHEDULE_DAY=0 (Monday, Python convention) must
    # become cron day_of_week=1 (Monday, cron convention), not 0 (Sunday).
    assert crontab_schedule.day_of_week == {(settings.REPORT_SCHEDULE_DAY + 1) % 7}
