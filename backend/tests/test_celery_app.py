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
