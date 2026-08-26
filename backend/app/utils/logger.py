"""
SafeSOC — Structured JSON Logger
Replaces print() with timestamped, service-tagged JSON logs.

SS-077: request_id_var (a contextvar, set once per HTTP request by
middleware/observability.py:RequestIDMiddleware) is included in every
log entry automatically when one is set — the "structured tracing"
piece of platform observability, extending this existing logger
rather than standing up a second, parallel logging/tracing system.
Log lines with no request in flight (a Celery task, a startup message)
simply carry no request_id, same as today.
"""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

# Set by middleware/observability.py for the duration of one HTTP
# request; unset (None) outside a request context (background tasks,
# Celery workers, startup/shutdown).
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


class StructuredLogger:
    """Logger that outputs JSON-formatted log entries."""

    def __init__(self, name: str, service: str = "safesoc"):
        self.service = service
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.DEBUG)
            self.logger.addHandler(handler)

    def _format(self, level: str, message: str, **kwargs) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "service": self.service,
            "message": message,
        }
        request_id = request_id_var.get()
        if request_id is not None:
            entry["request_id"] = request_id
        entry.update(kwargs)
        return json.dumps(entry)

    def debug(self, message: str, **kwargs):
        self.logger.debug(self._format("DEBUG", message, **kwargs))

    def info(self, message: str, **kwargs):
        self.logger.info(self._format("INFO", message, **kwargs))

    def warning(self, message: str, **kwargs):
        self.logger.warning(self._format("WARNING", message, **kwargs))

    def error(self, message: str, **kwargs):
        self.logger.error(self._format("ERROR", message, **kwargs))

    def critical(self, message: str, **kwargs):
        self.logger.critical(self._format("CRITICAL", message, **kwargs))


# Module-level factory
def get_logger(name: str, service: str = "safesoc") -> StructuredLogger:
    return StructuredLogger(name, service)