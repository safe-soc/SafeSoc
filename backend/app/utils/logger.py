"""
SafeSOC — Structured JSON Logger
Replaces print() with timestamped, service-tagged JSON logs.
"""

import json
import logging
import sys
from datetime import datetime, timezone


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