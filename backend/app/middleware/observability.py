"""
SafeSOC — Observability Middleware (SS-077)
One middleware pass per request, two concerns: assigns/propagates a
request ID (reused from an incoming X-Request-ID header if the caller
already supplies one — e.g. from an upstream load balancer/gateway —
generated fresh otherwise) into utils/logger.py's request_id_var for
the duration of the request, echoed back as a response header; and
records the Prometheus HTTP metrics defined in utils/metrics.py.

This is the first thing backend/app/middleware/ (previously an empty
stub — see CLAUDE.md's note that nothing needed it yet) has actually
needed: HTTP-cross-cutting concerns are exactly what middleware is
for, and this issue (SS-077) is that need.
"""

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.utils.logger import request_id_var
from app.utils.metrics import http_request_duration_seconds, http_requests_total


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        token = request_id_var.set(request_id)

        start = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        elapsed = time.perf_counter() - start

        # The route's path TEMPLATE (e.g. "/api/v1/incidents/{incident_id}"),
        # not the raw path with a real UUID interpolated — a raw-path
        # label would make this metric's cardinality grow without bound
        # as new incidents/alerts are created (a classic Prometheus
        # footgun). Only populated once routing has resolved inside
        # call_next(); falls back to the raw path for an unmatched
        # route (a genuine 404) rather than dropping the request.
        route = request.scope.get("route")
        path_template = getattr(route, "path", None) or request.url.path

        http_requests_total.labels(method=request.method, path=path_template, status_code=response.status_code).inc()
        http_request_duration_seconds.labels(method=request.method, path=path_template).observe(elapsed)

        response.headers["X-Request-ID"] = request_id
        return response
