FROM python:3.12-slim

WORKDIR /app

# WeasyPrint (SS-052, PDF report generation) needs Pango for text
# shaping — not pulled in by pip since it's a native library, not a
# Python package. python:3.12-slim doesn't ship it by default.

RUN apt-get -o Acquire::Retries=3 update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Bring the schema up to date before serving, so a fresh Postgres volume
# (e.g. after `docker compose down -v`) never leaves the API running
# against missing tables. `alembic upgrade head` is a no-op when already
# at head. Only this default CMD migrates: docker-compose.yml's worker and
# beat override `command:`, so they never race the backend's migration —
# they start only once the backend's healthcheck passes instead.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"]