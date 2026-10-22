FROM python:3.12-slim

WORKDIR /app

# WeasyPrint (SS-052, PDF report generation) needs Pango for text
# shaping — not pulled in by pip since it's a native library, not a
# Python package. python:3.12-slim doesn't ship it by default.

RUN apt-get -o Acquire::Retries=3 update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]