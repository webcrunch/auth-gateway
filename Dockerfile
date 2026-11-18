FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates templates
COPY static static

RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8000
# One process, so the cache of n8n's answers is shared by every request; threads for parallel requests
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--access-logfile", "-", "app:app"]
