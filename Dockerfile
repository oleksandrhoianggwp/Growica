FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
RUN apt-get update \
 && apt-get install -y --no-install-recommends libatomic1 \
 && pip install -r requirements-dev.txt \
 && python -m playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*

COPY formbot ./formbot
COPY tests ./tests
COPY app.py pytest.ini ./

RUN useradd --create-home --uid 1000 appuser \
 && mkdir -p /app/data \
 && chown -R appuser:appuser /app /ms-playwright
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

CMD ["python", "app.py"]
