FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    DATABASE_PATH=/data/securedev.db

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Usuario sin privilegios (antes se ejecutaba como root)
RUN useradd --system --uid 10001 --no-create-home appuser && mkdir /data && chown appuser /data
COPY --chown=appuser app.py ./
COPY --chown=appuser templates ./templates

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=2)"
# 1 worker + hilos: el limitador de login y las métricas viven en memoria del proceso.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "app:create_app()"]
