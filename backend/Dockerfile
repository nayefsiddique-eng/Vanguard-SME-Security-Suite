# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /workspace

RUN --mount=type=bind,source=.,target=/src,readonly \
    apt-get update && apt-get install -y --no-install-recommends nmap clamav \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --only-binary=:all: -r /src/requirements.txt \
    && cp -a /src/app /workspace/app && chmod -R a+rX /workspace/app \
    && useradd --system --create-home vanguard \
    && mkdir /data && chown vanguard /data

USER vanguard
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
    CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=2).close()"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
