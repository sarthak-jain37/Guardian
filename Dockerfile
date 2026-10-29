# Build once; backend, inference worker, collector and dashboard share this image.
FROM python:3.11.14-slim-bookworm
ARG GUARDIAN_VERSION=0.2.0-rc.1
LABEL org.opencontainers.image.title="Guardian" org.opencontainers.image.version=$GUARDIAN_VERSION
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/app/.venv/bin:$PATH
WORKDIR /app
RUN pip install --no-cache-dir uv==0.9.5
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --extra verification && rm -rf /root/.cache
COPY agents agents
COPY backend backend
COPY contracts contracts
COPY frontend frontend
COPY scripts scripts
COPY demo/checks demo/checks
RUN useradd --uid 10001 --create-home guardian && mkdir -p /state && chown guardian:guardian /state
USER 10001:10001
EXPOSE 8000 8501
CMD ["uvicorn","backend.app.main:app","--host","0.0.0.0","--port","8000"]
