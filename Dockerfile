# AgentForge web service (read-only observability dashboard + platform API).
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 AGENTFORGE_EVALS_DIR=/app/evals
COPY pyproject.toml README.md ./
COPY src ./src
COPY evals ./evals
COPY docs ./docs
COPY contracts ./contracts
# Install the package (runtime deps resolved from pyproject).
RUN pip install --upgrade pip && pip install .
EXPOSE 8000
# Railway injects $PORT; default 8000 locally.
CMD ["sh", "-c", "uvicorn agentforge.web:app --host 0.0.0.0 --port ${PORT:-8000}"]
