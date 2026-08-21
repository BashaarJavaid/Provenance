# The Cloud Run image for ROADMAP Phase 1, item 3. Built by `./scripts/deploy.sh`.
#
# 3.12 because pyproject pins requires-python = "==3.12.*". ADK's own `adk deploy
# cloud_run` template is 3.11, agent-folder-shaped, and has no hook for the install
# below — see docs/adr/ADR-008.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY provenance ./provenance

# Two steps, deliberately, and the order matters. portunusmcp pins fastapi==0.115.6;
# without --no-deps pip silently downgrades fastapi/starlette out of google-adk's
# supported range (>=0.133,<1) rather than erroring, and drags in redis, sqlalchemy,
# asyncpg, alembic, mcp and uvloop. Same constraint as .github/workflows/ci.yml.
# See ROADMAP.md item 0.5 and docs/adr/ADR-004. Do not merge these into one line.
RUN pip install --no-cache-dir . \
 && pip install --no-cache-dir --no-deps portunusmcp==0.1.0

# Cloud Run injects $PORT (8080). Bind 0.0.0.0 or the container is unreachable.
ENV PORT=8080
CMD exec uvicorn provenance.app:app --host 0.0.0.0 --port "$PORT"
