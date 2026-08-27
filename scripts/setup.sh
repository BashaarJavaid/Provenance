#!/usr/bin/env bash
# One command for a clean checkout — the two installs the project needs, in the order it
# needs them. See ROADMAP item 0.5 and docs/adr/ADR-004 for why they cannot be one step:
# portunusmcp pins fastapi==0.115.6 and pip would silently downgrade google-adk's fastapi
# out of its supported range rather than reporting the conflict. `pip check` therefore
# exits non-zero here by design, and CI does not gate on it.
#
# provenance/credentials.py imports `services.gateway` from portunusmcp, so skipping the
# second step is not a soft failure — pytest fails at collection.
set -euo pipefail

PY="${PYTHON:-python3.12}"
VENV="${VENV:-.venv}"

[ -d "$VENV" ] || "$PY" -m venv "$VENV"
"$VENV/bin/pip" install -e ".[dev]"
"$VENV/bin/pip" install --no-deps portunusmcp==0.1.0

echo
echo "Done. Run the suite:  $VENV/bin/pytest"
