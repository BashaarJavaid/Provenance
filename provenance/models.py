"""Which model each reasoning role runs on (item 9).

ROADMAP item 1 recorded that **Gemini 3.5 Pro does not exist** for this project and closed
with a promise: "the model is a per-role config string, so swapping back is a one-line
change if access appears." This module is that promise made true — one file, four strings,
each overridable by environment variable without a redeploy of anything else.

`ARCHITECTURE.md` §5 assigns the roles: the Orchestrator (§5.3), the domain agents (§5.4)
and the Remediation Planner (§5.5) reason on `gemini-2.5-pro`; the Verification Agent
(§5.8) runs on `gemini-3.5-flash`. `VERIFICATION` is declared here now and first read in
item 10, so the four roles live together rather than three here and one somewhere else.

`LOCATION` is `global`, not a region. Item 1's finding: Gemini 3.x is served only from the
global endpoint and a regional probe 404s on models that are in fact available. 2.5-pro
serves from both (checked), so one endpoint covers every role and item 10 needs no second
client configuration.

This is a config module, not an authority: nothing here is an input to a deterministic
decision. A wrong string makes an agent fail to reason; it cannot make the gateway approve
something (§1.1 property 3).
"""

from __future__ import annotations

import os

ORCHESTRATOR = os.environ.get("PROVENANCE_MODEL_ORCHESTRATOR", "gemini-2.5-pro")
DOMAIN = os.environ.get("PROVENANCE_MODEL_DOMAIN", "gemini-2.5-pro")
PLANNER = os.environ.get("PROVENANCE_MODEL_PLANNER", "gemini-2.5-pro")
VERIFICATION = os.environ.get("PROVENANCE_MODEL_VERIFICATION", "gemini-3.5-flash")

# Item 16's recall index (§6.6). Not a reasoning role -- it nominates candidate belief ids and
# decides nothing, which is why ADR-005 lets the index be dumb. Probed live before it was
# wired: `text-embedding-005` serves from **both** `us-central1` and `global` for this project
# at 768 dimensions, so `LOCATION` below covers it and recall needs no endpoint of its own.
EMBEDDING = os.environ.get("PROVENANCE_MODEL_EMBEDDING", "text-embedding-005")

LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
