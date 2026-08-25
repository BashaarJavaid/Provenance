#!/usr/bin/env python3
"""Create the `provenance-ingest` Model Armor template (item 25), then read it back.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/setup_model_armor.py

Three settings, and each one is load-bearing:

  * **prompt-injection / jailbreak, enforcement ENABLED, confidence HIGH.** `HIGH` is what
    spec §10 published *before* anyone measured this payload, so it is a prior commitment and
    not a threshold fitted to the result we wanted. If the crafted payload turns out to be
    caught here, the honest move is to record that and re-script item 27 — not to lower this
    number until the demo works.
  * **Sensitive Data Protection, basic config ENABLED.** The other half of item 25's title.
    Basic covers credit cards / SSNs / GCP credentials with no DLP template to keep in sync.
  * **`log_sanitize_operations`.** This single flag *is* item 25's "verdicts logged to Cloud
    Logging". Model Armor writes each verdict itself, under service `modelarmor.googleapis.com`
    — the service's own record rather than our restatement of it, so there are not two sources
    that can disagree.

No RAI filters and no malicious-URI filter: neither is what item 25 names, and neither the
`verify:` line nor item 27's arc exercises them.

Create-if-absent and **deliberately no `--reset`** — `seed_registry.py` and `seed_belief.py`'s
posture. Item 27 may tune this template on camera; a script that silently rewrote it would
undo that. A re-run reads the existing template back, prints its config, and exits 0.

The template id, the location and the regional endpoint all come from `provenance/ingest.py`
so there is one source of truth for them. Needs credentials, so it is not in CI.
"""

from __future__ import annotations

import os
import sys

from google.api_core import exceptions as gexc
from google.cloud import modelarmor_v1

from provenance import ingest

WANTED = modelarmor_v1.Template(
    filter_config=modelarmor_v1.FilterConfig(
        pi_and_jailbreak_filter_settings=modelarmor_v1.PiAndJailbreakFilterSettings(
            filter_enforcement=modelarmor_v1.PiAndJailbreakFilterSettings.PiAndJailbreakFilterEnforcement.ENABLED,
            confidence_level=modelarmor_v1.DetectionConfidenceLevel.HIGH,
        ),
        sdp_settings=modelarmor_v1.SdpFilterSettings(
            basic_config=modelarmor_v1.SdpBasicConfig(
                filter_enforcement=modelarmor_v1.SdpBasicConfig.SdpBasicConfigEnforcement.ENABLED
            )
        ),
    ),
    template_metadata=modelarmor_v1.Template.TemplateMetadata(log_sanitize_operations=True),
)


def describe(template: modelarmor_v1.Template) -> None:
    pi = template.filter_config.pi_and_jailbreak_filter_settings
    sdp = template.filter_config.sdp_settings.basic_config
    print(f"    name                    {template.name}")
    print(f"    pi_and_jailbreak        {pi.filter_enforcement.name} / {pi.confidence_level.name}")
    print(f"    sdp basic               {sdp.filter_enforcement.name}")
    print(f"    log_sanitize_operations {template.template_metadata.log_sanitize_operations}")


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print(
            "      GOOGLE_CLOUD_PROJECT=provenance-hackathon"
            " .venv/bin/python scripts/setup_model_armor.py",
            file=sys.stderr,
        )
        return 1

    name = ingest.template_path(project_id)
    client = ingest._default_client()
    print(f"==> {name}")

    try:
        existing = client.get_template(name=name)
    except gexc.NotFound:
        existing = None
    if existing is not None:
        print("    already exists — no-op (this script has no --reset, deliberately)")
        describe(existing)
        return 0

    parent = f"projects/{project_id}/locations/{ingest.LOCATION}"
    created = client.create_template(parent=parent, template_id=ingest.TEMPLATE_ID, template=WANTED)
    print("    created")
    describe(created)

    # Read it back through a second call rather than trusting the create response: the
    # `verify:` line is that the template *reads back* with the settings we asked for.
    stored = client.get_template(name=name)
    pi = stored.filter_config.pi_and_jailbreak_filter_settings
    if pi.confidence_level != modelarmor_v1.DetectionConfidenceLevel.HIGH:
        print(
            f"FAIL: confidence read back as {pi.confidence_level.name}, not HIGH", file=sys.stderr
        )
        return 1
    if not stored.template_metadata.log_sanitize_operations:
        print(
            "FAIL: log_sanitize_operations read back false — verdicts would not be logged",
            file=sys.stderr,
        )
        return 1
    print("==> done. Verdicts from this template land in Cloud Logging.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
