#!/usr/bin/env bash
# Deploys the Cloud Run service for ROADMAP Phase 1, item 3, and checks its own
# `verify:` line — "the service URL responds publicly; deploy is one command from a
# clean checkout" — by curling the deployed URL rather than trusting the deploy.
#
#   gcloud auth login
#   PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" PROVENANCE_TRIGGER_TOKEN=... \
#     ./scripts/deploy.sh        # PROJECT_ID, REGION and SERVICE override the defaults
#
# Item 9 added two required secrets. The Planner signs its own gateway credential, and
# seed_registry.py prints each private half once and stores it nowhere (ADR-010), so the
# PEM has to arrive from outside the repo. The trigger token guards POST /trigger: the
# service is public by design and every trigger spends model tokens against a fixed
# credit, so an unguarded endpoint is a loop somebody else gets to run.
#
# Cost: --min-instances=0 means $0 while idle, the only posture CLAUDE.md's cost ceiling
# permits by default. Cloud Build minutes and egress sit inside the free tier at this
# volume. Nothing provisioned here bills overnight.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-provenance-hackathon}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-provenance}"
# Gemini 3.x serves only from the global endpoint and 2.5-pro serves from both, so one
# location covers every role (ROADMAP item 1). Must match provenance/models.py's default.
LOCATION="${GOOGLE_CLOUD_LOCATION:-global}"

for required in PROVENANCE_PLANNER_KEY PROVENANCE_TRIGGER_TOKEN; do
  if [[ -z "${!required:-}" ]]; then
    echo "FAIL: ${required} is not set; the deployed fleet would fail closed on every trigger."
    echo "      See the header of this script."
    exit 1
  fi
done

# A PEM is multi-line, which --set-env-vars cannot carry, so the whole environment goes
# in as a YAML file with the key as a block scalar. The file holds a private key: it is
# created with a restrictive umask and removed on every exit path, including a Ctrl-C.
ENV_FILE="$(mktemp -t provenance-env.XXXXXX)"
trap 'rm -f "${ENV_FILE}"' EXIT INT TERM
chmod 600 "${ENV_FILE}"
{
  echo "GOOGLE_CLOUD_PROJECT: \"${PROJECT_ID}\""
  echo "GOOGLE_GENAI_USE_VERTEXAI: \"1\""
  echo "GOOGLE_CLOUD_LOCATION: \"${LOCATION}\""
  echo "PROVENANCE_TRIGGER_TOKEN: \"${PROVENANCE_TRIGGER_TOKEN}\""
  echo "PROVENANCE_PLANNER_KEY: |"
  printf '%s\n' "${PROVENANCE_PLANNER_KEY}" | sed 's/^/  /'
} > "${ENV_FILE}"

echo "==> deploying ${SERVICE} to ${PROJECT_ID} (${REGION})"

# Fail closed: gcloud's own error when an API is off is obscure and arrives after the
# source upload. scripts/gcp_setup.sh owns enabling them; this only checks.
enabled="$(gcloud services list --enabled --project="${PROJECT_ID}" \
           --format='value(config.name)' 2>/dev/null || true)"
for api in run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com; do
  if ! grep -qx "${api}" <<<"${enabled}"; then
    echo "FAIL: ${api} is not enabled on ${PROJECT_ID}."
    echo "      Enable everything this project needs, then re-run:"
    echo "        PROJECT_ID=${PROJECT_ID} ./scripts/gcp_setup.sh"
    exit 1
  fi
done

echo "--> building from source and deploying"
# GOOGLE_CLOUD_PROJECT is what telemetry.configure_tracing() reads. Cloud Run sets no
# such variable on its own, and without it the service comes up with tracing off.
gcloud run deploy "${SERVICE}" \
  --source . \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=3 \
  --memory=512Mi \
  --cpu=1 \
  --env-vars-file="${ENV_FILE}" \
  --quiet

# status.url still reports the legacy run.app hostname Google is retiring; the annotation
# lists the canonical project-number URL first. Both serve — this is the one for the README.
URL="$(gcloud run services describe "${SERVICE}" --project="${PROJECT_ID}" --region="${REGION}" \
       --format='value(metadata.annotations."run.googleapis.com/urls")' \
       | tr -d '[]"' | cut -d, -f1)"
CONSOLE="https://console.cloud.google.com/run/detail/${REGION}/${SERVICE}/metrics?project=${PROJECT_ID}"

echo "--> checking ${URL}/health responds publicly"
# No credentials on the curl: an unauthenticated 200 is the thing being verified.
if ! body="$(curl -fsS --max-time 30 "${URL}/health")"; then
  echo "FAIL: ${URL}/health did not return 200."
  echo "      Logs: ${CONSOLE}"
  exit 1
fi
echo "    ${body}"

# The trigger stream must be guarded on the public URL. A 403 here is the check passing:
# an open /trigger on a public service is an unbounded spend against a fixed credit.
echo "--> checking ${URL}/trigger refuses an unauthenticated trigger"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST "${URL}/trigger" \
        -H 'Content-Type: application/json' \
        -d '{"target":"inventory-api","observed_value":0.38,"observed_at":"2026-08-21T14:06:00Z"}')"
if [[ "${code}" != "403" ]]; then
  echo "FAIL: ${URL}/trigger answered ${code} with no token, expected 403."
  echo "      Logs: ${CONSOLE}"
  exit 1
fi
echo "    403 — guarded"

echo "==> live: ${URL}"
echo "    console: ${CONSOLE}"
