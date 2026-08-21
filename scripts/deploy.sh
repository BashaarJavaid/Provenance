#!/usr/bin/env bash
# Deploys the Cloud Run service for ROADMAP Phase 1, item 3, and checks its own
# `verify:` line — "the service URL responds publicly; deploy is one command from a
# clean checkout" — by curling the deployed URL rather than trusting the deploy.
#
#   gcloud auth login
#   ./scripts/deploy.sh          # PROJECT_ID, REGION and SERVICE override the defaults
#
# Cost: --min-instances=0 means $0 while idle, the only posture CLAUDE.md's cost ceiling
# permits by default. Cloud Build minutes and egress sit inside the free tier at this
# volume. Nothing provisioned here bills overnight.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-provenance-hackathon}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-provenance}"

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
  --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT_ID}" \
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

echo "==> live: ${URL}"
echo "    console: ${CONSOLE}"
