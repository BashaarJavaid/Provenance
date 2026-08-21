#!/usr/bin/env bash
# Provisions the GCP side of ROADMAP Phase 1, item 1: project, APIs, Firestore,
# and a live Gemini 3.5 access probe. Idempotent — safe to re-run.
#
#   gcloud auth login && gcloud auth application-default login
#   PROJECT_ID=my-project ./scripts/gcp_setup.sh
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-provenance-hackathon}"
REGION="${REGION:-us-central1}"

echo "==> project: ${PROJECT_ID}   region: ${REGION}"

if ! gcloud projects describe "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "--> creating project"
  if ! gcloud projects create "${PROJECT_ID}" --name="Provenance"; then
    echo "FAIL: could not create '${PROJECT_ID}' (the ID may be taken globally)."
    echo "      Re-run with a different ID: PROJECT_ID=${PROJECT_ID}-$(date +%s) $0"
    exit 1
  fi
fi

# Fail closed: everything below needs billing, and the failures without it are obscure.
if [[ -z "$(gcloud billing projects describe "${PROJECT_ID}" \
            --format='value(billingAccountName)' 2>/dev/null)" ]]; then
  echo "FAIL: no billing account linked to ${PROJECT_ID}."
  echo "      Link one, then re-run:"
  echo "        gcloud billing accounts list"
  echo "        gcloud billing projects link ${PROJECT_ID} --billing-account=<ACCOUNT_ID>"
  exit 1
fi

echo "--> enabling APIs (Cloud Run and Cloud Trace land with roadmap items 3 and 2)"
gcloud services enable aiplatform.googleapis.com firestore.googleapis.com \
  --project="${PROJECT_ID}"

if gcloud firestore databases describe --database='(default)' \
     --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "--> Firestore '(default)' already exists"
else
  echo "--> creating Firestore '(default)' (Native mode, ${REGION}) — location is permanent"
  gcloud firestore databases create --database='(default)' \
    --location="${REGION}" --type=firestore-native --project="${PROJECT_ID}"
fi

# An enabled API is not a servable model: ask each model for one token.
TOKEN="$(gcloud auth print-access-token)"
probe_ok=0
for model in gemini-3.5-pro gemini-3.5-flash; do
  status="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
    -d '{"contents":[{"role":"user","parts":[{"text":"ping"}]}],
         "generationConfig":{"maxOutputTokens":1}}' \
    "https://${REGION}-aiplatform.googleapis.com/v1/projects/${PROJECT_ID}/locations/${REGION}/publishers/google/models/${model}:generateContent")"
  if [[ "${status}" == "200" ]]; then
    echo "--> ${model}: OK"
  else
    echo "--> ${model}: FAIL (HTTP ${status}) — likely quota or model access, not this script"
    probe_ok=1
  fi
done

echo "==> done. Firestore ready in ${REGION}."
exit "${probe_ok}"
