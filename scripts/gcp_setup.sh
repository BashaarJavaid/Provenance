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

echo "--> enabling APIs"
# cloudtrace: the one trace stream (roadmap item 2). Ingestion is free to 2.5M spans/month
# and nothing here bills while idle, so it costs nothing against the $300 ceiling.
# run/cloudbuild/artifactregistry: what `./scripts/deploy.sh` needs (roadmap item 3).
# Cloud Run at min-instances=0 bills nothing idle; Cloud Build minutes are free-tier here.
gcloud services enable aiplatform.googleapis.com firestore.googleapis.com \
  cloudtrace.googleapis.com run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com --project="${PROJECT_ID}"

# `gcloud run deploy --source` builds as the Compute Engine default service account, which
# on a project created after mid-2024 has no build permissions and fails after the source
# upload with an opaque PERMISSION_DENIED. add-iam-policy-binding is a no-op if already set.
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
echo "--> granting the Cloud Build role to ${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role='roles/cloudbuild.builds.builder' --condition=None --quiet >/dev/null

# The same account is the Cloud Run *runtime* identity, and from ROADMAP item 5 the
# service reads the agent registry from Firestore on every authorization (ARCHITECTURE
# §1.1 property 4). Without this the registry read fails closed in production and every
# proposal is denied. datastore.user is read+write on Firestore Native; there is no
# narrower predefined role that still permits the standing write.
echo "--> granting the Firestore role to ${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role='roles/datastore.user' --condition=None --quiet >/dev/null

if gcloud firestore databases describe --database='(default)' \
     --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "--> Firestore '(default)' already exists"
else
  echo "--> creating Firestore '(default)' (Native mode, ${REGION}) — location is permanent"
  gcloud firestore databases create --database='(default)' \
    --location="${REGION}" --type=firestore-native --project="${PROJECT_ID}"
fi

# An enabled API is not a servable model: ask each model for one token.
# Gemini 3.x is served from the `global` endpoint, not a regional one — a regional
# probe 404s on models that are in fact available. gemini-3.5-pro is not served to
# this project at all, so the reasoning roles run on 2.5 Pro (ROADMAP item 1).
TOKEN="$(gcloud auth print-access-token)"
probe_ok=0
for model in gemini-2.5-pro gemini-3.5-flash; do
  status="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
    -d '{"contents":[{"role":"user","parts":[{"text":"ping"}]}],
         "generationConfig":{"maxOutputTokens":1}}' \
    "https://aiplatform.googleapis.com/v1/projects/${PROJECT_ID}/locations/global/publishers/google/models/${model}:generateContent")"
  if [[ "${status}" == "200" ]]; then
    echo "--> ${model}: OK"
  else
    echo "--> ${model}: FAIL (HTTP ${status}) — likely quota or model access, not this script"
    probe_ok=1
  fi
done

echo "==> done. Firestore ready in ${REGION}."
exit "${probe_ok}"
