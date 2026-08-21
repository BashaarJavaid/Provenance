#!/usr/bin/env bash
# A $300 Cloud Billing budget with alerts at 50/90/100%, scoped to this project.
# Alerts notify; they do not stop spend. The spend guardrails are the deploy
# rules in CLAUDE.md's "Cost ceiling" section. Idempotent.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-provenance-hackathon}"
DISPLAY_NAME="Provenance trial credit"

BILLING_ACCOUNT="$(gcloud billing projects describe "${PROJECT_ID}" \
  --format='value(billingAccountName)' | sed 's|billingAccounts/||')"
if [[ -z "${BILLING_ACCOUNT}" ]]; then
  echo "FAIL: no billing account linked to ${PROJECT_ID}."
  exit 1
fi

PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"

gcloud services enable billingbudgets.googleapis.com --project="${PROJECT_ID}"

# --billing-project: the budgets API goes through ADC, which has no quota project.
if gcloud billing budgets list --billing-account="${BILLING_ACCOUNT}" \
     --billing-project="${PROJECT_ID}" \
     --format='value(displayName)' 2>/dev/null | grep -qx "${DISPLAY_NAME}"; then
  echo "--> budget '${DISPLAY_NAME}' already exists"
  exit 0
fi

gcloud billing budgets create \
  --billing-account="${BILLING_ACCOUNT}" \
  --billing-project="${PROJECT_ID}" \
  --display-name="${DISPLAY_NAME}" \
  --budget-amount=300USD \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0 \
  --filter-projects="projects/${PROJECT_NUMBER}"

echo "==> budget set. Alerts go to the billing account's admins."
