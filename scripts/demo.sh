#!/usr/bin/env bash
# Walks through the reference scenarios against a seeded control plane.
#
#   make dev-db && make migrate && make seed && ./scripts/demo.sh
#
# Each case names the policy that decided it. Read the "produced" line: that is
# the control plane explaining itself.

set -euo pipefail
cd "$(dirname "$0")/.."

CPCTL="${CPCTL:-.venv/bin/cpctl}"
export COLUMNS="${COLUMNS:-100}"

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }

bold "1. A reviewed agent reads the knowledge base"
echo "   Expect ALLOW. The SSN is masked; the email is pseudonymised, so the"
echo "   same customer stays recognisable across a conversation."
$CPCTL decide --principal agent:support_bot --principal-type agent --action read \
  --resource qdrant://kb_docs \
  --payload "Customer jane.doe@acme.com (SSN 536-90-4432) asks about refunds."

bold "2. The same agent sends health data to an external model"
echo "   Expect DENY, from a policy that outranks the everyday grant."
$CPCTL decide --principal agent:support_bot --principal-type agent --action infer \
  --resource pg://clinical.encounters --destination external

bold "3. A table nobody registered, under a schema that was"
echo "   Expect DENY. pg://clinical.* classifies everything beneath it, so"
echo "   forgetting to register a table does not create a gap."
$CPCTL decide --principal agent:analytics_copilot --principal-type agent --action infer \
  --resource pg://clinical.lab_results_2026 --destination external

bold "4. A credential in the payload"
echo "   Expect DENY, whoever is asking. This rule has no exception path."
$CPCTL decide --principal user:analyst --principal-type user --action read \
  --resource qdrant://kb_docs --payload "deploy with AKIAIOSFODNN7EXAMPLE"

bold "5. A cleared analyst reads the real values"
echo "   Expect ALLOW, unredacted. Redaction has a cost, and an analyst"
echo "   investigating one customer cannot work against hashes."
$CPCTL decide --principal user:analyst --principal-type user --action read \
  --resource pg://public.customers --payload "jane.doe@acme.com"

bold "6. The same analyst exports the whole table"
echo "   Expect REQUIRE_APPROVAL. Legitimate, and also what exfiltration"
echo "   looks like; a human makes the two distinguishable afterwards."
$CPCTL decide --principal user:analyst --principal-type user --action export \
  --resource pg://public.customers

bold "7. Something nobody wrote a rule for"
echo "   Expect DENY by default. Nothing is permitted implicitly."
$CPCTL decide --principal agent:nobody --principal-type agent --action drop_table \
  --resource pg://public.customers

bold "8. The audit trail"
echo "   Every decision above is sealed into a hash chain. Recompute it:"
$CPCTL audit verify
$CPCTL audit tail --limit 8
