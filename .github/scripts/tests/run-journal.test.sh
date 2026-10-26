#!/usr/bin/env bash
# Tests de scripts/lib/run-journal.sh (issue #40). Aucun appel réseau.
#
# Usage : bash .github/scripts/tests/run-journal.test.sh

set -uo pipefail

LIB="$(cd "$(dirname "$0")/../../.." && pwd)/scripts/lib/run-journal.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export NM_RUNS_ROOT="$WORK/runs"
unset NM_RUN_ID

# shellcheck source=scripts/lib/run-journal.sh
. "$LIB"

failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (attendu « $3 », obtenu « $2 »)"; fi; }

# --- nm_run_init --------------------------------------------------------------
id=$(nm_run_init "Phase 0 — Fondations" 2)
dir="$NM_RUNS_ROOT/$id"
[ -d "$dir" ] && pass "run_init: dossier créé" || fail "run_init: dossier créé"
[ -f "$dir/meta.json" ] && pass "run_init: meta.json créé" || fail "run_init: meta.json créé"
[ -f "$dir/journal.ndjson" ] && pass "run_init: journal créé" || fail "run_init: journal créé"
grep -q '"milestone":"Phase 0 — Fondations"' "$dir/meta.json" && pass "run_init: milestone dans meta" || fail "run_init: milestone dans meta"
grep -q '"max_parallel":2' "$dir/meta.json" && pass "run_init: max_parallel dans meta" || fail "run_init: max_parallel dans meta"

# --- nm_log_phase -------------------------------------------------------------
NM_RUN_ID="$id"
nm_log_phase 12 queued --agent orchestrateur --detail "en attente"
nm_log_phase 12 dev --agent dev-ticket
nm_log_phase 12 tests --agent dev-ticket --pr 77
lines=$(wc -l < "$dir/journal.ndjson" | tr -d ' ')
check "log_phase: 3 lignes écrites" "$lines" "3"
grep -q '"ticket":12' "$dir/journal.ndjson" && pass "log_phase: ticket présent" || fail "log_phase: ticket présent"
grep -q '"phase":"tests"' "$dir/journal.ndjson" && pass "log_phase: phase présente" || fail "log_phase: phase présente"
grep -q '"pr":77' "$dir/journal.ndjson" && pass "log_phase: pr numérique" || fail "log_phase: pr numérique"
grep -q '"pr":null' "$dir/journal.ndjson" && pass "log_phase: pr null par défaut" || fail "log_phase: pr null par défaut"

# Échappement JSON du detail (guillemet).
nm_log_phase 13 dev --detail 'say "hi"'
grep -q '\\"hi\\"' "$dir/journal.ndjson" && pass "log_phase: detail échappé" || fail "log_phase: detail échappé"

# Phase inconnue → rejetée, pas d'écriture.
before=$(wc -l < "$dir/journal.ndjson" | tr -d ' ')
nm_log_phase 14 wizz 2>/dev/null && fail "log_phase: phase inconnue rejetée (statut)" || pass "log_phase: phase inconnue rejetée (statut)"
after=$(wc -l < "$dir/journal.ndjson" | tr -d ' ')
check "log_phase: phase inconnue n'écrit rien" "$after" "$before"

# Ticket non numérique → rejeté.
nm_log_phase abc dev 2>/dev/null && fail "log_phase: ticket non numérique rejeté" || pass "log_phase: ticket non numérique rejeté"

# --- NDJSON valide (si jq dispo) ---------------------------------------------
if command -v jq >/dev/null 2>&1; then
  if jq -e . "$dir/journal.ndjson" >/dev/null 2>&1; then pass "journal: NDJSON valide (jq)"; else fail "journal: NDJSON valide (jq)"; fi
else
  echo "skip - jq absent, validation NDJSON ignorée"
fi

# --- nm_run_dir : résolution du plus récent (racine isolée) -------------------
(
  export NM_RUNS_ROOT="$WORK/runs-order"
  unset NM_RUN_ID
  NM_RUN_ID="20260101T000000Z-aaaa" nm_run_init "Jalon A" >/dev/null
  NM_RUN_ID="20260101T000001Z-bbbb" nm_run_init "Jalon B" >/dev/null
  latest=$(basename "$(nm_run_dir)")
  [ "$latest" = "20260101T000001Z-bbbb" ] || { echo "latest=$latest"; exit 1; }
  got=$(basename "$(nm_run_dir "20260101T000000Z-aaaa")")
  [ "$got" = "20260101T000000Z-aaaa" ] || { echo "explicit=$got"; exit 1; }
  nm_run_dir "nexiste-pas" >/dev/null 2>&1 && exit 1
  exit 0
) && pass "run_dir: plus récent / explicite / inexistant" || fail "run_dir: plus récent / explicite / inexistant"

# --- Fail-safe : aucun run → nm_log_phase échoue sans planter -----------------
(
  export NM_RUNS_ROOT="$WORK/vide"
  mkdir -p "$NM_RUNS_ROOT"
  unset NM_RUN_ID
  nm_log_phase 1 dev 2>/dev/null && exit 1 || exit 0
) && pass "log_phase: aucun run → échec propre" || fail "log_phase: aucun run → échec propre"

echo
if [ "$failures" -eq 0 ]; then echo "Tous les tests passent."; else echo "$failures test(s) en échec."; exit 1; fi
