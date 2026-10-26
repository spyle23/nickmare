#!/usr/bin/env bash
# Tests de scripts/run-dashboard.sh (issue #40). Aucun appel réseau ; rendu en
# mode --once (sans TTY, donc sans couleur) pour pouvoir vérifier le texte.
#
# Usage : bash .github/scripts/tests/run-dashboard.test.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DASH="$ROOT/scripts/run-dashboard.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export NM_RUNS_ROOT="$WORK/runs"
unset NM_RUN_ID NM_FORCE_COLOR

failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }

# Prépare un run avec un journal fabriqué à la main.
RID="20260101T120000Z-test"
RDIR="$NM_RUNS_ROOT/$RID"
mkdir -p "$RDIR"
printf '{"run_id":"%s","milestone":"Phase 0 — Fondations","started_at":"2026-01-01T12:00:00Z","max_parallel":2}\n' "$RID" > "$RDIR/meta.json"
cat > "$RDIR/journal.ndjson" <<'EOF'
{"ts":"2026-01-01T12:00:00Z","run_id":"r","ticket":1,"phase":"queued","agent":"orchestrateur","pr":null,"detail":"init"}
{"ts":"2026-01-01T12:01:00Z","run_id":"r","ticket":1,"phase":"dev","agent":"dev-ticket","pr":null,"detail":""}
{"ts":"2026-01-01T12:05:00Z","run_id":"r","ticket":1,"phase":"tests","agent":"dev-ticket","pr":55,"detail":""}
ligne corrompue à ignorer {pas du json}
{"ts":"2026-01-01T12:02:00Z","run_id":"r","ticket":2,"phase":"done","agent":"qa-ticket","pr":56,"detail":"fusionné"}
EOF

OUT="$WORK/out.txt"
bash "$DASH" "$RID" --once > "$OUT" 2>&1
st=$?
[ "$st" -eq 0 ] && pass "dashboard: --once sort proprement (statut 0)" || fail "dashboard: --once statut $st"

# Phase courante = dernier événement du ticket.
grep -qE '#1 .*TESTS' "$OUT" && pass "dashboard: #1 en phase TESTS (dernier événement)" || { fail "dashboard: #1 en phase TESTS"; cat "$OUT"; }
grep -qE '#2 .*DONE' "$OUT" && pass "dashboard: #2 en phase DONE" || fail "dashboard: #2 en phase DONE"

# La ligne corrompue n'a pas fait planter ni ajouté de ticket fantôme.
grep -qE '#1' "$OUT" && grep -qE '#2' "$OUT" && pass "dashboard: ligne corrompue ignorée, tickets rendus" || fail "dashboard: ligne corrompue ignorée"

# Progression done/total : 1 done sur 2 tickets.
grep -qE 'Progression: .*1/2' "$OUT" && pass "dashboard: progression 1/2" || { fail "dashboard: progression 1/2"; grep Progression "$OUT"; }

# PR rattachée affichée.
grep -q 'PR#55' "$OUT" && pass "dashboard: PR du ticket #1 affichée" || fail "dashboard: PR du ticket #1 affichée"

# Jalon dans l'en-tête.
grep -q 'Phase 0 — Fondations' "$OUT" && pass "dashboard: jalon dans l'en-tête" || fail "dashboard: jalon dans l'en-tête"

# Résolution par chemin de journal explicite.
bash "$DASH" "$RDIR/journal.ndjson" --once > "$OUT" 2>&1
grep -qE '#1 .*TESTS' "$OUT" && pass "dashboard: résolution par chemin de journal" || fail "dashboard: résolution par chemin de journal"

# Résolution « plus récent » sans argument.
bash "$DASH" --once > "$OUT" 2>&1
grep -qE '#1 .*TESTS' "$OUT" && pass "dashboard: résolution du run le plus récent" || fail "dashboard: résolution du run le plus récent"

# Run inexistant → message + sortie 0 (fail-safe).
(
  export NM_RUNS_ROOT="$WORK/vide"; mkdir -p "$NM_RUNS_ROOT"
  bash "$DASH" --once > "$WORK/empty.txt" 2>&1
  st=$?
  [ "$st" -eq 0 ] || exit 1
  grep -qi 'aucun run' "$WORK/empty.txt" || exit 1
) && pass "dashboard: run inexistant → message + statut 0" || fail "dashboard: run inexistant → message + statut 0"

# Titre court depuis titles.tsv.
printf '1\tPhase 0 · core::model\n' > "$RDIR/titles.tsv"
bash "$DASH" "$RID" --once > "$OUT" 2>&1
grep -q 'core::model' "$OUT" && pass "dashboard: titre depuis titles.tsv" || fail "dashboard: titre depuis titles.tsv"

echo
if [ "$failures" -eq 0 ]; then echo "Tous les tests passent."; else echo "$failures test(s) en échec."; exit 1; fi
