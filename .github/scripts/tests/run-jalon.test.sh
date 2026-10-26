#!/usr/bin/env bash
# Tests de scripts/run-jalon.sh (issue #40). Aucun appel réseau : `claude`, le
# dashboard et `gh` sont bouchonnés via NM_*_CMD.
#
# Usage : bash .github/scripts/tests/run-jalon.test.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
LAUNCH="$ROOT/scripts/run-jalon.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }

# Bouchons : journalisent leurs invocations.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/claude" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "$WORK/claude.log"
exit 0
EOF
cat > "$WORK/bin/dashboard" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "$WORK/dashboard.log"
exit 0
EOF
chmod +x "$WORK/bin/claude" "$WORK/bin/dashboard"

run_launch() {
  : > "$WORK/claude.log"; : > "$WORK/dashboard.log"
  NM_RUNS_ROOT="$WORK/runs" \
  NM_CLAUDE_CMD="$WORK/bin/claude" \
  NM_DASHBOARD_CMD="$WORK/bin/dashboard" \
  NM_SKIP_TITLES=1 \
    bash "$LAUNCH" "$@" > "$WORK/out.txt" 2>&1
}
latest_meta() { cat "$NM_RUNS_ROOT_LAST"/runs/*/meta.json 2>/dev/null; }

# --- --dry-run ----------------------------------------------------------------
rm -rf "$WORK/runs"
run_launch --dry-run "Phase 0 — Fondations"
st=$?
[ "$st" -eq 0 ] && pass "dry-run: statut 0" || fail "dry-run: statut $st"
meta=$(cat "$WORK"/runs/*/meta.json 2>/dev/null)
echo "$meta" | grep -q '"milestone":"Phase 0 — Fondations"' && pass "dry-run: meta.json avec le bon jalon" || fail "dry-run: meta.json avec le bon jalon"
[ -f "$(echo "$WORK"/runs/*/journal.ndjson)" ] && pass "dry-run: journal.ndjson créé" || fail "dry-run: journal.ndjson créé"
grep -q -- '--dry-run' "$WORK/claude.log" && pass "dry-run: orchestrateur appelé avec --dry-run" || fail "dry-run: orchestrateur appelé avec --dry-run"
grep -q 'Phase 0 — Fondations' "$WORK/claude.log" && pass "dry-run: jalon transmis à l'orchestrateur" || fail "dry-run: jalon transmis"
[ ! -s "$WORK/dashboard.log" ] && pass "dry-run: dashboard NON ouvert" || fail "dry-run: dashboard NON ouvert"

# --- --no-dashboard -----------------------------------------------------------
rm -rf "$WORK/runs"
run_launch --no-dashboard "Phase 0 — Fondations"
grep -q 'Phase 0 — Fondations' "$WORK/claude.log" && ! grep -q -- '--dry-run' "$WORK/claude.log" \
  && pass "no-dashboard: orchestrateur appelé sans --dry-run" || fail "no-dashboard: orchestrateur appelé sans --dry-run"
[ ! -s "$WORK/dashboard.log" ] && pass "no-dashboard: dashboard NON ouvert" || fail "no-dashboard: dashboard NON ouvert"

# --- --max-parallel transmis --------------------------------------------------
rm -rf "$WORK/runs"
run_launch --dry-run --max-parallel 3 "Phase 1 — Recon, cartographie & cible"
grep -q -- '--max-parallel 3' "$WORK/claude.log" && pass "max-parallel: valeur transmise" || fail "max-parallel: valeur transmise"
cat "$WORK"/runs/*/meta.json | grep -q '"max_parallel":3' && pass "max-parallel: dans meta.json" || fail "max-parallel: dans meta.json"

# --- jalon à espaces préservé -------------------------------------------------
rm -rf "$WORK/runs"
run_launch --dry-run "Transverse — Sûreté, sécurité & docs"
cat "$WORK"/runs/*/meta.json | grep -q '"milestone":"Transverse — Sûreté, sécurité & docs"' \
  && pass "jalon à espaces: titre complet préservé" || fail "jalon à espaces: titre complet préservé"

# --- jalon manquant → erreur --------------------------------------------------
rm -rf "$WORK/runs"
run_launch --dry-run
[ "$?" -ne 0 ] && pass "jalon manquant → statut non nul" || fail "jalon manquant → statut non nul"

# --- claude introuvable → fail-safe -------------------------------------------
rm -rf "$WORK/runs"
: > "$WORK/claude.log"; : > "$WORK/dashboard.log"
NM_RUNS_ROOT="$WORK/runs" NM_CLAUDE_CMD="$WORK/bin/nexiste-pas" \
  NM_DASHBOARD_CMD="$WORK/bin/dashboard" NM_SKIP_TITLES=1 \
  bash "$LAUNCH" "Phase 0 — Fondations" > "$WORK/out.txt" 2>&1
[ "$?" -ne 0 ] && pass "claude introuvable → statut non nul" || fail "claude introuvable → statut non nul"

echo
if [ "$failures" -eq 0 ]; then echo "Tous les tests passent."; else echo "$failures test(s) en échec."; exit 1; fi
