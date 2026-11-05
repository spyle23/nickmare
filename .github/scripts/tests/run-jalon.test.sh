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
{ echo "RUNS_ROOT=\${NM_RUNS_ROOT:-}"; echo "RUN_ID=\${NM_RUN_ID:-}"; } > "$WORK/env.log"
exit 0
EOF
cat > "$WORK/bin/dashboard" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "$WORK/dashboard.log"
exit 0
EOF
cat > "$WORK/bin/supervise" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "$WORK/supervise.log"
exit 0
EOF
chmod +x "$WORK/bin/claude" "$WORK/bin/dashboard" "$WORK/bin/supervise"

run_launch() {
  : > "$WORK/claude.log"; : > "$WORK/dashboard.log"; : > "$WORK/supervise.log"
  NM_RUNS_ROOT="$WORK/runs" \
  NM_CLAUDE_CMD="$WORK/bin/claude" \
  NM_DASHBOARD_CMD="$WORK/bin/dashboard" \
  NM_SUPERVISE_CMD="$WORK/bin/supervise" \
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

# --- --no-dashboard (run autorisé) -------------------------------------------
rm -rf "$WORK/runs"
run_launch --authorize --no-dashboard "Phase 0 — Fondations"
grep -q 'Phase 0 — Fondations' "$WORK/claude.log" && ! grep -q -- '--dry-run' "$WORK/claude.log" \
  && pass "no-dashboard: orchestrateur appelé sans --dry-run" || fail "no-dashboard: orchestrateur appelé sans --dry-run"
[ ! -s "$WORK/dashboard.log" ] && pass "no-dashboard: dashboard NON ouvert" || fail "no-dashboard: dashboard NON ouvert"

# --- porte unique : sans --authorize, plan seul (fail-safe) -------------------
rm -rf "$WORK/runs"
run_launch "Phase 0 — Fondations"
st=$?
[ "$st" -eq 0 ] && pass "sans autorisation: statut 0" || fail "sans autorisation: statut $st"
grep -q -- '--dry-run' "$WORK/claude.log" && pass "sans autorisation: orchestrateur forcé en --dry-run" \
  || fail "sans autorisation: orchestrateur forcé en --dry-run"
! grep -q -- '--authorize' "$WORK/claude.log" && pass "sans autorisation: --authorize NON transmis" \
  || fail "sans autorisation: --authorize NON transmis"
[ ! -s "$WORK/dashboard.log" ] && pass "sans autorisation: dashboard NON ouvert" \
  || fail "sans autorisation: dashboard NON ouvert"
grep -q -- '--authorize' "$WORK/out.txt" && pass "sans autorisation: message indique --authorize" \
  || fail "sans autorisation: message indique --authorize"

# --- porte unique : --authorize transmis, pas de --dry-run ---------------------
rm -rf "$WORK/runs"
run_launch --authorize --no-dashboard "Phase 0 — Fondations"
grep -q -- '--authorize' "$WORK/claude.log" && pass "autorisé: --authorize transmis" \
  || fail "autorisé: --authorize transmis"
! grep -q -- '--dry-run' "$WORK/claude.log" && pass "autorisé: pas de --dry-run" \
  || fail "autorisé: pas de --dry-run"

# --- porte unique : alias --yes ------------------------------------------------
rm -rf "$WORK/runs"
run_launch --yes --no-dashboard "Phase 0 — Fondations"
grep -q -- '--authorize' "$WORK/claude.log" && ! grep -q -- '--dry-run' "$WORK/claude.log" \
  && pass "alias --yes: équivaut à --authorize" || fail "alias --yes: équivaut à --authorize"

# --- porte unique : --dry-run l'emporte sur --authorize ------------------------
rm -rf "$WORK/runs"
run_launch --dry-run --authorize "Phase 0 — Fondations"
grep -q -- '--dry-run' "$WORK/claude.log" && pass "dry-run + authorize: reste un plan" \
  || fail "dry-run + authorize: reste un plan"
[ ! -s "$WORK/dashboard.log" ] && pass "dry-run + authorize: dashboard NON ouvert" \
  || fail "dry-run + authorize: dashboard NON ouvert"

# --- --supervise (run autorisé) : lance le superviseur, pas l'orchestrateur ----
rm -rf "$WORK/runs"
run_launch --authorize --supervise --no-dashboard "Phase 0 — Fondations"
grep -q 'Phase 0 — Fondations' "$WORK/supervise.log" && pass "supervise: superviseur appelé avec le jalon" \
  || fail "supervise: superviseur appelé avec le jalon"
grep -q -- '--authorize' "$WORK/supervise.log" && pass "supervise: --authorize transmis au superviseur" \
  || fail "supervise: --authorize transmis au superviseur"
grep -q -- '--max-parallel 2' "$WORK/supervise.log" && pass "supervise: --max-parallel transmis" \
  || fail "supervise: --max-parallel transmis"
[ ! -s "$WORK/claude.log" ] && pass "supervise: orchestrateur NON appelé directement" \
  || fail "supervise: orchestrateur NON appelé directement"
[ ! -s "$WORK/dashboard.log" ] && pass "supervise: dashboard NON ouvert (--no-dashboard)" \
  || fail "supervise: dashboard NON ouvert (--no-dashboard)"

# --- --supervise SANS --authorize : plan seul, superviseur NON lancé -----------
rm -rf "$WORK/runs"
run_launch --supervise --no-dashboard "Phase 0 — Fondations"
[ ! -s "$WORK/supervise.log" ] && pass "supervise sans autorisation: superviseur NON lancé" \
  || fail "supervise sans autorisation: superviseur NON lancé"
grep -q -- '--dry-run' "$WORK/claude.log" && pass "supervise sans autorisation: plan via orchestrateur" \
  || fail "supervise sans autorisation: plan via orchestrateur"

# --- NM_RUNS_ROOT résolu et exporté vers l'orchestrateur (agents en worktree) --
# Sans NM_RUNS_ROOT hérité : le lanceur doit résoudre la racine lui-même (dépôt
# git courant) et l'exporter, pour que les agents en worktree écrivent au même
# endroit que le dashboard.
REPO="$WORK/depot"
mkdir -p "$REPO" && git -C "$REPO" init -q && git -C "$REPO" -c user.email=t@t -c user.name=t \
  commit -q --allow-empty -m init
: > "$WORK/claude.log"; : > "$WORK/env.log"
( cd "$REPO" && env -u NM_RUNS_ROOT NM_CLAUDE_CMD="$WORK/bin/claude" \
    NM_DASHBOARD_CMD="$WORK/bin/dashboard" NM_SKIP_TITLES=1 \
    bash "$LAUNCH" --authorize --no-dashboard "Phase 0 — Fondations" > "$WORK/out.txt" 2>&1 )
exported=$(sed -n 's/^RUNS_ROOT=//p' "$WORK/env.log")
run_id=$(sed -n 's/^RUN_ID=//p' "$WORK/env.log")
[ -n "$exported" ] && [ -f "$exported/$run_id/meta.json" ] \
  && pass "NM_RUNS_ROOT résolu et exporté à l'orchestrateur" \
  || fail "NM_RUNS_ROOT résolu et exporté à l'orchestrateur (RUNS_ROOT='$exported', RUN_ID='$run_id')"
[ -n "$run_id" ] && pass "NM_RUN_ID exporté à l'orchestrateur" || fail "NM_RUN_ID exporté à l'orchestrateur"

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

# --- autorisé avec dashboard : le dashboard est ouvert ------------------------
# En dernier : l'orchestrateur tourne alors en arrière-plan et pourrait écrire
# dans claude.log après le début d'un test suivant.
rm -rf "$WORK/runs"
run_launch --authorize "Phase 0 — Fondations"
[ -s "$WORK/dashboard.log" ] && pass "autorisé: dashboard ouvert" || fail "autorisé: dashboard ouvert"

echo
if [ "$failures" -eq 0 ]; then echo "Tous les tests passent."; else echo "$failures test(s) en échec."; exit 1; fi
