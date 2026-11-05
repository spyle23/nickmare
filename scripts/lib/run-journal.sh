#!/usr/bin/env bash
# Shim de compatibilité — l'implémentation du journal de run est désormais en
# Python (scripts/run_journal.py). Ce fichier reste **sourçable** pour que le
# lanceur (scripts/run-jalon.sh) et les agents (.claude/*) continuent d'appeler
# nm_run_init / nm_run_dir / nm_log_phase / nm_runs_root sans aucun changement.
#
#   source scripts/lib/run-journal.sh
#   id=$(nm_run_init "Phase 0 — Fondations" 2)
#   nm_log_phase 12 dev --agent dev-ticket --detail "implémentation portscan"
#
# Contrat inchangé : .nickmare/runs/<id>/{meta.json,journal.ndjson}, append-only,
# variables NM_RUNS_ROOT / NM_RUN_ID respectées (lues côté Python).
#
# Interpréteur : $NM_PYTHON si défini, sinon le premier de python3 / python / py.
# Fail-safe : si aucun Python n'est trouvé, les fonctions renvoient un statut non
# nul sans tuer le shell appelant (la journalisation est best-effort).

_nm__journal_py="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/run_journal.py"

_nm_python() {
  if [ -n "${NM_PYTHON:-}" ]; then printf '%s' "$NM_PYTHON"; return 0; fi
  local cand
  for cand in python3 python py; do
    if command -v "$cand" >/dev/null 2>&1; then printf '%s' "$cand"; return 0; fi
  done
  echo "run-journal.sh: aucun interpréteur Python (python3/python/py) trouvé" >&2
  return 1
}

_nm_journal() {
  local py
  py=$(_nm_python) || return 1
  "$py" "$_nm__journal_py" "$@"
}

nm_runs_root() { _nm_journal root "$@"; }
nm_run_init()  { _nm_journal init "$@"; }
nm_run_dir()   { _nm_journal dir "$@"; }
nm_log_phase() { _nm_journal log "$@"; }

# Contrôle du run (issue #48) : pause / arrêt / quota et point de contrôle `gate`.
# `nm_gate` renvoie le code de sortie de la décision (0 continuer · 1 pause · 2
# arrêt · 3 plus rien à faire · 4 quota épuisé) : l'orchestrateur l'appelle avant
# chaque lot et applique le code. Les autres délèguent tel quel au Python.
nm_pause()   { _nm_journal pause "$@"; }
nm_unpause() { _nm_journal unpause "$@"; }
nm_stop()    { _nm_journal stop "$@"; }
nm_status()  { _nm_journal status "$@"; }
nm_gate()    { _nm_journal gate "$@"; }
nm_quota()   { _nm_journal quota "$@"; }

# Horodatage ISO 8601 UTC — conservé pour d'éventuels appelants historiques.
nm_now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
