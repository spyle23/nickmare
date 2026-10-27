#!/usr/bin/env bash
# Shim de compatibilité — le dashboard de suivi est désormais en Python
# (scripts/run_dashboard.py). Ce fichier reste l'entrée par défaut utilisée par
# le lanceur (NM_DASHBOARD_CMD) et par l'habitude `scripts/run-dashboard.sh`.
#
# Tu peux aussi le lancer directement, sans Git Bash (ex. dans PowerShell) :
#   python scripts/run_dashboard.py [<run_id|chemin journal>] [--once] [--interval N]
#
# Interpréteur : $NM_PYTHON si défini, sinon le premier de python3 / python / py.

set -uo pipefail

_nm_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_nm_python() {
  if [ -n "${NM_PYTHON:-}" ]; then printf '%s' "$NM_PYTHON"; return 0; fi
  local cand
  for cand in python3 python py; do
    if command -v "$cand" >/dev/null 2>&1; then printf '%s' "$cand"; return 0; fi
  done
  echo "run-dashboard.sh: aucun interpréteur Python (python3/python/py) trouvé" >&2
  return 1
}

py=$(_nm_python) || exit 1
exec "$py" "$_nm_here/run_dashboard.py" "$@"
