#!/usr/bin/env bash
# Bibliothèque de journal de run (issue #40) — sourçable.
#
# Un « run » d'orchestration (/run-jalon) vit sous `.nickmare/runs/<run_id>/` :
#   - meta.json      : { run_id, milestone, started_at, max_parallel }
#   - journal.ndjson : une ligne JSON par événement de phase (append-only)
#
# Événement :
#   { "ts":"<ISO8601 UTC>", "run_id":"…", "ticket":N, "phase":"queued|dev|tests|
#     fix|qa|merge|done|blocked", "agent":"orchestrateur|dev-ticket|qa-ticket",
#     "pr":<n|null>, "detail":"…" }
#
# Le journal est **append-only** (jamais réécrit), dans le même esprit que le
# journal d'audit produit (docs/ARCHITECTURE.md §11). Le dashboard le lit en
# lecture seule. Aucun secret n'y est écrit.
#
# Variables d'environnement reconnues :
#   NM_RUNS_ROOT  racine des runs (défaut : <racine git>/.nickmare/runs)
#   NM_RUN_ID     run actif ciblé par nm_log_phase (défaut : le plus récent)
#
# Usage :
#   source scripts/lib/run-journal.sh
#   id=$(nm_run_init "Phase 0 — Fondations" 2)
#   nm_log_phase 12 dev --agent dev-ticket --detail "implémentation portscan"
#
# Cette bibliothèque ne pose pas `set -e` : elle n'altère pas les options du shell
# appelant. Les fonctions renvoient un statut non nul en cas d'erreur sans tuer
# l'appelant (fail-safe).

# Racine des runs : override explicite, sinon <racine git>/.nickmare/runs.
nm_runs_root() {
  if [ -n "${NM_RUNS_ROOT:-}" ]; then
    printf '%s' "$NM_RUNS_ROOT"
    return 0
  fi
  local top
  top=$(git rev-parse --show-toplevel 2>/dev/null) || top=$PWD
  printf '%s/.nickmare/runs' "$top"
}

# Horodatage ISO 8601 UTC à la seconde.
nm_now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Identifiant de run triable par ordre lexical (= chronologique).
nm__gen_run_id() { printf '%s-%04x' "$(date -u +%Y%m%dT%H%M%SZ)" "$((RANDOM))"; }

# Échappe une chaîne pour une valeur JSON (antislash, guillemet, sauts/tabs).
_nm_json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  s=${s//$'\r'/\\r}
  printf '%s' "$s"
}

# nm_run_init <milestone> [max_parallel] — crée le run, renvoie son run_id.
nm_run_init() {
  local milestone=${1:-} maxp=${2:-2}
  if [ -z "$milestone" ]; then
    echo "nm_run_init: milestone requis" >&2
    return 2
  fi
  case $maxp in ''|*[!0-9]*) maxp=2 ;; esac
  local root id dir
  root=$(nm_runs_root)
  id=${NM_RUN_ID:-$(nm__gen_run_id)}
  dir="$root/$id"
  mkdir -p "$dir" || { echo "nm_run_init: impossible de créer $dir" >&2; return 1; }
  printf '{"run_id":"%s","milestone":"%s","started_at":"%s","max_parallel":%s}\n' \
    "$(_nm_json_escape "$id")" "$(_nm_json_escape "$milestone")" "$(nm_now_iso)" "$maxp" \
    > "$dir/meta.json"
  : >> "$dir/journal.ndjson"
  printf '%s\n' "$id"
}

# nm_run_dir [run_id] — chemin du run ciblé (ou le plus récent). 1 si aucun.
nm_run_dir() {
  local id=${1:-${NM_RUN_ID:-}} root latest
  root=$(nm_runs_root)
  if [ -n "$id" ]; then
    if [ -d "$root/$id" ]; then printf '%s' "$root/$id"; return 0; fi
    return 1
  fi
  latest=$(ls -1d "$root"/*/ 2>/dev/null | sort | tail -n1)
  if [ -n "$latest" ]; then printf '%s' "${latest%/}"; return 0; fi
  return 1
}

# nm_log_phase <ticket> <phase> [--pr N] [--agent X] [--detail "…"]
# Ajoute une ligne NDJSON au journal du run actif (atomique : un seul write O_APPEND).
nm_log_phase() {
  local ticket=${1:-} phase=${2:-}
  if [ $# -lt 2 ]; then echo "nm_log_phase: <ticket> <phase> requis" >&2; return 2; fi
  shift 2
  local pr=null agent="" detail=""
  while [ $# -gt 0 ]; do
    case $1 in
      --pr)     pr=${2:-null}; shift 2 || return 2 ;;
      --agent)  agent=${2:-}; shift 2 || return 2 ;;
      --detail) detail=${2:-}; shift 2 || return 2 ;;
      *) shift ;;
    esac
  done
  case $ticket in ''|*[!0-9]*) echo "nm_log_phase: ticket numérique attendu" >&2; return 1 ;; esac
  case " queued dev tests fix qa merge done blocked " in
    *" $phase "*) ;;
    *) echo "nm_log_phase: phase inconnue « $phase »" >&2; return 1 ;;
  esac
  case $pr in ''|*[!0-9]*) pr=null ;; esac
  local dir
  dir=$(nm_run_dir) || { echo "nm_log_phase: aucun run actif (NM_RUN_ID ?)" >&2; return 1; }
  printf '{"ts":"%s","run_id":"%s","ticket":%s,"phase":"%s","agent":"%s","pr":%s,"detail":"%s"}\n' \
    "$(nm_now_iso)" "$(_nm_json_escape "$(basename "$dir")")" "$ticket" "$phase" \
    "$(_nm_json_escape "$agent")" "$pr" "$(_nm_json_escape "$detail")" \
    >> "$dir/journal.ndjson"
}
