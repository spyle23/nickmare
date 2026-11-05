#!/usr/bin/env bash
# Lanceur de run de jalon (issue #40).
#
# Initialise un run observable (dossier .nickmare/runs/<id>/ : meta.json +
# journal.ndjson), lance l'orchestrateur Claude Code `/run-jalon`, et ouvre le
# dashboard live sur ce run.
#
# Usage :
#   scripts/run-jalon.sh "<titre du jalon>" [--authorize] [--supervise] [--max-parallel N] [--dry-run] [--no-dashboard]
#
#   --authorize       autorisation humaine groupée (porte unique) : SANS ce drapeau, le run
#                     n'affiche que le plan et s'arrête. AVEC, l'orchestrateur enchaîne tous les
#                     tickets du jalon en autonomie (y compris type:security / prio:P0), sans
#                     redemander ticket par ticket. Alias : --yes.
#   --supervise       lance le SUPERVISEUR (scripts/run_supervise.py) au lieu d'un seul appel
#                     orchestrateur : il enchaîne « un lot par appel », détecte la limite d'usage
#                     Claude (quota), attend la réouverture de la fenêtre et relance (issue #49).
#                     Exige --authorize (sinon plan seul, comme sans autorisation).
#   --max-parallel N  agents dev simultanés (transmis à /run-jalon, défaut 2)
#   --dry-run         affiche le plan (aucun agent lancé, dashboard non ouvert)
#   --no-dashboard    lance le run sans ouvrir le dashboard
#
# Le lanceur ne merge RIEN et ne force aucune fusion : le merge reste piloté par
# le label `auto-merge` + CI verte (cf. docs/WORKFLOW_TICKETS.md). Fail-safe : il
# refuse de démarrer si `claude` est introuvable.
#
# Variables d'environnement (surtout pour les tests) :
#   NM_CLAUDE_CMD      commande de l'orchestrateur (défaut : claude)
#   NM_DASHBOARD_CMD   commande du dashboard (défaut : scripts/run-dashboard.sh)
#   NM_SUPERVISE_CMD   commande du superviseur (défaut : python scripts/run_supervise.py)
#   NM_GH_CMD          commande gh pour les titres (défaut : gh)
#   NM_SKIP_TITLES=1   n'essaie pas de récupérer les titres d'issues

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/run-journal.sh
. "$HERE/lib/run-journal.sh"

CLAUDE_CMD=${NM_CLAUDE_CMD:-claude}
DASHBOARD_CMD=${NM_DASHBOARD_CMD:-"$HERE/run-dashboard.sh"}
GH_CMD=${NM_GH_CMD:-gh}

usage() { sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

DRY_RUN=0
AUTHORIZE=0
NO_DASHBOARD=0
SUPERVISE=0
MAX_PARALLEL=2
MILESTONE=""

while [ $# -gt 0 ]; do
  case $1 in
    --dry-run)         DRY_RUN=1; shift ;;
    --authorize|--yes) AUTHORIZE=1; shift ;;
    --supervise)     SUPERVISE=1; shift ;;
    --no-dashboard)  NO_DASHBOARD=1; shift ;;
    --max-parallel)  MAX_PARALLEL=${2:-2}; shift 2 ;;
    -h|--help)       usage; exit 0 ;;
    --)              shift; while [ $# -gt 0 ]; do MILESTONE="${MILESTONE:+$MILESTONE }$1"; shift; done ;;
    -*)              echo "option inconnue : $1" >&2; shift ;;
    *)               MILESTONE="${MILESTONE:+$MILESTONE }$1"; shift ;;
  esac
done
case $MAX_PARALLEL in ''|*[!0-9]*) MAX_PARALLEL=2 ;; esac

if [ -z "$MILESTONE" ]; then
  echo "Erreur : titre de jalon manquant." >&2
  usage >&2
  exit 2
fi

if ! command -v "$CLAUDE_CMD" >/dev/null 2>&1; then
  echo "Erreur : commande orchestrateur introuvable : $CLAUDE_CMD" >&2
  echo "(installe Claude Code, ou définis NM_CLAUDE_CMD)" >&2
  exit 1
fi

RUN_ID=$(nm_run_init "$MILESTONE" "$MAX_PARALLEL") || { echo "Échec de l'initialisation du run." >&2; exit 1; }
RUN_DIR=$(nm_run_dir "$RUN_ID")
# NM_RUNS_ROOT résolu une fois ici et exporté : les agents dev/QA tournent dans
# des worktrees, et doivent écrire dans le journal que lit le dashboard (#47).
RUNS_ROOT=$(nm_runs_root) || RUNS_ROOT=""
export NM_RUN_ID="$RUN_ID" NM_RUN_DIR="$RUN_DIR"
[ -n "$RUNS_ROOT" ] && export NM_RUNS_ROOT="$RUNS_ROOT"

echo "Run initialisé : $RUN_ID"
echo "  jalon   : $MILESTONE"
echo "  dossier : $RUN_DIR"

# Titres d'issues (best-effort, jamais bloquant) — ignoré en dry-run.
if [ "$DRY_RUN" = 0 ] && [ "${NM_SKIP_TITLES:-}" != 1 ] && command -v "$GH_CMD" >/dev/null 2>&1; then
  "$GH_CMD" issue list --milestone "$MILESTONE" --state all --limit 200 \
    --json number,title -q '.[] | "\(.number)\t\(.title)"' > "$RUN_DIR/titles.tsv" 2>/dev/null || true
fi

# Porte unique : sans autorisation humaine explicite (--authorize), on se limite au plan.
# L'orchestrateur `-p` est non interactif ; le drapeau EST l'accord humain (fail-safe).
if [ "$DRY_RUN" = 0 ] && [ "$AUTHORIZE" = 0 ]; then
  echo "Aucune autorisation (--authorize) : affichage du plan uniquement, aucun agent lancé." >&2
  echo "Pour exécuter le jalon en autonomie, relance avec --authorize." >&2
  DRY_RUN=1
fi

# Commande d'orchestration.
PROMPT="/run-jalon \"$MILESTONE\" --max-parallel $MAX_PARALLEL"
[ "$DRY_RUN" = 1 ] && PROMPT="$PROMPT --dry-run"
[ "$AUTHORIZE" = 1 ] && PROMPT="$PROMPT --authorize"

if [ "$DRY_RUN" = 1 ]; then
  echo "Mode --dry-run : affichage du plan, aucun effet de bord d'orchestration."
  "$CLAUDE_CMD" -p "$PROMPT"
  exit $?
fi

# Mode superviseur (issue #49) : au lieu d'un unique appel orchestrateur, on lance
# scripts/run_supervise.py, qui enchaîne « un lot par appel », détecte la limite
# d'usage Claude, attend la réouverture de la fenêtre et relance. Il rejoue
# l'autorisation groupée (--authorize), sans jamais l'élargir. N'est atteint
# qu'une fois le run autorisé (sinon la porte unique ci-dessus a forcé DRY_RUN).
if [ "$SUPERVISE" = 1 ]; then
  SUPERVISE_CMD=${NM_SUPERVISE_CMD:-}
  if [ -z "$SUPERVISE_CMD" ]; then
    _py=$(_nm_python) || { echo "Erreur : aucun interpréteur Python pour le superviseur." >&2; exit 1; }
    SUPERVISE_CMD="$_py $HERE/run_supervise.py"
  fi
  if [ "$NO_DASHBOARD" = 1 ]; then
    echo "Lancement du superviseur (quota + reprise, sans dashboard)…"
    $SUPERVISE_CMD "$MILESTONE" --authorize --max-parallel "$MAX_PARALLEL"
    exit $?
  fi
  echo "Lancement du superviseur en arrière-plan + dashboard live…"
  $SUPERVISE_CMD "$MILESTONE" --authorize --max-parallel "$MAX_PARALLEL" \
    > "$RUN_DIR/superviseur.log" 2>&1 &
  SPID=$!
  "$DASHBOARD_CMD" "$RUN_ID" || true
  echo
  echo "Dashboard fermé. Le superviseur tourne peut-être encore (PID $SPID)."
  echo "Journal : $RUN_DIR/journal.ndjson"
  echo "Sortie superviseur : $RUN_DIR/superviseur.log"
  exit 0
fi

if [ "$NO_DASHBOARD" = 1 ]; then
  echo "Lancement de l'orchestrateur (sans dashboard)…"
  "$CLAUDE_CMD" -p "$PROMPT"
  exit $?
fi

# Orchestrateur en arrière-plan, dashboard au premier plan.
echo "Lancement de l'orchestrateur en arrière-plan + dashboard live…"
"$CLAUDE_CMD" -p "$PROMPT" > "$RUN_DIR/orchestrateur.log" 2>&1 &
CPID=$!
"$DASHBOARD_CMD" "$RUN_ID" || true
echo
echo "Dashboard fermé. L'orchestrateur tourne peut-être encore (PID $CPID)."
echo "Journal : $RUN_DIR/journal.ndjson"
echo "Sortie orchestrateur : $RUN_DIR/orchestrateur.log"
