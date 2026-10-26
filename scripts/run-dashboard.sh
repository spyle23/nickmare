#!/usr/bin/env bash
# Dashboard terminal live du suivi de run (issue #40).
#
# Lit le journal NDJSON d'un run et affiche, en se rafraîchissant, quel ticket
# est à quelle phase, depuis combien de temps, avec quel agent et quelle PR.
# Lecture seule : il n'écrit jamais dans le journal.
#
# Usage :
#   scripts/run-dashboard.sh [<run_id|chemin journal>] [--once] [--interval N]
#
#   (sans argument)  → run le plus récent sous .nickmare/runs/
#   <run_id>         → .nickmare/runs/<run_id>/journal.ndjson
#   <chemin>         → ce fichier journal précis
#   --once           → un seul rendu puis sortie (testable, sans TTY)
#   --interval N     → période de rafraîchissement en secondes (défaut 1)
#
# Couleurs activées si la sortie est un terminal (ou NM_FORCE_COLOR=1).
# Fail-safe : ligne JSON malformée ignorée ; run inexistant → message + sortie 0.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/run-journal.sh
. "$HERE/lib/run-journal.sh"

ONCE=0
INTERVAL=1
TARGET=""

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case $1 in
    --once) ONCE=1; shift ;;
    --interval) INTERVAL=${2:-1}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "option inconnue : $1" >&2; shift ;;
    *) TARGET=$1; shift ;;
  esac
done
case $INTERVAL in ''|*[!0-9]*) INTERVAL=1 ;; esac

# --- Résolution du journal ----------------------------------------------------
resolve_journal() {
  local t=$1 dir
  if [ -n "$t" ] && [ -f "$t" ]; then printf '%s' "$t"; return 0; fi
  if [ -n "$t" ]; then
    dir=$(nm_run_dir "$t") || return 1
  else
    dir=$(nm_run_dir) || return 1
  fi
  printf '%s/journal.ndjson' "$dir"
}

JOURNAL=$(resolve_journal "$TARGET") || {
  echo "Aucun run trouvé sous $(nm_runs_root). Lance d'abord scripts/run-jalon.sh." >&2
  exit 0
}
if [ ! -f "$JOURNAL" ]; then
  echo "Journal introuvable : $JOURNAL" >&2
  exit 0
fi
RUN_DIR=$(dirname "$JOURNAL")
META="$RUN_DIR/meta.json"
TITLES="$RUN_DIR/titles.tsv"

json_str() { # extrait une valeur chaîne d'un petit JSON plat
  sed -n "s/.*\"$2\":\"\\([^\"]*\\)\".*/\\1/p" "$1" 2>/dev/null | head -n1
}

# --- Couleurs -----------------------------------------------------------------
if [ -t 1 ] || [ "${NM_FORCE_COLOR:-}" = 1 ]; then C=1; else C=0; fi
c() { [ "$C" = 1 ] && printf '\033[%sm' "$1" || true; }
R()  { c 0; }

# Code couleur par phase.
phase_color() {
  case $1 in
    queued)  echo 90 ;;  # gris
    dev)     echo 34 ;;  # bleu
    tests)   echo 36 ;;  # cyan
    fix)     echo 33 ;;  # jaune
    qa)      echo 35 ;;  # magenta
    merge)   echo 32 ;;  # vert
    done)    echo 92 ;;  # vert vif
    blocked) echo 31 ;;  # rouge
    *)       echo 37 ;;
  esac
}

# Réduit le journal : dernière phase par ticket, dans l'ordre d'apparition.
# Sortie TSV : ticket \t phase \t ts \t agent \t pr \t detail
reduce() {
  awk '
    {
      line=$0
      if (!match(line, /"ticket":[0-9]+/)) next
      t=substr(line,RSTART,RLENGTH); sub(/"ticket":/,"",t)
      if (!match(line, /"phase":"[a-z]+"/)) next
      ph=substr(line,RSTART,RLENGTH); gsub(/("phase":"|")/,"",ph)
      if (!match(line, /"ts":"[^"]+"/)) next
      ts=substr(line,RSTART,RLENGTH); gsub(/("ts":"|")/,"",ts)
      ag=""
      if (match(line, /"agent":"[^"]*"/)) { ag=substr(line,RSTART,RLENGTH); gsub(/("agent":"|")/,"",ag) }
      pr="null"
      if (match(line, /"pr":(null|[0-9]+)/)) { pr=substr(line,RSTART,RLENGTH); sub(/"pr":/,"",pr) }
      dt=""
      if (match(line, /"detail":".*"}[ ]*$/)) { dt=substr(line,RSTART,RLENGTH); sub(/"detail":"/,"",dt); sub(/"}[ ]*$/,"",dt) }
      if (!(t in seen)) { seen[t]=1; order[++n]=t }
      phase[t]=ph; tss[t]=ts; agent[t]=ag; prr[t]=pr; det[t]=dt
    }
    END { for (i=1;i<=n;i++){ t=order[i]; printf "%s\t%s\t%s\t%s\t%s\t%s\n", t, phase[t], tss[t], agent[t], prr[t], det[t] } }
  ' "$JOURNAL" 2>/dev/null
}

ts_epoch() { date -u -d "$1" +%s 2>/dev/null; }

fmt_elapsed() { # secondes → "Xs" / "Xm Ys" / "Xh Ym"
  local s=$1
  if [ -z "$s" ] || [ "$s" -lt 0 ] 2>/dev/null; then printf '?'; return; fi
  if [ "$s" -lt 60 ]; then printf '%ds' "$s"
  elif [ "$s" -lt 3600 ]; then printf '%dm %02ds' $((s/60)) $((s%60))
  else printf '%dh %02dm' $((s/3600)) $(((s%3600)/60)); fi
}

ticket_title() { # titre court depuis titles.tsv si présent
  [ -f "$TITLES" ] || return 0
  awk -F'\t' -v t="$1" '$1==t {print $2; exit}' "$TITLES" 2>/dev/null
}

progress_bar() { # <done> <total> → barre texte
  local done=$1 total=$2 width=24 filled pct
  if [ "$total" -le 0 ]; then filled=0; pct=0
  else filled=$(( done * width / total )); pct=$(( done * 100 / total )); fi
  local bar=""
  local i=0
  while [ $i -lt $width ]; do
    if [ $i -lt $filled ]; then bar="$bar#"; else bar="$bar-"; fi
    i=$((i+1))
  done
  printf '[%s] %d/%d (%d%%)' "$bar" "$done" "$total" "$pct"
}

SPIN='|/-\'
FRAME=0

render() {
  local now milestone started
  now=$(date -u +%s)
  milestone=$(json_str "$META" milestone 2>/dev/null)
  started=$(json_str "$META" started_at 2>/dev/null)
  [ -z "$milestone" ] && milestone="(jalon inconnu)"

  local spin_char=${SPIN:FRAME%${#SPIN}:1}
  FRAME=$((FRAME+1))

  local rows total=0 done=0 blocked=0
  rows=$(reduce)

  # En-tête
  c 1; printf 'Nickmare · suivi de run'; R; printf '\n'
  c 90; printf 'Jalon : '; R; printf '%s\n' "$milestone"
  c 90; printf 'Run   : '; R; printf '%s' "$(basename "$RUN_DIR")"
  [ -n "$started" ] && { c 90; printf '   démarré '; R; printf '%s' "$started"; }
  printf '\n'
  printf '%s\n' "------------------------------------------------------------------------------"

  # Lignes par ticket
  if [ -z "$rows" ]; then
    c 90; printf 'Aucun événement pour l’instant… %s\n' "$spin_char"; R
  else
    local t ph ts ag pr dt epoch elapsed title badge active
    while IFS=$'\t' read -r t ph ts ag pr dt; do
      [ -z "$t" ] && continue
      total=$((total+1))
      [ "$ph" = done ] && done=$((done+1))
      [ "$ph" = blocked ] && blocked=$((blocked+1))
      epoch=$(ts_epoch "$ts")
      if [ -n "$epoch" ]; then elapsed=$(fmt_elapsed $((now-epoch))); else elapsed='?'; fi
      title=$(ticket_title "$t")
      [ -z "$title" ] && title=$dt
      case $ph in dev|tests|fix|qa|merge) active=1 ;; *) active=0 ;; esac
      badge=$(printf '%-7s' "$(printf '%s' "$ph" | tr '[:lower:]' '[:upper:]')")

      printf '  '
      c 1; printf '#%-4s' "$t"; R
      c "$(phase_color "$ph")"; printf ' %s' "$badge"; R
      [ "$active" = 1 ] && printf '%s ' "$spin_char" || printf '  '
      printf '%-7s ' "$elapsed"
      [ -n "$ag" ] && printf '%-12s ' "$ag" || printf '%-12s ' '-'
      [ "$pr" != null ] && printf 'PR#%-4s ' "$pr" || printf '%-7s ' '-'
      [ -n "$title" ] && printf '%s' "$title"
      printf '\n'
    done <<< "$rows"
  fi

  printf '%s\n' "------------------------------------------------------------------------------"
  printf 'Progression: '
  c 92; progress_bar "$done" "$total"; R
  [ "$blocked" -gt 0 ] && { printf '   '; c 31; printf '%d bloqué(s)' "$blocked"; R; }
  printf '\n'
  [ "$ONCE" = 0 ] && { c 90; printf '(q pour quitter — rafraîchi toutes les %ss)\n' "$INTERVAL"; R; }
}

if [ "$ONCE" = 1 ]; then
  render
  exit 0
fi

# Mode live : masque le curseur, le restaure en sortie.
cleanup() { c 0; printf '\033[?25h\n'; }
trap cleanup EXIT INT TERM
printf '\033[?25l'
while :; do
  printf '\033[2J\033[H'   # efface l'écran, curseur en haut
  render
  if read -r -t "$INTERVAL" -n1 key 2>/dev/null; then
    [ "$key" = q ] && break
  fi
done
