#!/usr/bin/env bash
# Ferme les issues liées à une PR une fois celle-ci mergée (cf. issue #37).
#
# Le job `auto-merge` de ci.yml fusionne avec le GITHUB_TOKEN : GitHub ne propage
# alors pas le `Closes #N` du corps de PR, et l'issue reste ouverte. Ce script
# comble le manque, en best-effort :
#
# - il ne ferme rien tant que la PR n'est pas effectivement MERGED ;
# - il lit les mots-clés de fermeture GitHub (close/closes/closed, fix/fixes/fixed,
#   resolve/resolves/resolved, insensibles à la casse) suivis d'un ou plusieurs
#   `#N` (`Closes #1`, `Closes #1, #2`, `Fixes #1 et #2`, `Closes #1` + `Fixes #2`) ;
#   les références inter-dépôts (`owner/repo#N`) sont ignorées ;
# - chaque fermeture est journalisée (`--reason completed` + commentaire pointant la PR) ;
# - il ne renvoie JAMAIS d'erreur : un échec est signalé en `::warning::` sans
#   jamais faire échouer ni bloquer le merge (fail-safe).
#
# Usage :
#   PR=<numéro> REPO=<owner/repo> close-linked-issues.sh   # mode CI (requiert gh)
#   close-linked-issues.sh --extract < corps.md             # extraction seule (tests)

set -uo pipefail

# Lit un corps de PR sur stdin, écrit les numéros d'issue à fermer (uniques, triés).
extract_issue_numbers() {
  local keyword='(close[sd]?|fix(e[sd])?|resolve[sd]?)'
  local ref='#[0-9]+'
  local list="${ref}([[:space:]]*,?[[:space:]]*((and|et)[[:space:]]+)?${ref})*"
  grep -oiE "(^|[^[:alnum:]_])${keyword}[[:space:]]*:?[[:space:]]+${list}" \
    | grep -oE "${ref}" \
    | tr -d '#' \
    | sort -un
}

main() {
  if [ -z "${PR:-}" ] || [ -z "${REPO:-}" ]; then
    echo "::warning::PR ou REPO non défini — aucune issue fermée."
    return 0
  fi

  local state body
  if ! state=$(gh pr view "$PR" --repo "$REPO" --json state -q .state); then
    echo "::warning::Impossible de lire l'état de la PR #$PR — aucune issue fermée."
    return 0
  fi
  if [ "$state" != "MERGED" ]; then
    echo "::notice::PR #$PR non mergée (état : $state) — aucune issue fermée."
    return 0
  fi
  if ! body=$(gh pr view "$PR" --repo "$REPO" --json body -q .body); then
    echo "::warning::Impossible de lire le corps de la PR #$PR — aucune issue fermée."
    return 0
  fi

  local issues
  issues=$(printf '%s\n' "$body" | extract_issue_numbers)
  if [ -z "$issues" ]; then
    echo "::notice::PR #$PR sans issue liée (pas de « Closes #N ») — rien à fermer."
    return 0
  fi

  local n issue_state
  for n in $issues; do
    if ! issue_state=$(gh issue view "$n" --repo "$REPO" --json state -q .state); then
      echo "::warning::Issue #$n introuvable ou illisible — ignorée."
      continue
    fi
    if [ "$issue_state" != "OPEN" ]; then
      echo "Issue #$n déjà fermée — rien à faire."
      continue
    fi
    if gh issue close "$n" --repo "$REPO" --reason completed \
         --comment "Fermée automatiquement suite au merge de la PR #$PR (job \`auto-merge\`)."; then
      echo "Issue #$n fermée (completed) — liée à la PR #$PR."
    else
      echo "::warning::Échec de la fermeture de l'issue #$n — à fermer à la main."
    fi
  done
  return 0
}

if [ "${1:-}" = "--extract" ]; then
  extract_issue_numbers
  exit 0
fi

main
exit 0
