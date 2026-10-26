#!/usr/bin/env bash
# Tests de close-linked-issues.sh (issue #37). Aucun appel réseau : `gh` est
# remplacé par un bouchon qui journalise ses appels.
#
# Usage : bash .github/scripts/tests/close-linked-issues.test.sh

set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/close-linked-issues.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }

# --- Extraction ---------------------------------------------------------------

expect_extract() {
  local name="$1" body="$2" expected="$3" got
  got=$(printf '%s\n' "$body" | bash "$SCRIPT" --extract | tr '\n' ' ' | sed 's/ $//')
  if [ "$got" = "$expected" ]; then pass "extract: $name"; else fail "extract: $name (attendu « $expected », obtenu « $got »)"; fi
}

expect_extract "une issue"                "Closes #37"                          "37"
expect_extract "casse indifférente"       "closes #4"$'\n'"FIXES #5"            "4 5"
expect_extract "tous les mots-clés"       "close #1 closed #2 fix #3 fixed #4 resolve #5 resolved #6 resolves #7" "1 2 3 4 5 6 7"
expect_extract "deux mots-clés"           "Closes #12"$'\n'"Fixes #13"          "12 13"
expect_extract "liste à virgules"         "Closes #12, #13"                     "12 13"
expect_extract "liste « et » / « and »"   "Closes #12 et #13 and #14"           "12 13 14"
expect_extract "deux-points"              "Closes: #9"                          "9"
expect_extract "doublons dédupliqués"     "Closes #8"$'\n'"Fixes #8"            "8"
expect_extract "sans issue liée"          "PR d'outillage, rien à fermer."      ""
expect_extract "simple mention ignorée"   "Voir #12 et la PR #13."              ""
expect_extract "placeholder du template"  "Closes #<!-- numéro -->"             ""
expect_extract "autre dépôt ignoré"       "Closes other/repo#12"                ""
expect_extract "mot englobant ignoré"     "encloses #12 prefixes #13"           ""

# --- Exécution avec un `gh` bouchonné ----------------------------------------

# Le bouchon lit l'état de la PR et des issues dans des variables d'env,
# et journalise chaque appel dans $GH_LOG.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$1 $2" in
  "pr view")
    case "$*" in
      *"--json state"*) [ -n "${STUB_PR_STATE:-}" ] && echo "$STUB_PR_STATE" || exit 1 ;;
      *"--json body"*)  printf '%s\n' "$STUB_PR_BODY" ;;
    esac ;;
  "issue view")
    var="STUB_ISSUE_$3"; [ -n "${!var:-}" ] && echo "${!var}" || exit 1 ;;
  "issue close")
    [ "${STUB_CLOSE_FAILS:-}" = "1" ] && exit 1 || exit 0 ;;
esac
EOF
chmod +x "$WORK/bin/gh"

# run_case <nom> ; les STUB_* sont passés en env. Renvoie le statut du script.
run_case() {
  GH_LOG="$WORK/gh.log"; : > "$GH_LOG"
  PATH="$WORK/bin:$PATH" GH_LOG="$GH_LOG" PR=99 REPO=o/r bash "$SCRIPT" > "$WORK/out.log" 2>&1
}
closed_issues() { grep -oE '^issue close [0-9]+' "$WORK/gh.log" | awk '{print $3}' | tr '\n' ' ' | sed 's/ $//'; }

expect_closed() {
  local name="$1" status="$2" expected="$3" got
  got=$(closed_issues)
  if [ "$status" -ne 0 ]; then fail "$name (statut $status, attendu 0)"; return; fi
  if [ "$got" = "$expected" ]; then pass "$name"; else fail "$name (fermées attendues « $expected », obtenues « $got »)"; cat "$WORK/out.log"; fi
}

export STUB_PR_STATE STUB_PR_BODY STUB_ISSUE_12 STUB_ISSUE_13 STUB_CLOSE_FAILS

STUB_PR_STATE=MERGED STUB_PR_BODY="Closes #12" STUB_ISSUE_12=OPEN STUB_ISSUE_13= STUB_CLOSE_FAILS=
run_case; expect_closed "PR mergée, une issue → fermée" $? "12"
if grep -q -- '--reason completed' "$WORK/gh.log" && grep -q 'PR #99' "$WORK/gh.log"; then
  pass "fermeture journalisée (--reason completed + renvoi à la PR)"
else
  fail "fermeture journalisée (--reason completed + renvoi à la PR)"
fi

STUB_PR_BODY="Closes #12"$'\n'"Fixes #13" STUB_ISSUE_13=OPEN
run_case; expect_closed "PR mergée, deux issues → les deux fermées" $? "12 13"

STUB_PR_BODY="Outillage, pas d'issue liée."
run_case; expect_closed "PR sans issue liée → rien fermé, pas d'échec" $? ""

STUB_PR_BODY="Closes #12, #13" STUB_ISSUE_12=CLOSED
run_case; expect_closed "issue déjà fermée → ignorée" $? "13"

# Tests négatifs de sécurité (docs/TESTING.md §10.4) : jamais de fermeture sans
# merge effectif, et jamais d'échec du job.
STUB_PR_BODY="Closes #12" STUB_ISSUE_12=OPEN
for st in OPEN CLOSED; do
  STUB_PR_STATE=$st
  run_case; expect_closed "PR non mergée ($st) → aucune fermeture" $? ""
done

STUB_PR_STATE=
run_case; expect_closed "état de PR illisible → aucune fermeture, pas d'échec" $? ""

STUB_PR_STATE=MERGED STUB_CLOSE_FAILS=1
run_case; expect_closed "échec de gh issue close → statut 0 (fail-safe)" $? "12"

STUB_CLOSE_FAILS= STUB_ISSUE_12=
run_case; expect_closed "issue introuvable → ignorée, pas d'échec" $? ""

GH_LOG="$WORK/gh.log"; : > "$GH_LOG"
PATH="$WORK/bin:$PATH" GH_LOG="$GH_LOG" PR= REPO= bash "$SCRIPT" > /dev/null 2>&1
expect_closed "PR/REPO absents → aucune fermeture, pas d'échec" $? ""

echo
if [ "$failures" -eq 0 ]; then echo "Tous les tests passent."; else echo "$failures test(s) en échec."; exit 1; fi
