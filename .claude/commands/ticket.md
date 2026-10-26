---
description: Traite un ticket GitHub de bout en bout — branche, implémentation, tests, PR liée, merge automatique
argument-hint: <numéro d'issue> [notes ou contraintes additionnelles]
allowed-tools: Bash, Read, Grep, Glob, Edit, Write
---

Tu traites intégralement le ticket **#$1** du projet **Nickmare** (outil d'audit de sécurité
réseau en Rust, destiné exclusivement à des engagements autorisés). Objectif : livrer une PR
reliée au ticket, qui se fusionne automatiquement une fois la CI verte.

Notes additionnelles éventuelles : $2

## Le ticket

> Le numéro est extrait de `$ARGUMENTS` (1er mot) et non de `$1` : dans un bloc `!`, `$ARGUMENTS`
> est substitué par Claude Code, alors que `$1` resterait un positionnel bash vide.

!`gh issue view "$(echo "$ARGUMENTS" | cut -d' ' -f1 | tr -d '#')" --json number,title,labels,milestone,body -q '"#\(.number) — \(.title)\n\nLabels: \([.labels[].name]|join(", "))\nMilestone: \(.milestone.title // "—")\n\n\(.body)"'`

## Règles non négociables (cf. `@docs/ARCHITECTURE.md` §3 & §11)

- **Non destructif par défaut**, action bornée au périmètre attesté, **journal d'audit** jamais
  contourné, **fail-safe**. Tout code intrusif reste derrière un drapeau explicite et un
  human-in-the-loop.
- Suis la **définition de réussite** de `@docs/TESTING.md` : pas de ticket « fini » sans les
  tests correspondants, y compris les **tests négatifs de sécurité** (§10.4) quand le ticket
  touche un garde-fou.

## Marche à suivre

1. **Comprendre** : lis le ticket ci-dessus et les sections de `docs/ARCHITECTURE.md` qu'il
   référence. Si le périmètre est ambigu ou dangereux, arrête-toi et demande avant de coder.

2. **Branche à jour** :
   ```
   git switch main && git pull --ff-only
   git switch -c <type>/<numéro>-<slug-court>    # ex. feat/12-scan-tcp, infra/3-workspace
   ```
   Préfixe selon le type du ticket : `feat/`, `infra/`, `fix/`, `test/`, `docs/`, `sec/`.

3. **Implémenter** par petits incréments cohérents. Respecte le style du code existant.
   Ajoute/able les tests au fur et à mesure.

4. **Vérifier localement** si un projet Cargo existe (`Cargo.toml` présent) :
   ```
   cargo fmt --all
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-features --workspace
   ```
   Corrige jusqu'au vert. (S'il n'y a pas encore de code Rust, saute cette étape.)

5. **Committer** en français, messages clairs et atomiques. Termine **chaque** message de commit
   par la ligne d'attribution Co-Authored-By exigée par la session Claude Code active
   (voir le rappel d'attribution de la session). Puis `git push -u origin HEAD`.

6. **Ouvrir la PR** reliée au ticket, en reprenant ses labels, et **ajouter le label
   `auto-merge`** (c'est lui qui déclenche la fusion automatique) :
   ```
   gh pr create --fill --base main \
     --body "Closes #$1

   <résumé orienté résultat + cases de sécurité du template cochées>" \
     --label auto-merge
   ```
   Termine la description de PR par : `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

7. **Laisser le merge se faire tout seul, et le confirmer** : le workflow `.github/workflows/ci.yml`
   (job `auto-merge`) fusionne la PR en squash et supprime la branche dès que la CI est verte.
   Surveille et rends compte :
   ```
   gh pr checks --watch
   gh pr view --json state,mergedAt -q '.state + " / mergé à " + (.mergedAt // "pas encore")'
   ```
   - Si la CI échoue : analyse les logs (`gh run view --log-failed`), corrige, re-pousse (la CI
     et le merge auto se relancent automatiquement).
   - Si tout est vert mais que la fusion n'a pas eu lieu (conflit, par ex.) : règle le problème,
     ne force jamais un merge manuel qui contournerait la CI.

8. **Clôturer** : une fois mergée, confirme que l'issue #$1 est bien fermée (le `Closes #$1`
   s'en charge) et reviens sur `main` à jour (`git switch main && git pull --ff-only`).
