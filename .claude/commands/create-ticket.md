---
description: Rédige et crée un ticket GitHub conforme à la taxonomie du dépôt (phase, epic, niveau, type, priorité)
argument-hint: <description libre du besoin> [--yes pour créer sans confirmation]
allowed-tools: Bash(gh label list:*), Bash(gh api:*), Bash(gh issue list:*), Bash(gh issue view:*), Bash(gh repo view:*), Bash(gh issue create:*), Read, Grep, Glob
---

Tu crées un ticket GitHub pour le projet **Nickmare** (outil d'audit de sécurité réseau en
Rust, usage autorisé uniquement). Le ticket doit s'insérer proprement dans l'organisation
existante du dépôt.

## Besoin exprimé

$ARGUMENTS

## Contexte du dépôt (chargé dynamiquement)

Dépôt : !`gh repo view --json nameWithOwner -q .nameWithOwner`

Labels disponibles :
!`gh label list --limit 100`

Milestones (= phases d'implémentation) :
!`gh api "repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/milestones" --jq '.[] | "\(.title)"'`

## Marche à suivre

1. **Classer le besoin** en t'appuyant sur `@docs/ARCHITECTURE.md` (§8 user stories, §9 phases)
   et `@docs/TESTING.md`. Détermine :
   - la **phase** → choisir le *milestone* exact dans la liste ci-dessus (ou `Transverse` pour
     sûreté/sécurité/docs qui ne relèvent pas d'une phase) ;
   - l'**epic** → un label `epic:*` ;
   - le **niveau de capacité** si applicable → `N1:recon` / `N2:exploitation` / `N3:cracking` /
     `N4:emulation` ;
   - le **type** → `type:feature` / `type:infra` / `type:security` / `type:test` / `type:docs` ;
   - la **priorité** → `prio:P0` uniquement si c'est un socle bloquant.
   N'invente aucun label ni milestone : n'utilise que ceux listés ci-dessus. Si un label utile
   manque vraiment, propose-le mais ne le crée pas sans accord.

2. **Vérifier les doublons** : `gh issue list --search "<mots-clés>"` avant de rédiger.

3. **Rédiger le ticket** en français, format :
   - **Titre** : `Phase N · <Epic> — <résumé d'action>` (ou `Transverse · …`), concis et orienté résultat.
   - **Corps** (markdown) avec ces sections :
     - `## Contexte` — pourquoi, et renvoi aux sections pertinentes de `docs/ARCHITECTURE.md`.
     - `## Dépendances` — liste des issues bloquantes (`#N`, une par ligne, idéalement `Bloqué par #N`)
       ou le mot `Aucune`. **Toujours présente** : c'est elle que l'orchestrateur `/run-jalon` lit pour
       construire le graphe de dépendances et déduire l'ordre et les lots parallélisables.
     - `## Tâches` — liste à cocher, granularité raisonnable.
     - `## Critères d'acceptation` — vérifiables, alignés sur la **définition de réussite** de
       `docs/TESTING.md`.
     - `## Garde-fous de sécurité` — invariants concernés (§3/§11 : non destructif par défaut,
       action bornée au périmètre, journal d'audit, fail-safe) et tests négatifs attendus si pertinent.

4. **Confirmation** : affiche le brouillon (titre, corps, labels, milestone) et demande validation
   à l'utilisateur. Saute cette étape **uniquement** si `--yes` est passé en argument.

5. **Créer** avec :
   ```
   gh issue create --title "<titre>" --body "<corps>" \
     --label "<l1>" --label "<l2>" ... --milestone "<titre exact du milestone>"
   ```
   Puis affiche l'URL de l'issue créée et rappelle qu'on peut lancer `/ticket <numéro>` pour la traiter.
