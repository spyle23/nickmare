---
description: Transforme une demande libre (session chat) en ticket GitHub puis enchaîne son traitement de bout en bout
argument-hint: <description libre du besoin> [notes ou contraintes additionnelles]
allowed-tools: Bash, Read, Grep, Glob, Edit, Write
---

Tu transformes une **demande formulée en chat** pour le projet **Nickmare** (outil d'audit de
sécurité réseau en Rust, usage autorisé uniquement) en un ticket GitHub conforme à la taxonomie
du dépôt, puis tu le traites jusqu'à la PR auto-mergée. Cette commande est le pont entre une idée
exprimée librement et un incrément livré.

## Demande exprimée

$ARGUMENTS

## Déroulé

Tu enchaînes les deux commandes existantes, avec **un seul point de contrôle** : la validation du
brouillon de ticket avant toute écriture de code.

### Étape 1 — Créer le ticket (logique de `/create-ticket`)

Applique intégralement la marche à suivre de `@.claude/commands/create-ticket.md` à partir de la
demande ci-dessus :

1. charge le contexte du dépôt (`gh repo view`, `gh label list`, milestones) ;
2. classe le besoin (phase/milestone, epic, niveau Nx, type, priorité) en t'appuyant sur
   `@docs/ARCHITECTURE.md` et `@docs/TESTING.md` — **sans inventer** de label ni de milestone ;
3. vérifie les doublons (`gh issue list --search …`) ;
4. rédige le ticket en français (Titre → Contexte → Tâches → Critères d'acceptation →
   Garde-fous de sécurité) ;
5. **PAUSE OBLIGATOIRE** : affiche le brouillon complet (titre, corps, labels, milestone) et
   **attends la validation de l'utilisateur**. N'enchaîne jamais sur l'étape 2 sans accord
   explicite — même si `--yes` apparaît dans les arguments, ce drapeau ne vaut que pour la
   création de l'issue, pas pour lancer le traitement.
6. une fois validé, crée l'issue avec `gh issue create …` et **récupère son numéro** depuis l'URL
   / la sortie de la commande.

### Étape 2 — Traiter le ticket (logique de `/ticket`)

Avec le **numéro d'issue** obtenu à l'étape 1, applique intégralement la marche à suivre de
`@.claude/commands/ticket.md`, en prenant ce numéro comme ticket à traiter et les éventuelles
contraintes de la demande comme notes additionnelles :

1. relis le ticket et les sections de `docs/ARCHITECTURE.md` qu'il référence ; si le périmètre est
   ambigu ou dangereux, **arrête-toi et demande** avant de coder ;
2. branche à jour depuis `main` avec le bon préfixe (`feat/`, `infra/`, `fix/`, `test/`, `docs/`,
   `sec/`) ;
3. implémentation incrémentale + tests (dont les **tests négatifs de sécurité** si un garde-fou
   est touché) ;
4. `cargo fmt` / `clippy -D warnings` / `test` en local si un `Cargo.toml` existe ;
5. commits en français (ligne d'attribution `Co-Authored-By` de la session active) + push ;
6. PR reliée (`Closes #<numéro>`) avec le label **`auto-merge`**, description terminée par la ligne
   `🤖 Generated with [Claude Code](https://claude.com/claude-code)` ;
7. surveille la CI, laisse le merge auto se faire et **rends-en compte** ; corrige en cas d'échec,
   ne force jamais un merge manuel qui contournerait la CI ;
8. confirme la fermeture de l'issue et le retour sur `main` à jour.

## Règles non négociables (cf. `@docs/ARCHITECTURE.md` §3 & §11)

- **Non destructif par défaut**, action bornée au périmètre attesté, **journal d'audit** jamais
  contourné, **fail-safe** — en cas de doute, on s'arrête.
- Suis la **définition de réussite** de `@docs/TESTING.md` : pas de ticket « fini » sans ses tests.
- La seule pause imposée est la validation du brouillon (fin d'étape 1). Tout le reste s'enchaîne,
  sauf si tu rencontres une ambiguïté de périmètre ou un risque de sécurité : alors demande.
