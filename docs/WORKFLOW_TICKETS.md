# Workflow de tickets (Claude Code + GitHub)

Des commandes Claude Code encadrent le cycle de vie d'un ticket — de sa création à son traitement
unitaire, et jusqu'à l'exécution d'un **jalon entier** par des agents coordonnés — et un pipeline
GitHub Actions assure le **merge automatique**. `/demande` est le raccourci « idée → incrément » qui
enchaîne création et traitement d'un ticket.

## `/demande <description>`

Pont « de l'idée à l'incrément » : transforme une demande formulée librement en session chat en
ticket, puis enchaîne son traitement. Concrètement, elle applique la logique de `/create-ticket`
puis celle de `/ticket`, avec **un seul point de contrôle** — la validation du brouillon de ticket
avant toute écriture de code. Après validation, tout s'enchaîne jusqu'à la PR auto-mergée (sauf
ambiguïté de périmètre ou risque de sécurité, où la commande s'arrête et demande).

Utilise `/create-ticket` seul si tu veux seulement créer l'issue, et `/ticket <numéro>` seul pour
traiter une issue existante.

## `/create-ticket <description>`

Rédige et crée une issue GitHub conforme à la taxonomie du dépôt :

- choisit le **milestone** (= phase d'implémentation) et les labels `epic:*`, `Nx:*`, `type:*`,
  `prio:*` parmi ceux qui existent déjà — sans en inventer ;
- structure le corps : Contexte → **Dépendances** (issues `#N` bloquantes, lues par `/run-jalon`)
  → Tâches → **Critères d'acceptation** (alignés sur [`TESTING.md`](TESTING.md)) →
  **Garde-fous de sécurité** ([`ARCHITECTURE.md`](ARCHITECTURE.md) §3/§11) ;
- affiche le brouillon pour validation (passe `--yes` pour créer directement).

## `/ticket <numéro>`

Traite l'issue de bout en bout :

1. branche à jour depuis `main` (`feat/ `, `infra/`, `fix/`, `test/`, `docs/`, `sec/`) ;
2. implémentation incrémentale + tests (dont **tests négatifs de sécurité** si un garde-fou est touché) ;
3. `cargo fmt` / `clippy -D warnings` / `test` en local (si du code Rust existe) ;
4. commits + push ;
5. **PR reliée** au ticket (`Closes #N`) portant le label **`auto-merge`** ;
6. attente de la CI et compte rendu du merge.

## `/run-jalon <milestone> [--max-parallel N] [--dry-run]`

Exécute un **jalon entier** de façon semi-autonome en coordonnant des agents. C'est un cran
au-dessus du traitement unitaire : là où `/ticket` traite une issue, `/run-jalon` en traite tout un
*milestone*.

```
Orchestrateur de run  (/run-jalon)
  │  lit les issues du milestone + leur section ## Dépendances
  │  → graphe de dépendances → ordre (prio:P0 d'abord) → lots parallélisables
  │
  ├─ agent dev-ticket  ──┐  (plusieurs en parallèle, worktrees isolés)
  ├─ agent dev-ticket  ──┤  → chacun : branche, implémentation, tests, PR + auto-merge
  │                       │
  └─ agent qa-ticket   ──┘  vérifie chaque PR contre les critères d'acceptation
                            → PASS : laisse le merge auto ; FAIL : retire auto-merge, renvoie au dev
```

- **Orchestrateur** ([`.claude/commands/run-jalon.md`](../.claude/commands/run-jalon.md)) : ne
  considère « prêt » qu'un ticket dont toutes les dépendances sont fermées ; lance les agents dev par
  lots (≤ `--max-parallel`, défaut 2), puis la QA ; **sérialise les merges** et re-synchronise `main`
  entre les lots ; rend un **compte rendu de run** (ticket → PR → CI → verdict QA → statut).
- **Agent développeur** ([`.claude/agents/dev-ticket.md`](../.claude/agents/dev-ticket.md)) :
  logique de `/ticket` en worktree isolé (parallélisable).
- **Agent QA** ([`.claude/agents/qa-ticket.md`](../.claude/agents/qa-ticket.md)) : verdict
  `PASS`/`FAIL` motivé ; ne code jamais, ne merge jamais.

**Points d'arrêt humain (non négociables)** : aucun ticket `type:security` ni `prio:P0` n'est traité
en autonomie, et le run refuse d'enjamber le **jalon de revue #17** (garde-fous avant N2–N4). Dans
ces cas l'orchestrateur s'arrête et **demande une validation humaine**. Le merge reste toujours
piloté par la CI verte — jamais de merge manuel forcé. Utilise `--dry-run` pour afficher le plan
sans aucun effet de bord.

## Merge automatique

Déclenché par le label **`auto-merge`** sur la PR, via [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) :

- la CI s'exécute (format, clippy, tests multi-OS, build) — les étapes Rust sont **ignorées
  proprement** tant qu'il n'y a pas de `Cargo.toml`, pour ne pas bloquer les premiers tickets ;
- dès que la CI est verte **et** que le label `auto-merge` est présent, le job `auto-merge`
  **squash-merge** la PR et **supprime la branche** ;
- une fois la PR effectivement mergée, le même job **ferme automatiquement les issues liées**
  (`Closes #N`, `Fixes #N`, `Resolves #N`… ; plusieurs issues possibles : `Closes #1, #2` ou un
  mot-clé par ligne) avec `--reason completed` et un commentaire renvoyant à la PR. Plus besoin de
  les fermer à la main : un merge par le `GITHUB_TOKEN` ne propage pas le `Closes #N` de lui-même,
  d'où cette étape ([`close-linked-issues.sh`](../.github/scripts/close-linked-issues.sh)).
  Elle est **best-effort** : une PR sans issue liée se merge normalement, et un échec de fermeture
  ne fait jamais échouer ni annuler le merge (simple avertissement dans le journal du job).

> **Pourquoi un merge piloté par Actions plutôt que l'auto-merge natif de GitHub ?**
> L'auto-merge natif (`gh pr merge --auto`) exige `allow_auto_merge` + une protection de branche
> avec checks requis, indisponible ici (dépôt privé sans GitHub Pro). Le job Actions reproduit le
> même garde-fou — **jamais de fusion tant que la CI n'est pas verte** — de façon portable.

Pour qu'une PR **ne** se merge **pas** automatiquement : retire simplement le label `auto-merge`.
