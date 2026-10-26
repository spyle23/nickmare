# Workflow de tickets (Claude Code + GitHub)

Deux commandes Claude Code encadrent le cycle de vie d'un ticket, et un pipeline GitHub Actions
assure le **merge automatique**.

## `/create-ticket <description>`

Rédige et crée une issue GitHub conforme à la taxonomie du dépôt :

- choisit le **milestone** (= phase d'implémentation) et les labels `epic:*`, `Nx:*`, `type:*`,
  `prio:*` parmi ceux qui existent déjà — sans en inventer ;
- structure le corps : Contexte → Tâches → **Critères d'acceptation** (alignés sur
  [`TESTING.md`](TESTING.md)) → **Garde-fous de sécurité** ([`ARCHITECTURE.md`](ARCHITECTURE.md) §3/§11) ;
- affiche le brouillon pour validation (passe `--yes` pour créer directement).

## `/ticket <numéro>`

Traite l'issue de bout en bout :

1. branche à jour depuis `main` (`feat/ `, `infra/`, `fix/`, `test/`, `docs/`, `sec/`) ;
2. implémentation incrémentale + tests (dont **tests négatifs de sécurité** si un garde-fou est touché) ;
3. `cargo fmt` / `clippy -D warnings` / `test` en local (si du code Rust existe) ;
4. commits + push ;
5. **PR reliée** au ticket (`Closes #N`) portant le label **`auto-merge`** ;
6. attente de la CI et compte rendu du merge.

## Merge automatique

Déclenché par le label **`auto-merge`** sur la PR, via [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) :

- la CI s'exécute (format, clippy, tests multi-OS, build) — les étapes Rust sont **ignorées
  proprement** tant qu'il n'y a pas de `Cargo.toml`, pour ne pas bloquer les premiers tickets ;
- dès que la CI est verte **et** que le label `auto-merge` est présent, le job `auto-merge`
  **squash-merge** la PR et **supprime la branche**.

> **Pourquoi un merge piloté par Actions plutôt que l'auto-merge natif de GitHub ?**
> L'auto-merge natif (`gh pr merge --auto`) exige `allow_auto_merge` + une protection de branche
> avec checks requis, indisponible ici (dépôt privé sans GitHub Pro). Le job Actions reproduit le
> même garde-fou — **jamais de fusion tant que la CI n'est pas verte** — de façon portable.

Pour qu'une PR **ne** se merge **pas** automatiquement : retire simplement le label `auto-merge`.
