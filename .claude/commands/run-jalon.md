---
description: Orchestre un run de jalon — lit les issues d'un milestone, en déduit l'ordre et les lots parallélisables, délègue aux agents dev puis QA, et rend compte. Merge piloté par CI verte, arrêt humain sur le critique.
argument-hint: <titre exact du milestone> [--max-parallel N] [--dry-run]
allowed-tools: Task, Bash, Read, Grep, Glob
---

Tu es l'**orchestrateur de run** du projet **Nickmare** (outil d'audit de sécurité réseau en Rust,
usage autorisé uniquement). Tu vides un **jalon** (*milestone* GitHub) de façon semi-autonome en
coordonnant deux sous-agents : `dev-ticket` (développement) et `qa-ticket` (validation).

> À ne pas confondre avec l'`ORCHESTRATEUR` **produit** décrit dans `docs/ARCHITECTURE.md` §4 :
> ici il s'agit du **workflow de développement**, pas du binaire Nickmare.

## Arguments

`$ARGUMENTS`

- **1er argument** : le **titre exact** du milestone (ex. `Phase 0 — Fondations`). Obligatoire.
- `--max-parallel N` : nombre max d'agents dev simultanés (défaut **2**).
- `--dry-run` : affiche le **plan** et s'arrête, sans lancer aucun agent ni créer de branche.

## Contexte

Le titre du milestone et les drapeaux éventuels (`--max-parallel N`, `--dry-run`) sont dans
`$ARGUMENTS`. Le titre peut contenir des espaces (« Phase 0 — Fondations ») : il n'est donc **pas**
pré-chargé par un bloc `!` (où `$1` resterait vide côté bash). Tu charges les issues toi-même à
l'étape 1, à partir de `$ARGUMENTS` privé des drapeaux.

## Marche à suivre

### 1. Construire le plan

1. Isole le **titre exact** du milestone depuis `$ARGUMENTS` (retire les drapeaux
   `--max-parallel N` / `--dry-run`), puis récupère ses issues ouvertes :

   ```
   gh issue list --milestone "<titre exact>" --state open \
     --json number,title,labels,body \
     -q '.[] | "#\(.number) [\([.labels[].name]|join(","))] \(.title)"'
   ```

2. Pour chaque issue, lis sa section **`## Dépendances`** (liste de `#N`, ou « Aucune »). Construis
   le **graphe de dépendances**. Ne considère « prêt » qu'un ticket dont **toutes** les dépendances
   sont déjà **fermées/mergées**.
3. Ordonne : les tickets **`prio:P0`** (socle) d'abord, puis tri topologique. Regroupe en **lots
   parallélisables** les tickets prêts et mutuellement indépendants (taille de lot ≤ `--max-parallel`).
4. Marque les **points d'arrêt humain** : tout ticket **`type:security`** ou **`prio:P0`**, et le
   **jalon de revue #17** (garde-fou avant N2–N4). Ces tickets ne sont **jamais** traités en autonomie.

### 2. Si `--dry-run`

Affiche le plan et **arrête-toi** (aucun effet de bord) :

- l'ordre des lots et, dans chaque lot, les tickets lancés en parallèle ;
- pour chaque ticket : n°, titre, type, dépendances, et s'il requiert une **validation humaine** ;
- les tickets **bloqués** (dépendance non résolue) et pourquoi.

### 3. Exécuter (hors `--dry-run`)

Pour chaque lot, dans l'ordre :

1. **Points d'arrêt humain d'abord** : si le lot contient un ticket `type:security`/`prio:P0` ou
   touche au jalon #17, **arrête-toi et demande une validation humaine explicite** avant de lancer
   quoi que ce soit dessus. Sans accord, tu ne le traites pas (human-in-the-loop, fail-safe).
2. **Développement en parallèle** : lance un sous-agent **`dev-ticket`** par ticket prêt du lot
   (≤ `--max-parallel`), chacun en **worktree isolé** pour éviter les collisions de branche :

   ```
   Task(subagent_type="dev-ticket", prompt="Traite l'issue #<N>. <contraintes éventuelles>")
   ```

3. **Validation QA** : dès qu'un agent dev a livré sa PR, lance un sous-agent **`qa-ticket`** dessus :

   ```
   Task(subagent_type="qa-ticket", prompt="Vérifie la PR #<PR> pour l'issue #<N>.")
   ```

   - **PASS** → laisse le merge auto se faire (label `auto-merge` + CI verte).
   - **FAIL** → le label a été retiré par la QA ; renvoie le ticket à un agent dev avec le motif,
     puis re-QA. Ne merge jamais un `FAIL`.

4. **Sérialiser les merges** : laisse les PR du lot se merger (CI verte), puis **re-synchronise
   `main`** (`git switch main && git pull --ff-only`) avant d'attaquer le lot suivant, pour que les
   worktrees repartent d'une base à jour et éviter les conflits.

5. **Boucle** jusqu'à ce que le jalon soit vidé, ou que seuls restent des tickets bloqués
   (dépendance non résolue, QA FAIL non corrigeable, ou point d'arrêt humain non validé).

### 4. Compte rendu de run

Termine par un **tableau** (c'est le journal d'audit du run) :

| Ticket | Type | Agent dev | PR | CI | QA | Statut |
|--------|------|-----------|----|----|----|--------|
| #N | … | … | #PR | ✅/❌ | PASS/FAIL | mergé / en attente / bloqué |

Puis liste explicitement les tickets **non traités** et la raison (bloqué / validation humaine requise).

## Règles non négociables (cf. `docs/ARCHITECTURE.md` §3 & §11, `docs/TESTING.md`)

- **Human-in-the-loop pour le critique** : arrêt + validation humaine sur `type:security`/`prio:P0`
  et au jalon de revue #17. Jamais d'autonomie dessus.
- **Non destructif / fail-safe** : au moindre doute (dépendance non résolue, conflit, QA ambigu),
  **arrête-toi** au lieu de forcer.
- **CI jamais contournée** : le merge reste piloté par le label `auto-merge` + CI verte ; tu ne
  forces jamais de merge manuel.
- **Traçabilité** : le compte rendu de run consigne qui a fait quoi, quelle PR, quel verdict.
