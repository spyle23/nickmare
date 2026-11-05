---
description: Orchestre un run de jalon — lit les issues d'un milestone, en déduit l'ordre et les lots parallélisables, délègue aux agents dev puis QA, et rend compte. Merge piloté par CI verte, arrêt humain sur le critique.
argument-hint: <titre exact du milestone> [--authorize] [--max-parallel N] [--max-lots N] [--dry-run]
allowed-tools: Agent, Task, Bash, Read, Grep, Glob
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
- `--max-lots N` : s'arrêter **proprement après N lots** traités (laisse les PR du dernier lot
  suivre leur cours : QA + CI), puis rendre le compte rendu. Défaut : **illimité** (vide le jalon).
  C'est le levier du **superviseur** (`scripts/run_supervise.py`, issue #49), qui te relance « un
  lot par appel » (`--max-lots 1`) pour survivre à la fenêtre d'usage de cinq heures.
- `--dry-run` : affiche le **plan** et s'arrête, sans lancer aucun agent ni créer de branche.
- `--authorize` : **autorisation humaine groupée** (porte unique). Sa présence atteste qu'un humain
  a validé **tout** le run en amont : l'orchestrateur enchaîne alors les tickets en autonomie, y
  compris `type:security`/`prio:P0` et le jalon #17, **sans redemander ticket par ticket**.
  **Absent** → tu te limites au plan (comme `--dry-run`). En session interactive tu peux obtenir
  cette autorisation en la **demandant une seule fois** ; en mode `-p` non interactif, seul le
  drapeau `--authorize` l'accorde.

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
4. Repère les **tickets sensibles** : tout ticket **`type:security`** ou **`prio:P0`**, et le
   **jalon de revue #17** (garde-fou avant N2–N4). Ils ne bloquent **plus** le run ticket par
   ticket : ils sont couverts par l'**autorisation groupée unique** demandée une seule fois au
   lancement (étape 3.0). Énumère-les dès le plan, pour que l'humain sache exactement ce qu'il
   autorise avant de dire oui.

### 2. Si `--dry-run`

Affiche le plan et **arrête-toi** (aucun effet de bord) :

- l'ordre des lots et, dans chaque lot, les tickets lancés en parallèle ;
- pour chaque ticket : n°, titre, type, dépendances, et s'il est **sensible** (donc couvert par
  l'autorisation groupée de l'étape 3.0) ;
- les tickets **bloqués** (dépendance non résolue) et pourquoi.

### 3. Exécuter (hors `--dry-run`)

#### 3.0 Autorisation groupée (porte unique, une seule fois)

Avant de lancer le **premier** lot, présente le **plan complet** et **énumère les tickets
sensibles** (`type:security`, `prio:P0`, jalon #17) qui seront traités. Il te faut une **autorisation
humaine groupée** — c'est la **seule** intervention humaine du run :

- Si `--authorize` est présent dans `$ARGUMENTS`, ou si l'humain te l'accorde explicitement en
  session interactive → **autorisation acquise**.
- **Sinon** → tu t'en tiens au plan (comme `--dry-run`) et tu **t'arrêtes**, sans lancer aucun
  agent. Fail-safe : le défaut est de ne rien faire. (En mode `-p` non interactif, tu ne peux pas
  « demander » : seul `--authorize` accorde la porte.)

Une fois la porte franchie, tu **n'interromps plus** le run pour une validation : tu **organises et
enchaînes** les lots toi-même — en **parallèle** quand les dépendances le permettent, sinon **un par
un** — jusqu'à vider le jalon. **L'humain ne nomme jamais les tickets.** Consigne la porte, puis
dérive le **marqueur** à transmettre aux agents dev sur les tickets sensibles :

```
nm_log_phase 0 queued --agent orchestrateur --detail "run autorisé — porte unique"
# marqueur d'autorisation (à recopier dans le prompt des agents, cf. 3.1) :
AUTORISATION-RUN: <NM_RUN_ID> — validation humaine groupée accordée. Tickets P0/security couverts.
```

#### 3.1 Pour chaque lot, dans l'ordre

0. **Point de contrôle (`gate`)** — **avant** de lancer le moindre agent du lot, consulte le gate
   et **applique son code de sortie** (priorité : arrêt > quota > pause) :

   ```
   source scripts/lib/run-journal.sh
   nm_gate   # imprime la décision ; son code de sortie commande la suite
   ```

   - **0 — continuer** : lance le lot normalement (étape 1).
   - **1 — pause** : **finis le lot déjà en cours** (ne tue aucun agent : pas de branche orpheline),
     puis **ne lance plus de lot**. Ré-interroge `nm_gate` périodiquement ; reprends quand il repasse
     à 0 (après `unpause`). La pause d'origine **humaine** n'est levée **que** par un humain.
   - **2 — arrêt** : ne lance **aucun** agent, clos proprement le run et termine par le compte rendu.
     Indique **comment reprendre** : relancer `scripts/run-jalon.sh "<jalon>" --authorize` repartira
     du `main` à jour (les PR déjà mergées ne sont pas refaites ; un `stop` est terminal pour *ce* run).
   - **3 — plus rien à faire** : le jalon est vidé → compte rendu final.
   - **4 — quota épuisé** : ne lance aucun agent ; `nm_gate` imprime l'heure de reprise. Attends
     cette échéance (ou que le superviseur appelle `quota clear`), puis ré-interroge le gate. Une
     retenue de **quota** se lève seule à l'échéance ; elle ne masque jamais une pause humaine.

1. **Développement en parallèle** : lance un sous-agent **`dev-ticket`** par ticket prêt du lot
   (≤ `--max-parallel`), **tous dans un seul message** (c'est ce qui les fait travailler en même
   temps), chacun avec ces deux paramètres, **non négociables** :

   - `isolation: "worktree"` — un worktree isolé par agent, sinon leurs branches se marchent dessus ;
   - `run_in_background: false` — sous `claude -p` (lanceur `scripts/run-jalon.sh`), le processus
     **s'arrête dès que tu cesses d'écrire** : un agent lancé en arrière-plan meurt alors au milieu
     de son ticket, sans PR. Au premier plan, les agents d'un même message tournent quand même en
     parallèle, et l'appel ne te rend la main qu'une fois **tous** leurs comptes rendus reçus.

   **Ne termine jamais ton tour tant qu'un agent du lot n'a pas rendu son compte rendu** — ni pour
   annoncer le lancement, ni pour un point d'étape.

   Pour un ticket **sensible**, **recopie le marqueur d'autorisation** dans le prompt — sinon
   l'agent refuse par fail-safe. Chaque prompt est autonome (l'agent ne voit pas cette conversation) :

   ```
   Agent(subagent_type="dev-ticket", isolation="worktree", run_in_background=false,
         prompt="Traite l'issue #<N>. <contraintes éventuelles>
   NM_RUN_ID=<NM_RUN_ID> (exporte-le avant tes appels nm_log_phase).
   AUTORISATION-RUN: <NM_RUN_ID> — validation humaine groupée accordée. Tickets P0/security couverts.")
   ```

2. **Validation QA — la porte du merge** : l'agent dev ouvre sa PR **sans** le label
   `auto-merge`. Dès qu'il a livré, lance un sous-agent **`qa-ticket`** dessus (même règle :
   `run_in_background: false` ; pas besoin de worktree, la QA ne modifie rien) :

   ```
   Agent(subagent_type="qa-ticket", run_in_background=false,
         prompt="Vérifie la PR #<PR> pour l'issue #<N>. NM_RUN_ID=<NM_RUN_ID>.")
   ```

   - **PASS** → la QA a posé le label `auto-merge` : la CI verte fusionne la PR.
   - **FAIL** → aucun label : la PR ne peut pas être fusionnée. Renvoie le ticket à un agent dev
     (mêmes paramètres qu'en 1, sur la branche existante) avec le motif, puis re-QA. Ne pose jamais
     `auto-merge` toi-même et ne merge jamais un `FAIL`.

   Si une PR du lot porte `auto-merge` **sans** commentaire `✅ QA PASS`, retire le label
   (`gh pr edit <PR> --remove-label auto-merge`) et fais passer la QA : un merge ne précède jamais
   sa QA.

3. **Sérialiser les merges** : attends que les PR `PASS` du lot soient mergées (CI verte, `gh pr
   view <PR> --json state`), puis **re-synchronise `main`** dans le dépôt principal
   (`git switch main && git pull --ff-only`) avant d'attaquer le lot suivant : les worktrees du lot
   suivant partent de `origin/main`, qui doit porter le lot précédent.

4. **Boucle** jusqu'à ce que le jalon soit vidé, ou que seuls restent des tickets **réellement**
   bloqués (dépendance non résolue, ou QA FAIL non corrigeable). Il n'y a **plus** de point d'arrêt
   humain en cours de run : l'unique validation a eu lieu à l'étape 3.0. Avec **`--max-lots N`**,
   arrête-toi **proprement dès N lots traités** (sans tuer d'agent en cours ni couper une PR de son
   cycle QA/CI) et passe au compte rendu : le superviseur te rappellera pour le lot suivant.

### 4. Compte rendu de run

Termine par un **tableau** (c'est le journal d'audit du run) :

| Ticket | Type | Agent dev | PR | CI | QA | Statut |
|--------|------|-----------|----|----|----|--------|
| #N | … | … | #PR | ✅/❌ | PASS/FAIL | mergé / en attente / bloqué |

Puis liste explicitement les tickets **non traités** et la raison (bloqué / validation humaine requise).

## Journal de run (observabilité)

Quand tu es lancé via `scripts/run-jalon.sh`, un run est déjà initialisé (`NM_RUN_ID` exporté,
dossier sous `.nickmare/runs/`). Tu peux aussi l'initialiser toi-même. **Consigne les transitions
que les agents ne couvrent pas** (mise en file, blocage, merge, fin), pour que le dashboard
(`scripts/run-dashboard.sh`) reflète le run en direct :

```
source scripts/lib/run-journal.sh
nm_log_phase <N> queued  --agent orchestrateur --detail "<titre court>"   # ticket prêt, en attente d'un agent
nm_log_phase <N> blocked --agent orchestrateur --detail "<dépendance #M non résolue>"   # bloqué
nm_log_phase <N> merge   --agent orchestrateur --pr <PR>   # CI verte, fusion en cours
nm_log_phase <N> done    --agent orchestrateur --pr <PR>   # PR mergée, issue fermée
```

Les agents dev/QA émettent `dev`/`tests`/`fix`/`qa` eux-mêmes. Le journal est **append-only** et ne
contient aucun secret ; il ne remplace pas le journal d'audit produit (c'est l'observabilité du
**workflow de dev**). Émission best-effort : une erreur de journalisation ne doit jamais
interrompre le run.

### Piloter un run en cours (pause / arrêt / quota)

L'état de contrôle vit dans `<run>/control.json` (écriture atomique). Chaque changement est
journalisé (`paused` / `interrupted`) et apparaît en **bannière** sur le dashboard. Tu consultes ce
contrôle via `nm_gate` (étape 3.1.0) ; un humain — ou le superviseur de quota (#49) — le pilote
ainsi :

```
nm_pause  --reason "revue manuelle"   # pause d'origine humaine (gate → 1)
nm_unpause                            # lève la pause humaine ; une pause quota reste
nm_unpause --all                      # lève toutes les pauses (humaine + quota)
nm_stop   --reason "fin de journée"   # arrêt du run (gate → 2) ; terminal pour ce run
nm_status                             # état lisible + décision courante du gate
nm_quota hold  --until +90m           # retenue de quota avec reprise (gate → 4)
nm_quota clear                        # lève la retenue de quota (ne touche pas la pause humaine)
```

## Règles non négociables (cf. `docs/ARCHITECTURE.md` §3 & §11, `docs/TESTING.md`)

- **Human-in-the-loop pour le critique** : une **autorisation humaine groupée unique** au lancement
  (étape 3.0, drapeau `--authorize` ou accord explicite en session) couvre les tickets
  `type:security`/`prio:P0` et le jalon de revue #17. Sans elle, le run ne démarre pas ; avec elle,
  l'orchestrateur enchaîne **sans redemander**. L'humain ne nomme **jamais** les tickets un par un.
- **Non destructif / fail-safe** : au moindre doute (dépendance non résolue, conflit, QA ambigu),
  **arrête-toi** au lieu de forcer.
- **QA avant merge** : le label `auto-merge` n'est posé que par l'agent QA, sur `PASS`.
- **CI jamais contournée** : le merge reste piloté par le label `auto-merge` + CI verte ; tu ne
  forces jamais de merge manuel.
- **Traçabilité** : le compte rendu de run consigne qui a fait quoi, quelle PR, quel verdict.
