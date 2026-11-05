#!/usr/bin/env python3
"""Superviseur de run de jalon (issue #49) — limite d'usage et reprise automatique.

Un jalon dure souvent plus que la fenêtre d'usage Claude de cinq heures. Quand elle
se referme, la session ``claude -p`` qui **orchestre** meurt : elle ne peut ni
attendre, ni se relancer. Ce superviseur vit **hors** de Claude Code : il enchaîne
les lots « un lot par appel », détecte la limite d'usage, attend le rafraîchissement
de la fenêtre, puis relance — jusqu'à ce que le jalon soit vidé (gate ``idle``) ou
qu'une borne soit atteinte.

Modèle repris de *Spa & Booking* (``scripts/milestone_supervise.py``), seul dispositif
interne dont la reprise après quota est **prouvée en réel**. À l'inverse, *hotelerie*
a montré l'écueil : sa reprise reposait sur l'outil ``Workflow``, absent en ``claude -p``.
Ici, aucune dépendance à un outil interne : une simple boucle de processus.

Boucle (``un lot par appel``) ::

    tant que le gate dit « continuer » :
        réconcilier (le dépôt fait foi : PR ouvertes, worktrees, branches)
        claude -p "/run-jalon <jalon> --authorize --max-lots 1" \\
                  --output-format stream-json --verbose
        surveiller le flux stream-json :
          - refus de quota (rate_limit_event status=rejected) -> quota hold + attente
          - fenêtre déjà ≥ 80 % dans les 5 premières minutes -> abandon avant agents
          - silence prolongé / délai max dépassé -> coupure de l'appel
        bilan, puis on recommence

Garde-fous (cf. ``docs/ARCHITECTURE.md`` §3 & §11) :

* La reprise **n'élargit jamais** l'autorisation : elle rejoue l'autorisation groupée
  du lancement (``--authorize``), sans plus.
* Aucune relance ne contourne la QA ni la CI (merge toujours par ``QA PASS`` + CI verte) :
  le superviseur ne merge rien, il relance seulement l'orchestrateur.
* Fail-safe : en cas d'état incohérent (réconciliation impossible), le superviseur
  s'arrête et le journalise plutôt que de forcer. Une pause **humaine** posée pendant
  l'attente de quota n'est **jamais** levée par la reprise (seul ``quota`` l'est).

Observabilité : battement ``<run>/supervisor.alive`` (horodaté) et journal
``<run>/supervisor.log`` ; les transitions marquantes sont aussi écrites dans le
journal de run append-only (``run_journal.log_phase`` sur le ticket 0).

Interpréteur : s'appuie sur ``scripts/run_journal.py`` (issue #48) pour le contrôle
du run (gate, quota hold/clear) — **sans le réimplémenter**.

Préflight & veille Windows (issue #50)
--------------------------------------

Un ``claude -p`` lancé sans surveillance échoue **en silence** si ses commandes ne
sont pas autorisées (aucune invite de permission ne peut y être répondue), et le
superviseur ne survit ni à un terminal fermé, ni à un plantage, ni à un redémarrage
ou une mise en veille. On ajoute donc :

* **Préflight** (``--preflight``) : ``claude``/``gh`` présents, ``gh auth status`` OK,
  dossier de lancement dans un dépôt git, et dossier **approuvé sous la casse exacte**
  dans ``~/.claude.json`` (avertit si ``d:/…`` et ``D:/…`` divergent — leçon *hotelerie*
  du 19/10/2026 : 22 autorisations ignorées car la casse du chemin ne correspondait pas).
  Échec ⇒ report, **pas de lancement**. Le mode normal lance d'abord ce préflight.
* **Veille Windows** (``--arm`` / ``--disarm`` / ``--state`` / ``--wake``) : une tâche
  planifiée (``schtasks``, sans droits admin) lancée via un ``.cmd`` (chemins avec
  espaces) réveille le superviseur toutes les 5 min, avec les réglages d'alimentation
  corrigés (démarrage sur batterie, ``StartWhenAvailable`` — leçon *Spa & Booking*).
  À chaque réveil : reste-t-il du travail, un superviseur bat-il, le quota est-il revenu ?
  → relance détachée **seulement** si (travail restant ∧ aucun battement ∧ quota revenu).
  Auto-désarmement : jalon vidé, ``stop`` ou pause ``human``, run supprimé, ou armement
  de plus de 14 jours. Une pause **humaine** n'est jamais levée par la veille.

CLI ::

    python run_supervise.py "<titre du jalon>" [options]   # superviseur (préflight d'abord)
    python run_supervise.py --preflight                    # vérifie l'environnement, ne lance rien
    python run_supervise.py "<jalon>" --arm                # arme la veille Windows (tâche planifiée)
    python run_supervise.py --disarm   [--run-id ID]       # désarme la veille
    python run_supervise.py --state    [--run-id ID]       # état de la veille + conditions de relance
    python run_supervise.py --wake     [--run-id ID]       # réveil (appelé par la tâche planifiée)

Options (bornes de sûreté) ::

    --max-parallel N     agents dev simultanés passés à /run-jalon (défaut 2)
    --lots-per-call N    lots par appel claude (défaut 1 — « un lot par appel »)
    --max-legs N         nombre max d'appels claude (0 = illimité)
    --max-hours H        plafond de durée du superviseur (0 = illimité)
    --patience N         arrêt après N appels consécutifs sans aucun ticket mergé (0 = off)
    --max-call SECONDS   délai max d'un appel claude (défaut 7200)
    --max-silence SEC    coupure si l'appel reste muet SEC secondes (défaut 600)
    --window SECONDS     fenêtre d'usage par défaut, sans resetsAt (défaut 18000 = 5 h)
    --margin SECONDS     marge ajoutée après le reset avant de reprendre (défaut 120)
    --prune-worktrees    supprime les worktrees PROPRES dont la PR est mergée
    --run-id ID          run ciblé (défaut : $NM_RUN_ID, sinon le plus récent)

Variables d'environnement (surtout pour les tests) :

    NM_CLAUDE_CMD    commande claude (shlex-split ; défaut : ``claude``)
    NM_GH_CMD        commande gh (défaut : ``gh``)
    NM_GIT_CMD       commande git (défaut : ``git``)
    NM_SCHTASKS_CMD  commande schtasks pour la veille (défaut : ``schtasks`` ; bouchonnée en test)
    NM_CLAUDE_JSON   chemin du ``~/.claude.json`` à inspecter (défaut : ``~/.claude.json``)
    NM_SKIP_PREFLIGHT=1  saute le préflight avant lancement (ne jamais utiliser en prod)
    NM_RUN_ID        run ciblé
    NM_RUNS_ROOT     racine des runs (hérité de run_journal.py)
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_journal  # noqa: E402  (même dossier)

# Sortie UTF-8 garantie (accents des messages), comme run_journal.py/run_dashboard.py.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# --- Constantes de réglage ---------------------------------------------------

OPENING_WINDOW_SECONDS = 300      # « 5 premières minutes » de la garde d'ouverture
OPENING_USAGE_THRESHOLD = 0.80    # « fenêtre consommée à ≥ 80 % »
DEFAULT_WINDOW_SECONDS = 5 * 3600  # fenêtre d'usage par défaut (sans resetsAt)
DEFAULT_MARGIN_SECONDS = 120      # marge après le reset avant de reprendre
DEFAULT_MAX_CALL_SECONDS = 2 * 3600
DEFAULT_MAX_SILENCE_SECONDS = 600
DEFAULT_PATIENCE = 3
PAUSE_POLL_SECONDS = 30           # période de ré-interrogation du gate en pause
QUOTA_POLL_SECONDS = 60           # découpage du sommeil pendant l'attente de quota

# Issues d'un appel claude (leg = un appel = un lot).
LEG_OK = "ok"                     # l'appel s'est terminé normalement
LEG_QUOTA = "quota"               # refus de quota (rate_limit_event rejected / fallback)
LEG_OPENING_ABORT = "opening_abort"  # fenêtre déjà ≥ 80 % à l'ouverture → abandon
LEG_SILENT = "silent"             # appel muet coupé
LEG_TIMEOUT = "timeout"           # délai max par appel dépassé
LEG_ERROR = "error"               # sortie non nulle sans signal de quota

# Issues de la boucle du superviseur.
RUN_DONE = "done"                 # gate idle : plus rien à faire → jalon vidé
RUN_STOPPED = "stopped"           # arrêt humain (gate stop)
RUN_MAX_LEGS = "max_legs"
RUN_MAX_HOURS = "max_hours"
RUN_PATIENCE = "patience"
RUN_INCOHERENT = "incoherent"     # réconciliation impossible → fail-safe


# --- Analyse du flux stream-json ---------------------------------------------


def extract_rate_limit(obj) -> dict | None:
    """Extrait l'objet de limite d'usage d'un événement stream-json, ou ``None``.

    Tolère les formes : événement de type ``rate_limit_event`` à plat, ou bloc
    imbriqué sous ``rate_limit_event`` / ``rate_limit`` / ``rateLimit``.
    """
    if not isinstance(obj, dict):
        return None
    if obj.get("type") == "rate_limit_event":
        return obj
    for key in ("rate_limit_event", "rate_limit", "rateLimit"):
        val = obj.get(key)
        if isinstance(val, dict):
            return val
    return None


def rate_limit_usage_fraction(rl: dict) -> float | None:
    """Fraction de fenêtre consommée (0..1) d'après un bloc de limite, ou ``None``.

    Accepte un pourcentage (``usedPercent``/``percentUsed``/``percent``), un couple
    ``used``/``limit``, ou ``remaining``/``limit``.
    """
    for key in ("usedPercent", "percentUsed", "percent", "usage_percent"):
        val = rl.get(key)
        if isinstance(val, (int, float)):
            return float(val) / 100.0
    used, limit = rl.get("used"), rl.get("limit")
    if isinstance(used, (int, float)) and isinstance(limit, (int, float)) and limit > 0:
        return float(used) / float(limit)
    remaining = rl.get("remaining")
    if isinstance(remaining, (int, float)) and isinstance(limit, (int, float)) and limit > 0:
        return 1.0 - float(remaining) / float(limit)
    return None


def parse_resets_at(rl: dict) -> float | None:
    """Échéance de rouverture de la fenêtre (epoch), ou ``None``.

    Accepte un epoch (int/float) ou une chaîne (ISO 8601, epoch textuel, ``+90m``),
    sous ``resetsAt`` / ``resets_at`` / ``reset_at`` / ``resets``.
    """
    for key in ("resetsAt", "resets_at", "reset_at", "resets"):
        val = rl.get(key)
        if val is None:
            continue
        if isinstance(val, (int, float)):
            return float(val)
        try:
            return run_journal.parse_when(str(val))
        except ValueError:
            continue
    return None


def text_signals_quota(text: str) -> bool:
    """Filet de secours : la limite d'usage transparaît dans du texte libre.

    Motifs : « usage limit reached », « hit your … limit », ou un HTTP 429 **en
    contexte** de limite (le simple nombre 429 ne suffit pas).
    """
    t = text or ""
    if re.search(r"usage limit reached", t, re.IGNORECASE):
        return True
    if re.search(r"hit your .{0,40}?limit", t, re.IGNORECASE):
        return True
    if "429" in t and re.search(r"rate.?limit|too many requests|usage", t, re.IGNORECASE):
        return True
    return False


# --- Un appel claude (leg) ---------------------------------------------------


@dataclass
class LegOutcome:
    """Résultat d'un appel claude : type d'issue + éventuelle échéance de reset."""
    kind: str
    resets_at: float | None = None
    returncode: int | None = None
    detail: str = ""


def _terminate(proc: subprocess.Popen) -> None:
    """Arrête un sous-processus claude proprement (puis de force si besoin)."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass


def claude_argv(prompt: str, claude_cmd=None) -> list[str]:
    """Commande d'un appel orchestrateur : ``claude -p <prompt> --output-format …``.

    ``claude_cmd`` accepte une liste (tests) ou une chaîne (``NM_CLAUDE_CMD``)."""
    base = claude_cmd if claude_cmd is not None else os.environ.get("NM_CLAUDE_CMD") or "claude"
    return [*_split(base), "-p", prompt,
            "--output-format", "stream-json", "--verbose"]


def run_leg(prompt: str, *, claude_cmd=None,
            max_call: float = DEFAULT_MAX_CALL_SECONDS,
            max_silence: float = DEFAULT_MAX_SILENCE_SECONDS,
            opening_window: float = OPENING_WINDOW_SECONDS,
            opening_threshold: float = OPENING_USAGE_THRESHOLD,
            now=time.time, on_line=None) -> LegOutcome:
    """Lance **un** appel claude et surveille son flux ``stream-json``.

    Retourne un :class:`LegOutcome`. Décisions, par ordre de priorité :

    * ``rate_limit_event`` avec ``status == "rejected"`` → ``LEG_QUOTA`` (avec
      ``resets_at`` si connu) : on tue l'appel, l'appelant pose un ``quota hold``.
    * limite d'usage ≥ seuil dans les ``opening_window`` premières secondes →
      ``LEG_OPENING_ABORT`` : on abandonne **avant** que l'appel ne lance des agents.
    * aucun octet pendant ``max_silence`` → ``LEG_SILENT`` (appel muet coupé).
    * durée > ``max_call`` → ``LEG_TIMEOUT``.
    * sinon, à la fin : motifs texte de quota (filet) → ``LEG_QUOTA`` ; code de
      retour non nul → ``LEG_ERROR`` ; sinon ``LEG_OK``.
    """
    argv = claude_argv(prompt, claude_cmd)
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace", bufsize=1)
    except OSError as exc:
        return LegOutcome(LEG_ERROR, detail=f"claude introuvable : {exc}")

    q: "queue.Queue[tuple[str, str | None]]" = queue.Queue()

    def reader(stream):
        try:
            for line in stream:
                q.put(("line", line))
        finally:
            q.put(("eof", None))

    reader_thread = threading.Thread(target=reader, args=(proc.stdout,), daemon=True)
    reader_thread.start()

    call_start = now()
    deadline = call_start + max_call if max_call else None
    stdout_accum: list[str] = []
    outcome: LegOutcome | None = None
    try:
        while True:
            current = now()
            if deadline is not None and current >= deadline:
                _terminate(proc)
                outcome = LegOutcome(LEG_TIMEOUT,
                                     detail=f"délai max d'appel dépassé ({max_call}s)")
                break
            wait = max_silence if max_silence else QUOTA_POLL_SECONDS
            if deadline is not None:
                wait = min(wait, max(0.05, deadline - current))
            try:
                kind, payload = q.get(timeout=wait)
            except queue.Empty:
                _terminate(proc)
                outcome = LegOutcome(LEG_SILENT,
                                     detail=f"appel muet coupé (silence > {max_silence}s)")
                break
            if kind == "eof":
                break
            line = payload or ""
            stdout_accum.append(line)
            if on_line is not None:
                try:
                    on_line(line)
                except Exception:  # noqa: BLE001 — l'observateur ne doit jamais tuer le leg
                    pass
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue  # ligne non-JSON : ignorée (fail-safe)
            rl = extract_rate_limit(obj)
            if rl is None:
                continue
            if rl.get("status") == "rejected":
                _terminate(proc)
                outcome = LegOutcome(LEG_QUOTA, resets_at=parse_resets_at(rl),
                                     detail="refus de quota (rate_limit_event rejected)")
                break
            frac = rate_limit_usage_fraction(rl)
            if (frac is not None and frac >= opening_threshold
                    and (now() - call_start) <= opening_window):
                _terminate(proc)
                outcome = LegOutcome(LEG_OPENING_ABORT, resets_at=parse_resets_at(rl),
                                     detail=f"fenêtre déjà consommée à {frac * 100:.0f}% "
                                            "à l'ouverture — abandon avant lancement d'agent")
                break

        if outcome is None:
            # Fin normale du flux (eof) : on récupère le code de retour et stderr.
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                _terminate(proc)
            stderr = ""
            try:
                if proc.stderr is not None:
                    stderr = proc.stderr.read() or ""
            except OSError:
                pass
            combined = "".join(stdout_accum) + "\n" + stderr
            if text_signals_quota(combined):
                outcome = LegOutcome(LEG_QUOTA, resets_at=None, returncode=proc.returncode,
                                     detail="limite d'usage détectée dans le texte "
                                            "(filet de secours)")
            elif proc.returncode not in (0, None):
                outcome = LegOutcome(LEG_ERROR, returncode=proc.returncode,
                                     detail=f"appel claude terminé en code {proc.returncode}")
            else:
                outcome = LegOutcome(LEG_OK, returncode=proc.returncode)
    finally:
        # Le process est mort (eof ou _terminate) : le lecteur se termine seul.
        # On l'attend avant de fermer les tuyaux pour éviter une lecture sur un
        # flux fermé dans le thread.
        reader_thread.join(timeout=5)
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
    return outcome


# --- Réconciliation : le dépôt fait foi --------------------------------------

_BRANCH_TICKET_RE = re.compile(r"^(?:feat|infra|fix|test|docs|sec)/(\d+)-")
_CLOSES_RE = re.compile(r"\bcloses\s+#(\d+)", re.IGNORECASE)


class ReconcileError(Exception):
    """État du dépôt impossible à lire → fail-safe : le superviseur s'arrête."""


@dataclass
class Worktree:
    path: str
    branch: str | None
    dirty: bool
    locked: bool
    primary: bool = False


@dataclass
class Reconciliation:
    """Vue du dépôt à un instant : PR ouvertes/mergées, worktrees."""
    open_prs: list[dict] = field(default_factory=list)
    merged_prs: list[dict] = field(default_factory=list)
    worktrees: list[Worktree] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def tickets_in_progress(self) -> set[int]:
        """Tickets portés par une PR **ouverte** → à ne pas relancer de zéro."""
        return {t for pr in self.open_prs if (t := _pr_ticket(pr)) is not None}

    def merged_tickets(self) -> set[int]:
        return {t for pr in self.merged_prs if (t := _pr_ticket(pr)) is not None}

    def prunable_worktrees(self) -> list[Worktree]:
        """Worktrees sûrs à supprimer : **propres**, non verrouillés, non primaires,
        et dont la branche porte un ticket **mergé**.

        Un worktree **sale** n'est **jamais** prunable (travail non commité à préserver).
        """
        merged = self.merged_tickets()
        out = []
        for wt in self.worktrees:
            if wt.primary or wt.dirty or wt.locked or not wt.branch:
                continue
            ticket = _branch_ticket(wt.branch)
            if ticket is not None and ticket in merged:
                out.append(wt)
        return out


def _pr_ticket(pr: dict) -> int | None:
    """Numéro de ticket d'une PR : via ``Closes #N`` dans le corps, sinon la branche."""
    body = pr.get("body") or ""
    m = _CLOSES_RE.search(body)
    if m:
        return int(m.group(1))
    return _branch_ticket(pr.get("headRefName") or "")


def _branch_ticket(branch: str) -> int | None:
    m = _BRANCH_TICKET_RE.match(branch or "")
    return int(m.group(1)) if m else None


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace")


def _split(cmd) -> list[str]:
    """Normalise une commande configurable (``gh`` / ``git`` / ``claude``) en argv.

    Accepte une **liste** (prise telle quelle) ou une **chaîne** (découpée en
    champs). La forme liste évite tout souci de citation ou d'échappement
    (chemins Windows avec ``\\``, espaces) et sert surtout aux tests ; la forme
    chaîne reste pratique en configuration (``NM_CLAUDE_CMD="python fake.py"``)."""
    if cmd is None:
        return []
    if isinstance(cmd, (list, tuple)):
        return [str(x) for x in cmd]
    return shlex.split(cmd)


def _gh_prs(gh_cmd: str, state: str) -> list[dict]:
    res = _run([*_split(gh_cmd), "pr", "list", "--state", state, "--limit", "100",
                "--json", "number,headRefName,body"])
    if res.returncode != 0:
        return []
    try:
        data = json.loads(res.stdout or "[]")
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) else []


def list_worktrees(git_cmd: str = "git", repo: str = ".") -> list[Worktree]:
    """Inventaire des worktrees via ``git worktree list --porcelain`` (+ propreté).

    Lève :class:`ReconcileError` si git est injoignable (fail-safe de l'appelant).
    """
    res = _run([*_split(git_cmd), "-C", repo, "worktree", "list", "--porcelain"])
    if res.returncode != 0:
        raise ReconcileError(f"`git worktree list` a échoué : {res.stderr.strip()}")
    entries: list[dict] = []
    cur: dict | None = None
    for line in res.stdout.splitlines():
        if line.startswith("worktree "):
            if cur:
                entries.append(cur)
            cur = {"path": line[len("worktree "):], "branch": None,
                   "locked": False, "detached": False}
        elif cur is None:
            continue
        elif line.startswith("branch "):
            cur["branch"] = line[len("branch "):].replace("refs/heads/", "")
        elif line.startswith("locked"):
            cur["locked"] = True
        elif line.startswith("detached"):
            cur["detached"] = True
    if cur:
        entries.append(cur)

    worktrees = []
    for i, e in enumerate(entries):
        worktrees.append(Worktree(
            path=e["path"], branch=e.get("branch"),
            dirty=_is_dirty(git_cmd, e["path"]),
            locked=e["locked"], primary=(i == 0),
        ))
    return worktrees


def _is_dirty(git_cmd: str, path: str) -> bool:
    """Un worktree est « sale » s'il a des changements non commités (suivis ou non)."""
    res = _run([*_split(git_cmd), "-C", path, "status", "--porcelain"])
    if res.returncode != 0:
        # Inaccessible : on le considère sale par sûreté (jamais supprimé).
        return True
    return bool(res.stdout.strip())


def reconcile(milestone: str, *, gh_cmd: str | None = None,
              git_cmd: str = "git", repo: str = ".") -> Reconciliation:
    """Lit l'état du dépôt (fait foi) : PR ouvertes/mergées et worktrees.

    Ne touche à rien : c'est une **lecture**. L'appelant décide ensuite quoi
    purger (jamais un worktree sale) via :meth:`Reconciliation.prunable_worktrees`.
    """
    gh = gh_cmd if gh_cmd is not None else os.environ.get("NM_GH_CMD") or "gh"
    recon = Reconciliation()
    recon.worktrees = list_worktrees(git_cmd, repo)  # peut lever ReconcileError
    recon.open_prs = _gh_prs(gh, "open")
    recon.merged_prs = _gh_prs(gh, "merged")
    in_progress = sorted(recon.tickets_in_progress())
    if in_progress:
        recon.notes.append("PR ouvertes (tickets non relancés de zéro) : "
                           + ", ".join(f"#{t}" for t in in_progress))
    dirty = [wt.path for wt in recon.worktrees if wt.dirty and not wt.primary]
    if dirty:
        recon.notes.append(f"worktrees sales conservés : {len(dirty)}")
    return recon


def prune_worktrees(recon: Reconciliation, *, git_cmd: str = "git",
                    repo: str = ".", dry_run: bool = False) -> list[str]:
    """Supprime les worktrees **prunables** (jamais un sale). Renvoie les chemins traités.

    ``dry_run`` : renvoie la liste sans rien supprimer.
    """
    removed = []
    for wt in recon.prunable_worktrees():
        removed.append(wt.path)
        if dry_run:
            continue
        _run([*_split(git_cmd), "-C", repo, "worktree", "remove", "--", wt.path])
    return removed


# --- Le superviseur ----------------------------------------------------------


@dataclass
class SuperviseOptions:
    max_parallel: int = 2
    lots_per_call: int = 1
    max_legs: int = 0
    max_hours: float = 0.0
    patience: int = DEFAULT_PATIENCE
    max_call: float = DEFAULT_MAX_CALL_SECONDS
    max_silence: float = DEFAULT_MAX_SILENCE_SECONDS
    window: float = DEFAULT_WINDOW_SECONDS
    margin: float = DEFAULT_MARGIN_SECONDS
    prune_worktrees: bool = False


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class Supervisor:
    """Boucle « un lot par appel » avec détection de quota et reprise.

    Les points lents ou à effet de bord sont **injectables** (pour les tests) :
    ``now`` / ``sleep`` (horloge), ``leg_runner`` (appel claude), ``gate_fn``
    (décision d'avant-lot), ``progress_fn`` (mesure de progrès pour la patience).
    Par défaut, ils s'appuient sur le vrai temps, le vrai :func:`run_leg` et le
    contrôle de run de ``run_journal`` (issue #48).
    """

    def __init__(self, milestone: str, options: SuperviseOptions, *,
                 run_id: str | None = None, repo: str = ".",
                 now=time.time, sleep=time.sleep,
                 leg_runner=None, gate_fn=None, progress_fn=None,
                 reconcile_fn=None):
        if not milestone:
            raise ValueError("titre de jalon requis")
        self.milestone = milestone
        self.opt = options
        self.run_id = run_id or os.environ.get("NM_RUN_ID") or None
        self.repo = repo
        self.now = now
        self.sleep = sleep
        self._leg_runner = leg_runner or self._default_leg_runner
        self._gate_fn = gate_fn or (lambda: run_journal.gate(self.run_id))
        self._progress_fn = progress_fn or self._default_progress
        self._reconcile_fn = reconcile_fn or self._default_reconcile
        self.legs = 0

    # -- observabilité --------------------------------------------------------

    def _run_dir(self) -> Path | None:
        try:
            return run_journal.run_dir(self.run_id)
        except Exception:  # noqa: BLE001
            return None

    def _heartbeat(self, state: str, **extra) -> None:
        """Battement ``supervisor.alive`` (horodaté, atomique). Best-effort."""
        d = self._run_dir()
        if d is None:
            return
        beat = {"pid": os.getpid(), "ts": run_journal.now_iso(),
                "state": state, "legs": self.legs, **extra}
        try:
            _atomic_write(d / "supervisor.alive",
                          json.dumps(beat, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _log(self, message: str, *, phase: str | None = None) -> None:
        """Journal du superviseur (``supervisor.log``) + console. Best-effort.

        Si ``phase`` est donnée, trace aussi dans le journal de run append-only
        (ticket 0, agent « superviseur ») pour que le dashboard reflète l'état.
        """
        stamp = run_journal.now_iso()
        print(f"[superviseur {stamp}] {message}")
        d = self._run_dir()
        if d is not None:
            try:
                with (d / "supervisor.log").open("a", encoding="utf-8") as fh:
                    fh.write(f"{stamp} {message}\n")
            except OSError:
                pass
        if phase is not None:
            try:
                run_journal.log_phase(0, phase, agent="superviseur", detail=message)
            except Exception:  # noqa: BLE001 — journalisation best-effort
                pass

    # -- défauts injectables --------------------------------------------------

    def _default_leg_runner(self) -> LegOutcome:
        prompt = (f'/run-jalon "{self.milestone}" --authorize '
                  f'--max-lots {self.opt.lots_per_call} '
                  f'--max-parallel {self.opt.max_parallel}')
        return run_leg(prompt, max_call=self.opt.max_call,
                       max_silence=self.opt.max_silence,
                       now=self.now, on_line=lambda _l: self._heartbeat("leg-stream"))

    def _default_progress(self) -> int | None:
        """Nombre d'issues fermées du jalon (proxy de « tickets mergés »)."""
        gh = os.environ.get("NM_GH_CMD") or "gh"
        res = _run([*_split(gh), "issue", "list", "--milestone", self.milestone,
                    "--state", "closed", "--json", "number", "--limit", "500"])
        if res.returncode != 0:
            return None
        try:
            data = json.loads(res.stdout or "[]")
        except (ValueError, TypeError):
            return None
        return len(data) if isinstance(data, list) else None

    # -- contrôle du quota (délègue à run_journal, issue #48) -----------------

    def _hold_quota(self, resets_at: float | None, reason: str) -> float:
        """Pose une retenue de quota jusqu'à ``resets_at + marge`` (ou fenêtre + marge).

        Renvoie l'échéance (epoch) retenue. Délègue à ``run_journal`` : ne
        réimplémente pas le contrôle de run.
        """
        base = resets_at if resets_at is not None else self.now() + self.opt.window
        until = base + self.opt.margin
        try:
            run_journal.control_quota_hold(run_journal.iso_utc(until),
                                            by="superviseur", reason=reason,
                                            run_id=self.run_id)
        except Exception as exc:  # noqa: BLE001 — run absent (ex. tests ciblés)
            self._log(f"impossible de poser la retenue de quota : {exc}")
        self._log(f"quota épuisé — reprise prévue à {run_journal.iso_utc(until)} "
                  f"({reason})", phase="paused")
        return until

    def _wait_for_quota(self) -> str:
        """Attend la réouverture de la fenêtre puis **lève la retenue de quota**.

        Une pause **humaine** n'est jamais levée ici (``quota clear`` n'y touche pas) :
        la reprise ne rouvre que le quota. Si un arrêt est demandé pendant l'attente,
        on renvoie ``RUN_STOPPED`` sans rien lever. Renvoie ``"resumed"`` sinon.
        """
        d = self._run_dir()
        while True:
            control = {}
            if d is not None:
                try:
                    control = run_journal.load_control(d)
                except run_journal.ControlCorrupt:
                    control = {}
            if control.get("signal") == "stop":
                self._log("arrêt demandé pendant l'attente de quota — on n'enchaîne pas")
                return RUN_STOPPED
            hold = run_journal.quota_hold_active(control, now=self.now())
            if hold is None:
                break  # fenêtre rouverte (échéance atteinte)
            left = float(hold["until"]) - self.now()
            if left <= 0:
                break
            self._heartbeat("quota-wait", until=hold.get("until_iso"))
            self.sleep(min(left, QUOTA_POLL_SECONDS))
        try:
            run_journal.control_quota_clear(by="superviseur", run_id=self.run_id)
        except Exception as exc:  # noqa: BLE001
            self._log(f"levée de quota impossible : {exc}")
        self._log("fenêtre d'usage rouverte — quota levé, reprise", phase="queued")
        return "resumed"

    # -- réconciliation -------------------------------------------------------

    def _default_reconcile(self) -> bool:
        """Réconcilie avant un appel. Renvoie ``False`` si l'état est incohérent.

        Le dépôt fait foi. On ne relance jamais un ticket dont la PR est ouverte,
        et on ne supprime jamais un worktree sale. Fail-safe : réconciliation
        impossible ⇒ on s'arrête.
        """
        try:
            recon = reconcile(self.milestone, repo=self.repo)
        except ReconcileError as exc:
            self._log(f"réconciliation impossible : {exc} — arrêt (fail-safe)",
                      phase="blocked")
            return False
        for note in recon.notes:
            self._log(f"réconciliation — {note}")
        if self.opt.prune_worktrees:
            removed = prune_worktrees(recon, repo=self.repo)
            if removed:
                self._log(f"worktrees propres mergés purgés : {len(removed)}")
        return True

    # -- boucle principale ----------------------------------------------------

    def run(self) -> str:
        start = self.now()
        no_progress = 0
        last_progress = self._progress_fn()
        self._log(f"superviseur démarré — jalon « {self.milestone} »", phase="queued")
        self._heartbeat("starting")

        while True:
            if self.opt.max_hours and (self.now() - start) >= self.opt.max_hours * 3600:
                self._log("plafond de durée atteint — arrêt", phase="interrupted")
                return self._finish(RUN_MAX_HOURS)
            if self.opt.max_legs and self.legs >= self.opt.max_legs:
                self._log(f"plafond de lots atteint ({self.opt.max_legs}) — arrêt",
                          phase="interrupted")
                return self._finish(RUN_MAX_LEGS)

            code, msg = self._gate_fn()
            if code == run_journal.GATE_STOP:
                self._log(f"gate : arrêt — {msg}", phase="interrupted")
                return self._finish(RUN_STOPPED)
            if code == run_journal.GATE_IDLE:
                self._log("gate : plus rien à faire — jalon vidé", phase="done")
                return self._finish(RUN_DONE)
            if code == run_journal.GATE_PAUSE:
                self._heartbeat("paused")
                self._log(f"gate : pause — {msg} ; on attend (sans lancer d'agent)")
                self.sleep(PAUSE_POLL_SECONDS)
                continue
            if code == run_journal.GATE_QUOTA:
                # Une retenue de quota est déjà posée : on attend sa levée.
                if self._wait_for_quota() == RUN_STOPPED:
                    return self._finish(RUN_STOPPED)
                continue

            # gate == continuer : réconcilier, puis un appel = un lot.
            if not self._reconcile_fn():
                return self._finish(RUN_INCOHERENT)

            self.legs += 1
            self._heartbeat("leg", leg=self.legs)
            self._log(f"lancement de l'appel #{self.legs} "
                      f"(/run-jalon --max-lots {self.opt.lots_per_call})")
            outcome = self._leg_runner()
            self._log(f"appel #{self.legs} terminé : {outcome.kind}"
                      + (f" — {outcome.detail}" if outcome.detail else ""))

            if outcome.kind in (LEG_QUOTA, LEG_OPENING_ABORT):
                self._hold_quota(outcome.resets_at, outcome.detail or outcome.kind)
                if self._wait_for_quota() == RUN_STOPPED:
                    return self._finish(RUN_STOPPED)
                continue  # le gate rejouera : une pause humaine éventuelle bloquera

            # Appel qui a réellement travaillé (ok/silent/timeout/error) : patience.
            progress = self._progress_fn()
            if progress is not None and last_progress is not None and progress > last_progress:
                no_progress = 0
                last_progress = progress
            elif progress is not None:
                no_progress += 1
                if last_progress is None:
                    last_progress = progress
                if self.opt.patience and no_progress >= self.opt.patience:
                    self._log(f"patience épuisée ({no_progress} appels sans merge) — arrêt",
                              phase="interrupted")
                    return self._finish(RUN_PATIENCE)

    def _finish(self, result: str) -> str:
        self._heartbeat("stopped", result=result)
        self._log(f"superviseur terminé — {result} ({self.legs} appel(s))")
        return result


# --- Préflight (issue #50) ---------------------------------------------------
#
# Un run sans surveillance ne peut répondre à aucune invite de permission : si une
# commande n'est pas autorisée (cf. .claude/settings.json), ``claude -p`` échoue en
# silence. Et l'approbation du dossier dans ``~/.claude.json`` se lit **sur la casse
# exacte** du chemin — ``d:/projet`` et ``D:/projet`` sont deux entrées distinctes
# (leçon *hotelerie* : 22 autorisations ignorées). Le préflight refuse tout lancement
# tant que l'environnement n'est pas sain (fail-safe).


@dataclass
class Check:
    """Un point de contrôle du préflight : nom, verdict, détail."""
    name: str
    ok: bool
    detail: str = ""


@dataclass
class PreflightResult:
    checks: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def report(self) -> list[str]:
        lines = ["Préflight du superviseur :"]
        for c in self.checks:
            lines.append(f"  [{'OK' if c.ok else 'KO'}] {c.name}"
                         + (f" — {c.detail}" if c.detail else ""))
        for w in self.warnings:
            lines.append(f"  ⚠ {w}")
        lines.append("verdict : " + ("prêt" if self.ok else "ÉCHEC — pas de lancement"))
        return lines


def _cmd_available(cmd) -> bool:
    """Vrai si la commande (chaîne ou liste) est résoluble en exécutable."""
    argv = _split(cmd)
    if not argv:
        return False
    exe = argv[0]
    return bool(shutil.which(exe)) or Path(exe).exists()


def _norm_path_key(p: str) -> str:
    """Normalise un chemin pour comparaison : séparateurs ``/``, sans slash final.

    **La casse est préservée** : c'est tout l'enjeu (``d:`` ≠ ``D:`` pour Claude Code)."""
    return str(p).replace("\\", "/").rstrip("/")


def load_claude_json(path=None) -> tuple[dict, str | None]:
    """Charge ``~/.claude.json`` (ou ``$NM_CLAUDE_JSON``). Renvoie (données, erreur)."""
    p = Path(path) if path else Path(os.environ.get("NM_CLAUDE_JSON")
                                     or (Path.home() / ".claude.json"))
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, f"~/.claude.json introuvable ({p})"
    except (OSError, ValueError) as exc:
        return {}, f"~/.claude.json illisible : {exc}"
    return (data if isinstance(data, dict) else {}), None


def check_approved_dir(claude_json: dict, launch_dir: str) -> tuple[bool, list[str]]:
    """Le dossier de lancement est-il approuvé **sous la casse exacte** ?

    Renvoie (approuvé, avertissements). Trois cas :

    * clé présente sous la casse exacte et non explicitement rejetée → approuvé ;
    * clé présente **sous une autre casse seulement** → NON approuvé + avertissement
      (Claude Code lira la casse exacte comme non approuvée : autorisations ignorées) ;
    * absente → NON approuvé + avertissement.
    """
    target = _norm_path_key(launch_dir)
    projects = claude_json.get("projects") if isinstance(claude_json, dict) else None
    keys = {}
    if isinstance(projects, dict):
        for k, v in projects.items():
            keys[_norm_path_key(k)] = v
    if target in keys:
        entry = keys[target]
        if isinstance(entry, dict) and entry.get("hasTrustDialogAccepted") is False:
            return False, [f"dossier {target} présent mais non approuvé "
                           "(hasTrustDialogAccepted=false)"]
        return True, []
    divergent = sorted(k for k in keys if k.lower() == target.lower())
    if divergent:
        return False, [
            f"dossier approuvé sous une AUTRE casse ({', '.join(divergent)}) mais PAS "
            f"sous la casse exacte du lancement (« {target} ») : Claude Code lira « {target} » "
            "comme NON approuvé et ignorera les autorisations (leçon hotelerie 19/10/2026)."]
    return False, [f"dossier « {target} » absent de ~/.claude.json : non approuvé "
                   "(aucune autorisation ne s'appliquera à un run sans surveillance)."]


def preflight(*, launch_dir=None, claude_cmd=None, gh_cmd=None, git_cmd=None,
              claude_json_path=None) -> PreflightResult:
    """Vérifie l'environnement d'un run sans surveillance. Ne lance rien.

    Les commandes sont **injectables** (tests) ; par défaut elles viennent de
    ``NM_CLAUDE_CMD`` / ``NM_GH_CMD`` / ``NM_GIT_CMD``.
    """
    launch_dir = launch_dir or os.getcwd()
    claude = claude_cmd if claude_cmd is not None else os.environ.get("NM_CLAUDE_CMD") or "claude"
    gh = gh_cmd if gh_cmd is not None else os.environ.get("NM_GH_CMD") or "gh"
    git = git_cmd if git_cmd is not None else os.environ.get("NM_GIT_CMD") or "git"
    res = PreflightResult()

    claude_ok = _cmd_available(claude)
    res.checks.append(Check("commande claude présente", claude_ok,
                            "" if claude_ok else f"introuvable : {claude}"))

    gh_ok = _cmd_available(gh)
    res.checks.append(Check("commande gh présente", gh_ok,
                            "" if gh_ok else f"introuvable : {gh}"))

    if gh_ok:
        auth = _run([*_split(gh), "auth", "status"])
        res.checks.append(Check("gh authentifié (gh auth status)", auth.returncode == 0,
                                "" if auth.returncode == 0
                                else "`gh auth status` a échoué (gh auth login ?)"))
    else:
        res.checks.append(Check("gh authentifié (gh auth status)", False, "gh absent"))

    git_res = _run([*_split(git), "-C", launch_dir, "rev-parse", "--is-inside-work-tree"])
    in_repo = git_res.returncode == 0 and git_res.stdout.strip() == "true"
    res.checks.append(Check("dossier de lancement dans un dépôt git", in_repo,
                            "" if in_repo else f"pas un dépôt git : {launch_dir}"))

    claude_json, cj_err = load_claude_json(claude_json_path)
    if cj_err:
        res.checks.append(Check("dossier approuvé dans ~/.claude.json (casse exacte)",
                                False, cj_err))
    else:
        approved, warns = check_approved_dir(claude_json, launch_dir)
        res.checks.append(Check("dossier approuvé dans ~/.claude.json (casse exacte)",
                                approved,
                                "" if approved else "non approuvé sous la casse exacte"))
        res.warnings.extend(warns)
    return res


# --- Veille Windows (issue #50) ----------------------------------------------
#
# Une tâche planifiée ``schtasks`` (sans droits admin) réveille le superviseur
# toutes les 5 min via un ``.cmd`` (chemins avec espaces). Réglages d'alimentation
# corrigés (démarrage sur batterie + ``StartWhenAvailable`` : rattrape les réveils
# manqués d'un redémarrage/mise en veille — leçon *Spa & Booking*). La veille n'agit
# que tant qu'un run autorisé est ouvert ; sinon elle se supprime.

HEARTBEAT_STALE_SECONDS = 600   # au-delà, le battement est jugé périmé (superviseur mort)
MAX_ARM_AGE_DAYS = 14           # auto-désarmement si armée depuis plus longtemps

WAKE_RELAUNCHED = "relaunched"  # un superviseur détaché a été relancé
WAKE_DISARMED = "disarmed"      # condition de désarmement atteinte : la veille se retire
WAKE_IDLE = "idle"              # rien à faire (toujours armée)


def _resolve_schtasks(schtasks_cmd=None):
    if schtasks_cmd is not None:
        return schtasks_cmd
    return os.environ.get("NM_SCHTASKS_CMD") or "schtasks"


def _task_name(run_id) -> str:
    """Nom de tâche déterministe (reconstruisible sans l'état) : ``Nickmare-Veille-<rid>``."""
    base = re.sub(r"[^A-Za-z0-9._-]", "_", str(run_id or "run"))
    return f"Nickmare-Veille-{base}"


def watchdog_path(d: Path) -> Path:
    return d / "watchdog.json"


def load_watchdog(d: Path | None) -> dict | None:
    """État de la veille (``watchdog.json``), ou ``None`` si absent/illisible."""
    if d is None:
        return None
    p = watchdog_path(d)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def save_watchdog(d: Path, state: dict) -> None:
    _atomic_write(watchdog_path(d),
                  json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def build_veille_cmd_text(launch_dir: str, python: str, script: str,
                          run_id: str, log_path: str) -> str:
    """Contenu du ``.cmd`` lancé par la tâche. Tous les chemins sont **entre guillemets**
    (ils contiennent souvent des espaces, ex. ``Spa & Booking``). CRLF pour cmd.exe."""
    return (
        "@echo off\r\n"
        "rem Veille Nickmare (issue #50) — relance du superviseur. Fichier généré.\r\n"
        f'cd /d "{launch_dir}"\r\n'
        f'"{python}" "{script}" --wake --run-id "{run_id}" >> "{log_path}" 2>&1\r\n'
    )


def build_task_xml(cmd_path: str, *, now: float | None = None) -> str:
    """XML de tâche planifiée : répétition 5 min + réglages d'alimentation corrigés.

    ``StartWhenAvailable`` rattrape un déclenchement manqué (veille/redémarrage) ;
    ``DisallowStartIfOnBatteries``/``StopIfGoingOnBatteries`` à ``false`` : la veille
    tourne aussi sur batterie (sans ces réglages, *Spa & Booking* est resté immobile
    5 h 30 après un redémarrage nocturne)."""
    now = time.time() if now is None else now
    start = datetime.fromtimestamp(now).strftime("%Y-%m-%dT%H:%M:%S")
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" '
        'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <RegistrationInfo>\n"
        "    <Description>Veille Nickmare (issue #50) — relance du superviseur de run"
        " de jalon.</Description>\n"
        "  </RegistrationInfo>\n"
        "  <Triggers>\n"
        "    <TimeTrigger>\n"
        f"      <StartBoundary>{start}</StartBoundary>\n"
        "      <Enabled>true</Enabled>\n"
        "      <Repetition>\n"
        "        <Interval>PT5M</Interval>\n"
        "        <StopAtDurationEnd>false</StopAtDurationEnd>\n"
        "      </Repetition>\n"
        "    </TimeTrigger>\n"
        "  </Triggers>\n"
        "  <Settings>\n"
        "    <StartWhenAvailable>true</StartWhenAvailable>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\n"
        "    <Enabled>true</Enabled>\n"
        "  </Settings>\n"
        "  <Actions>\n"
        "    <Exec>\n"
        "      <Command>cmd.exe</Command>\n"
        f'      <Arguments>/c "{cmd_path}"</Arguments>\n'
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>\n"
    )


def _schtasks_delete(name: str, schtasks_cmd=None) -> bool:
    """Supprime la tâche planifiée (best-effort). Vrai si schtasks a réussi."""
    res = _run([*_split(_resolve_schtasks(schtasks_cmd)), "/Delete", "/TN", name, "/F"])
    return res.returncode == 0


def arm_watchdog(d: Path, milestone: str, *, run_id=None, max_parallel: int = 2,
                 launch_dir=None, python=None, script=None, schtasks_cmd=None,
                 task_name=None, now: float | None = None):
    """Arme la veille : écrit le ``.cmd`` + le XML, crée la tâche (``/F`` → **idempotent**),
    et persiste ``watchdog.json``. Renvoie (state, ok, résultat schtasks).

    ``schtasks /Create /F`` écrase une tâche de même nom : réarmer ne crée pas de
    doublon. Le nom de tâche est déterministe (reconstruisible sans l'état)."""
    rid = run_id or d.name
    launch_dir = launch_dir or os.getcwd()
    python = python or sys.executable
    script = script or str(Path(__file__).resolve())
    name = task_name or _task_name(rid)
    cmd_path = str(d / "veille.cmd")
    log_path = str(d / "veille.log")
    xml_path = d / "veille-task.xml"

    Path(cmd_path).write_text(
        build_veille_cmd_text(launch_dir, python, script, rid, log_path),
        encoding="utf-8")
    # Task Scheduler attend un fichier XML encodé en UTF-16 pour ``/XML``.
    xml_path.write_text(build_task_xml(cmd_path, now=now), encoding="utf-16")

    res = _run([*_split(_resolve_schtasks(schtasks_cmd)), "/Create", "/XML",
                str(xml_path), "/TN", name, "/F"])
    ok = res.returncode == 0
    state = {
        "armed": bool(ok),
        "run_id": rid,
        "milestone": milestone,
        "max_parallel": int(max_parallel),
        "armed_at": run_journal.now_iso(),
        "task_name": name,
        "cmd_path": cmd_path,
        "log_path": log_path,
        "xml_path": str(xml_path),
        "python": python,
        "script": script,
        "launch_dir": launch_dir,
        "authorized": True,
    }
    save_watchdog(d, state)
    return state, ok, res


def disarm_watchdog(d: Path | None, *, state=None, schtasks_cmd=None,
                    reason: str = "") -> bool:
    """Désarme la veille : supprime la tâche + marque ``watchdog.json`` désarmé.

    Renvoie vrai si la tâche a été supprimée. Jamais d'exception : best-effort."""
    if state is None:
        state = load_watchdog(d) or {}
    rid = state.get("run_id") or (d.name if d is not None else "")
    name = state.get("task_name") or _task_name(rid)
    removed = _schtasks_delete(name, schtasks_cmd) if name else False
    state.setdefault("task_name", name)
    state["armed"] = False
    state["disarmed_at"] = run_journal.now_iso()
    if reason:
        state["disarm_reason"] = reason
    if d is not None:
        try:
            save_watchdog(d, state)
        except OSError:
            pass
    return removed


def should_relaunch(*, work_remaining: bool, heartbeat_alive: bool,
                    quota_available: bool) -> bool:
    """Relance **seulement si** (travail restant ∧ aucun battement ∧ quota revenu)."""
    return bool(work_remaining) and not heartbeat_alive and bool(quota_available)


def disarm_reason(*, run_present: bool, milestone_empty: bool, stopped: bool,
                  human_paused: bool, age_days: float | None,
                  max_age_days: int = MAX_ARM_AGE_DAYS) -> str | None:
    """Motif d'auto-désarmement, ou ``None``. Ordre : run supprimé > arrêt > pause
    humaine > jalon vidé > armement trop ancien. Une pause ``human`` fait **toujours**
    bâiller la veille (elle ne la lève jamais)."""
    if not run_present:
        return "run supprimé (plus de dossier de run)"
    if stopped:
        return "arrêt demandé (signal stop)"
    if human_paused:
        return "pause humaine (la veille ne lève jamais une pause human)"
    if milestone_empty:
        return "jalon vidé (plus d'issue ouverte)"
    if age_days is not None and age_days > max_age_days:
        return f"armement de plus de {max_age_days} jours"
    return None


def _milestone_open_count(milestone: str, gh_cmd=None) -> int | None:
    """Nombre d'issues **ouvertes** du jalon, ou ``None`` si indéterminable (gh KO)."""
    if not milestone:
        return None
    gh = gh_cmd if gh_cmd is not None else os.environ.get("NM_GH_CMD") or "gh"
    res = _run([*_split(gh), "issue", "list", "--milestone", milestone,
                "--state", "open", "--json", "number", "--limit", "500"])
    if res.returncode != 0:
        return None
    try:
        data = json.loads(res.stdout or "[]")
    except (ValueError, TypeError):
        return None
    return len(data) if isinstance(data, list) else None


def work_remaining(milestone: str, gh_cmd=None) -> bool | None:
    """Reste-t-il du travail ? ``True``/``False`` (jalon vidé) / ``None`` (inconnu)."""
    n = _milestone_open_count(milestone, gh_cmd)
    return None if n is None else n > 0


def heartbeat_alive(d: Path, now: float, stale: float = HEARTBEAT_STALE_SECONDS) -> bool:
    """Un superviseur bat-il encore ? Lit ``supervisor.alive`` (horodaté).

    Faux si le fichier est absent, périmé (> ``stale``), ou marqué ``stopped`` (le
    superviseur a terminé proprement → la veille peut relancer si du travail reste)."""
    p = d / "supervisor.alive"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict) or data.get("state") == "stopped":
        return False
    ts = data.get("ts")
    if not ts:
        return False
    try:
        epoch = run_journal.parse_when(str(ts))
    except ValueError:
        return False
    return (now - epoch) <= stale


def quota_available(d: Path, now: float | None = None) -> bool:
    """Le quota est-il revenu ? Faux si une retenue de quota est active (ou control illisible)."""
    now = time.time() if now is None else now
    try:
        control = run_journal.load_control(d)
    except run_journal.ControlCorrupt:
        return False
    return run_journal.quota_hold_active(control, now=now) is None


def _armed_age_days(state: dict, now: float) -> float:
    armed_at = state.get("armed_at")
    if not armed_at:
        return 0.0
    try:
        epoch = run_journal.parse_when(str(armed_at))
    except ValueError:
        return 0.0
    return max(0.0, (now - epoch) / 86400.0)


def _spawn_supervisor_detached(state: dict) -> None:
    """Relance un superviseur **détaché** (survit à la fin de la tâche planifiée).

    Rejoue l'autorisation groupée (``--authorize``), jamais plus large."""
    python = state.get("python") or sys.executable
    script = state.get("script") or str(Path(__file__).resolve())
    argv = [python, script, state.get("milestone") or "", "--authorize",
            "--max-parallel", str(state.get("max_parallel", 2))]
    rid = state.get("run_id")
    if rid:
        argv += ["--run-id", str(rid)]
    launch_dir = state.get("launch_dir") or os.getcwd()
    log_path = state.get("log_path")
    kwargs: dict = {"cwd": launch_dir, "stdin": subprocess.DEVNULL, "close_fds": True}
    if os.name == "nt":
        kwargs["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0)
                                   | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    else:
        kwargs["start_new_session"] = True
    out = None
    try:
        out = open(log_path, "a", encoding="utf-8") if log_path else subprocess.DEVNULL
        subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, **kwargs)  # noqa: S603
    except OSError:
        pass
    finally:
        if hasattr(out, "close"):
            try:
                out.close()
            except OSError:
                pass


def wake(run_id=None, *, now: float | None = None, gh_cmd=None, schtasks_cmd=None,
         spawn_fn=None, heartbeat_stale: float = HEARTBEAT_STALE_SECONDS,
         max_age_days: int = MAX_ARM_AGE_DAYS) -> tuple[str, str]:
    """Un réveil de la veille (appelé toutes les 5 min par la tâche planifiée).

    Désarme si une condition d'auto-désarmement est atteinte ; sinon relance un
    superviseur détaché **seulement si** (travail restant ∧ aucun battement ∧ quota
    revenu). Renvoie (statut, message)."""
    now = time.time() if now is None else now
    rid = run_id or os.environ.get("NM_RUN_ID") or None
    d = run_journal.run_dir(rid)
    state = load_watchdog(d) if d is not None else None

    # Run supprimé ou veille non armée → la veille se supprime (garde-fou).
    if d is None or state is None or not state.get("armed"):
        name = (state or {}).get("task_name") or (_task_name(rid) if rid else None)
        removed = _schtasks_delete(name, schtasks_cmd) if name else False
        suffix = " — tâche supprimée" if removed else ""
        return WAKE_DISARMED, f"run absent ou veille non armée{suffix}"

    milestone = state.get("milestone") or ""
    work = work_remaining(milestone, gh_cmd)

    try:
        control = run_journal.load_control(d)
        corrupt = False
    except run_journal.ControlCorrupt:
        control, corrupt = {}, True
    stopped = (not corrupt) and control.get("signal") == "stop"
    human_paused = (not corrupt) and isinstance(control.get("pause", {}).get("human"), dict)

    reason = disarm_reason(run_present=True, milestone_empty=(work is False),
                           stopped=stopped, human_paused=human_paused,
                           age_days=_armed_age_days(state, now), max_age_days=max_age_days)
    if reason:
        disarm_watchdog(d, state=state, schtasks_cmd=schtasks_cmd, reason=reason)
        return WAKE_DISARMED, f"désarmement : {reason}"

    beat = heartbeat_alive(d, now, heartbeat_stale)
    quota_ok = (not corrupt) and run_journal.quota_hold_active(control, now=now) is None
    if should_relaunch(work_remaining=(work is True), heartbeat_alive=beat,
                       quota_available=quota_ok):
        (spawn_fn or _spawn_supervisor_detached)(state)
        return WAKE_RELAUNCHED, ("relance du superviseur (travail restant, aucun "
                                 "battement, quota revenu)")

    why = []
    if work is not True:
        why.append("pas de travail confirmé")
    if beat:
        why.append("un superviseur bat déjà")
    if not quota_ok:
        why.append("quota non revenu")
    return WAKE_IDLE, "pas de relance — " + (", ".join(why) or "conditions non réunies")


def watchdog_report(d: Path | None, *, now: float | None = None, gh_cmd=None) -> list[str]:
    """État lisible de la veille + conditions de relance courantes (pour ``--state``)."""
    now = time.time() if now is None else now
    if d is None:
        return ["veille : aucun run actif"]
    state = load_watchdog(d)
    lines = [f"veille : run {d.name}"]
    if state is None:
        lines.append("  non armée (aucun watchdog.json)")
        return lines
    lines.append(f"  armée : {'oui' if state.get('armed') else 'non'}")
    lines.append(f"  jalon : {state.get('milestone', '?')}")
    lines.append(f"  armée le : {state.get('armed_at', '?')} "
                 f"(depuis {_armed_age_days(state, now):.1f} j)")
    lines.append(f"  tâche : {state.get('task_name', '?')}")
    if not state.get("armed"):
        if state.get("disarm_reason"):
            lines.append(f"  motif de désarmement : {state['disarm_reason']}")
        return lines
    work = work_remaining(state.get("milestone", ""), gh_cmd)
    beat = heartbeat_alive(d, now)
    quota_ok = quota_available(d, now)
    work_txt = {True: "oui", False: "non (jalon vidé)", None: "inconnu"}[work]
    lines.append(f"  travail restant : {work_txt}")
    lines.append(f"  superviseur en vie (battement) : {'oui' if beat else 'non'}")
    lines.append(f"  quota disponible : {'oui' if quota_ok else 'non'}")
    relance = should_relaunch(work_remaining=(work is True), heartbeat_alive=beat,
                              quota_available=quota_ok)
    lines.append(f"  relancerait maintenant : {'oui' if relance else 'non'}")
    return lines


# --- CLI ---------------------------------------------------------------------


_TERMINAL_OK = {RUN_DONE, RUN_STOPPED, RUN_MAX_LEGS, RUN_MAX_HOURS, RUN_PATIENCE}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run_supervise",
                                description="Superviseur de run de jalon (quota + reprise).")
    # Jalon optionnel : requis pour le superviseur et --arm ; inutile pour
    # --disarm/--state/--wake (le jalon est lu dans watchdog.json).
    p.add_argument("milestone", nargs="?",
                   help="titre exact du jalon (milestone GitHub)")
    p.add_argument("--max-parallel", type=int, default=2)
    p.add_argument("--lots-per-call", type=int, default=1)
    p.add_argument("--max-legs", type=int, default=0)
    p.add_argument("--max-hours", type=float, default=0.0)
    p.add_argument("--patience", type=int, default=DEFAULT_PATIENCE)
    p.add_argument("--max-call", type=float, default=DEFAULT_MAX_CALL_SECONDS)
    p.add_argument("--max-silence", type=float, default=DEFAULT_MAX_SILENCE_SECONDS)
    p.add_argument("--window", type=float, default=DEFAULT_WINDOW_SECONDS)
    p.add_argument("--margin", type=float, default=DEFAULT_MARGIN_SECONDS)
    p.add_argument("--prune-worktrees", action="store_true")
    p.add_argument("--run-id", default=None)
    # --authorize est accepté et ignoré : le superviseur passe toujours --authorize
    # à /run-jalon (il rejoue l'autorisation groupée du lancement, jamais plus).
    p.add_argument("--authorize", action="store_true", help=argparse.SUPPRESS)
    # Actions de veille/préflight (issue #50) — mutuellement exclusives.
    actions = p.add_mutually_exclusive_group()
    actions.add_argument("--preflight", action="store_true",
                         help="vérifie l'environnement (claude/gh/auth/dépôt/approbation) "
                              "et n'exécute rien")
    actions.add_argument("--arm", action="store_true",
                         help="arme la veille Windows (tâche planifiée) pour ce jalon")
    actions.add_argument("--disarm", action="store_true",
                         help="désarme la veille (supprime la tâche planifiée)")
    actions.add_argument("--state", action="store_true",
                         help="affiche l'état de la veille et les conditions de relance")
    actions.add_argument("--wake", action="store_true",
                         help="réveil de la veille (appelé par la tâche planifiée)")
    return p


def _cli_preflight(_ns) -> int:
    pf = preflight()
    for line in pf.report():
        print(line)
    return 0 if pf.ok else 1


def _cli_state(ns) -> int:
    rid = ns.run_id or os.environ.get("NM_RUN_ID") or None
    print("\n".join(watchdog_report(run_journal.run_dir(rid))))
    return 0


def _cli_disarm(ns) -> int:
    rid = ns.run_id or os.environ.get("NM_RUN_ID") or None
    d = run_journal.run_dir(rid)
    if d is None:
        if rid:
            _schtasks_delete(_task_name(rid))
        print("veille désarmée (aucun run actif).")
        return 0
    disarm_watchdog(d, reason="désarmement manuel (--disarm)")
    print(f"veille désarmée — tâche {_task_name(rid or d.name)} supprimée.")
    return 0


def _cli_wake(ns) -> int:
    rid = ns.run_id or os.environ.get("NM_RUN_ID") or None
    status, msg = wake(rid)
    print(f"[veille] {status} — {msg}")
    return 0


def _cli_arm(ns) -> int:
    if not ns.milestone:
        print("run_supervise --arm: titre de jalon requis", file=sys.stderr)
        return 2
    rid = ns.run_id or os.environ.get("NM_RUN_ID") or None
    d = run_journal.run_dir(rid)
    if d is None:
        print("run_supervise --arm: aucun run actif (NM_RUN_ID ?) — arme après le "
              "lancement du run", file=sys.stderr)
        return 1
    if os.environ.get("NM_SKIP_PREFLIGHT") != "1":
        pf = preflight()
        for line in pf.report():
            print(line)
        if not pf.ok:
            print("run_supervise --arm: préflight en échec — veille non armée "
                  "(fail-safe).", file=sys.stderr)
            return 1
    state, ok, res = arm_watchdog(d, ns.milestone, run_id=rid,
                                  max_parallel=max(1, ns.max_parallel))
    if not ok:
        print(f"run_supervise --arm: schtasks a échoué (code {res.returncode}) : "
              f"{res.stderr.strip()}", file=sys.stderr)
        return 1
    print(f"veille armée — tâche {state['task_name']} (réveil toutes les 5 min).")
    return 0


def main(argv: list[str]) -> int:
    ns = _build_parser().parse_args(argv)
    if ns.preflight:
        return _cli_preflight(ns)
    if ns.state:
        return _cli_state(ns)
    if ns.disarm:
        return _cli_disarm(ns)
    if ns.wake:
        return _cli_wake(ns)
    if ns.arm:
        return _cli_arm(ns)

    if not ns.milestone:
        print("run_supervise: titre de jalon requis (ou une action "
              "--preflight/--arm/--disarm/--state/--wake)", file=sys.stderr)
        return 2

    # Préflight avant tout lancement : échec ⇒ pas de lancement (fail-safe).
    if os.environ.get("NM_SKIP_PREFLIGHT") != "1":
        pf = preflight()
        for line in pf.report():
            print(line)
        if not pf.ok:
            print("run_supervise: préflight en échec — lancement refusé (fail-safe).",
                  file=sys.stderr)
            return 1

    options = SuperviseOptions(
        max_parallel=max(1, ns.max_parallel),
        lots_per_call=max(1, ns.lots_per_call),
        max_legs=max(0, ns.max_legs),
        max_hours=max(0.0, ns.max_hours),
        patience=max(0, ns.patience),
        max_call=max(0.0, ns.max_call),
        max_silence=max(0.0, ns.max_silence),
        window=max(1.0, ns.window),
        margin=max(0.0, ns.margin),
        prune_worktrees=ns.prune_worktrees,
    )
    try:
        sup = Supervisor(ns.milestone, options, run_id=ns.run_id)
        result = sup.run()
    except ValueError as exc:
        print(f"run_supervise: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("run_supervise: interruption clavier — arrêt du superviseur", file=sys.stderr)
        return 130
    return 0 if result in _TERMINAL_OK else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
