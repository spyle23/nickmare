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

CLI ::

    python run_supervise.py "<titre du jalon>" [options]

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
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
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


# --- CLI ---------------------------------------------------------------------


_TERMINAL_OK = {RUN_DONE, RUN_STOPPED, RUN_MAX_LEGS, RUN_MAX_HOURS, RUN_PATIENCE}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run_supervise",
                                description="Superviseur de run de jalon (quota + reprise).")
    p.add_argument("milestone", help="titre exact du jalon (milestone GitHub)")
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
    return p


def main(argv: list[str]) -> int:
    ns = _build_parser().parse_args(argv)
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
