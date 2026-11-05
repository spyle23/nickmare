#!/usr/bin/env python3
"""Journal de run (issue #40) — implémentation Python + petite CLI.

Un « run » d'orchestration (/run-jalon) vit sous ``.nickmare/runs/<run_id>/`` :

* ``meta.json``      : ``{"run_id","milestone","started_at","max_parallel"}``
* ``journal.ndjson`` : une ligne JSON par événement de phase (**append-only**)

Le journal est append-only (jamais réécrit), dans l'esprit du journal d'audit
produit (``docs/ARCHITECTURE.md`` §11). Le dashboard le lit en lecture seule.
Aucun secret n'y est écrit.

Schéma d'un événement ::

    {"ts":"<ISO8601 UTC>","run_id":"…","ticket":N,
     "phase":"queued|dev|tests|fix|qa|merge|done|blocked",
     "agent":"orchestrateur|dev-ticket|qa-ticket","pr":<n|null>,"detail":"…"}

Variables d'environnement :

* ``NM_RUNS_ROOT`` racine des runs (défaut : ``<racine git>/.nickmare/runs``) ;
* ``NM_RUN_ID``    run actif ciblé par ``log`` / id forcé par ``init``
  (défaut : le plus récent).

CLI (le shim bash ``scripts/lib/run-journal.sh`` délègue ici, pour que le
lanceur et les agents continuent d'appeler ``nm_run_init`` / ``nm_run_dir`` /
``nm_log_phase`` sans changement) ::

    python run_journal.py init "<jalon>" [max_parallel]   # -> imprime run_id
    python run_journal.py dir  [<run_id>]                 # -> imprime chemin
    python run_journal.py root                            # -> racine des runs
    python run_journal.py log  <ticket> <phase> [--pr N] [--agent X] [--detail "…"]

Contrôle du run (issue #48) — pause, arrêt et point de contrôle avant chaque lot ::

    python run_journal.py pause   [--reason "…"] [--by X]   # pause d'origine humaine
    python run_journal.py unpause [--all] [--by X]          # lève la pause humaine
    python run_journal.py stop    [--reason "…"] [--by X]   # arrêt du run
    python run_journal.py status  [<run_id>]                # état de contrôle lisible
    python run_journal.py gate    [<run_id>]                # code de sortie (cf. ci-dessous)
    python run_journal.py quota hold  --until <iso|epoch|+90m> [--reason "…"] [--by X]
    python run_journal.py quota clear [--by X]              # lève la retenue de quota

``gate`` consulte ``<run>/control.json`` et rend un **code de sortie** que
l'orchestrateur applique avant chaque lot (priorité : **arrêt > quota > pause**) :
``0`` continuer · ``1`` pause (finir le lot, ne plus en lancer) · ``2`` arrêt
(ne rien lancer) · ``3`` plus rien à faire · ``4`` quota épuisé (imprime la reprise).
``unpause`` ne lève que la pause ``human`` ; une pause ``quota`` reste jusqu'à
``quota clear`` (ou ``unpause --all``).

Fail-safe : en cas d'erreur, un message part sur stderr et le code de retour est
non nul, sans jamais lever d'exception vers l'appelant via la CLI. ``control.json``
illisible ⇒ ``gate`` rend « pause », jamais « continuer ».
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Sortie UTF-8 garantie, même si la console Windows est en cp1252 : les messages
# de `gate`/`status` portent des accents (« quota épuisé », « pause demandée »).
# Sans cela, une capture en UTF-8 (tests, pipes) échoue à les décoder. Fail-safe
# si le flux ne sait pas se reconfigurer (déjà redirigé, flux spécial).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

PHASES = ("queued", "dev", "tests", "fix", "qa", "merge", "done", "blocked",
          "paused", "interrupted")

# Codes de sortie de ``gate`` (cf. issue #48). Priorité : arrêt > quota > pause.
GATE_CONTINUE = 0   # continuer : lancer le lot
GATE_PAUSE = 1      # pause : finir le lot en cours, ne plus en lancer
GATE_STOP = 2       # arrêt : ne lancer aucun agent
GATE_IDLE = 3       # plus rien à faire (aucun run actif)
GATE_QUOTA = 4      # quota épuisé : ne rien lancer, reprise différée

# Événements de contrôle : journalisés sur le « ticket » 0, réservé au niveau run
# (même convention que l'orchestrateur, cf. .claude/commands/run-jalon.md).
_RUN_TICKET = 0

# Sérialisation compacte, sans espace après ':'/','  — JSON lisible ligne à ligne
# et stable pour grep/diff. ensure_ascii=False conserve les accents (« Sûreté »).
_DUMP = dict(ensure_ascii=False, separators=(",", ":"))


def now_iso() -> str:
    """Horodatage ISO 8601 UTC à la seconde (ex. ``2026-10-27T05:03:21Z``)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(*args: str) -> str:
    out = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _git_top() -> Path:
    """Racine du dépôt **principal**, y compris depuis un worktree secondaire.

    Les agents dev/QA tournent dans des worktrees (``git worktree``) : leur
    ``--show-toplevel`` est le worktree lui-même, où ``.nickmare/runs/`` (gitignoré)
    n'existe pas — ils écriraient dans le vide pendant que le dashboard lit le
    journal du dépôt principal (#47). Le dossier git *commun* à tous les worktrees
    (``--git-common-dir``) désigne, lui, le ``.git`` du dépôt principal.
    """
    try:
        common = Path(_git("rev-parse", "--git-common-dir"))
        if not common.is_absolute():
            common = Path.cwd() / common
        common = common.resolve()
        if common.name == ".git":
            return common.parent
    except Exception:
        pass
    try:  # dépôt atypique (sous-module, .git déporté) : racine du worktree courant
        top = _git("rev-parse", "--show-toplevel")
        if top:
            return Path(top)
    except Exception:
        pass
    return Path.cwd()


def runs_root() -> Path:
    """Racine des runs : ``$NM_RUNS_ROOT`` sinon ``<dépôt principal>/.nickmare/runs``."""
    env = os.environ.get("NM_RUNS_ROOT")
    return Path(env) if env else _git_top() / ".nickmare" / "runs"


def _gen_run_id() -> str:
    """Id triable par ordre lexical (= chronologique) : ``<stamp>-<rand hex>``."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{random.randint(0, 0xFFFF):04x}"


def run_init(milestone: str, max_parallel="2") -> str:
    """Crée le dossier de run + ``meta.json`` + journal vide. Renvoie le run_id."""
    if not milestone:
        raise ValueError("milestone requis")
    try:
        maxp = int(str(max_parallel))
    except (TypeError, ValueError):
        maxp = 2
    rid = os.environ.get("NM_RUN_ID") or _gen_run_id()
    d = runs_root() / rid
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "run_id": rid,
        "milestone": milestone,
        "started_at": now_iso(),
        "max_parallel": maxp,
    }
    (d / "meta.json").write_text(json.dumps(meta, **_DUMP) + "\n", encoding="utf-8")
    (d / "journal.ndjson").touch()  # crée sans écraser (append-only)
    return rid


def run_dir(run_id: str | None = None) -> Path | None:
    """Chemin du run ciblé (ou le plus récent). ``None`` si aucun."""
    rid = run_id or os.environ.get("NM_RUN_ID") or ""
    root = runs_root()
    if rid:
        d = root / rid
        return d if d.is_dir() else None
    if not root.is_dir():
        return None
    dirs = sorted(p for p in root.iterdir() if p.is_dir())
    return dirs[-1] if dirs else None


def log_phase(ticket, phase, pr=None, agent="", detail="") -> None:
    """Ajoute une ligne NDJSON au journal du run actif (un seul write en append)."""
    ticket = str(ticket)
    if not ticket.isdigit():
        raise ValueError("ticket numérique attendu")
    if phase not in PHASES:
        raise ValueError(f"phase inconnue « {phase} »")
    pr_val = int(pr) if pr is not None and str(pr).isdigit() else None
    d = run_dir()
    if d is None:
        raise RuntimeError("aucun run actif (NM_RUN_ID ?)")
    event = {
        "ts": now_iso(),
        "run_id": d.name,
        "ticket": int(ticket),
        "phase": phase,
        "agent": agent or "",
        "pr": pr_val,
        "detail": detail or "",
    }
    with (d / "journal.ndjson").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, **_DUMP) + "\n")


def _log_run_event(d: Path, phase: str, agent: str, detail: str) -> None:
    """Journalise un événement de niveau run (ticket 0), best-effort.

    Les changements de contrôle (pause/arrêt/quota/reprise) sont tracés dans le
    journal append-only, pour l'audit du workflow. Une erreur de journalisation
    ne doit jamais faire échouer le changement de contrôle lui-même.
    """
    event = {
        "ts": now_iso(),
        "run_id": d.name,
        "ticket": _RUN_TICKET,
        "phase": phase,
        "agent": agent or "",
        "pr": None,
        "detail": detail or "",
    }
    try:
        with (d / "journal.ndjson").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, **_DUMP) + "\n")
    except OSError as exc:  # best-effort : le contrôle prime sur sa trace
        print(f"run_journal: journalisation impossible ({exc})", file=sys.stderr)


# --- Contrôle du run : control.json, pause/arrêt/quota, gate (issue #48) ------
#
# Un run porte un état de contrôle dans ``<run>/control.json`` :
#
#     {"signal":"run|pause|stop","author":"…",
#      "pause":{"human":{…},"quota":{"until":…,"until_iso":"…",…}},
#      "updated":"<ISO>"}
#
# * ``signal``  : vue synthétique — ``stop`` prime, sinon ``pause`` si une origine
#   de pause est présente, sinon ``run``.
# * ``pause``   : origines de pause actives. ``human`` (posée à la main, jamais
#   levée par une reprise automatique) et ``quota`` (limite d'usage, avec échéance
#   ``until``, levée par ``quota clear`` ou l'expiration de l'échéance).
#
# Modèle repris de *Spa & Booking* (gate à codes de sortie) et d'*hotelerie*
# (origine typée des pauses). Écriture atomique (fichier temporaire + rename) pour
# qu'un lecteur concurrent (dashboard, superviseur) ne voie jamais un demi-fichier.


class ControlCorrupt(Exception):
    """``control.json`` présent mais illisible — fail-safe : gate rend « pause »."""


def control_path(d: Path) -> Path:
    return d / "control.json"


def _default_control() -> dict:
    return {"signal": "run", "author": "", "pause": {}}


def load_control(d: Path) -> dict:
    """État de contrôle du run.

    Fichier **absent** → état par défaut (``run``) : un run neuf continue.
    Fichier **présent mais illisible** → ``ControlCorrupt`` : l'appelant (gate)
    applique le fail-safe « pause », jamais « continuer ».
    """
    path = control_path(d)
    if not path.exists():
        return _default_control()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ControlCorrupt(str(exc)) from exc
    if not isinstance(data, dict):
        raise ControlCorrupt("control.json n'est pas un objet JSON")
    data.setdefault("signal", "run")
    data.setdefault("author", "")
    pause = data.get("pause")
    data["pause"] = pause if isinstance(pause, dict) else {}
    return data


def _recompute_signal(control: dict) -> None:
    """Ajuste ``signal`` d'après les origines de pause. ``stop`` est collant :
    seule une commande ``stop`` le pose, et aucune reprise ne le retire (on reprend
    un run arrêté en relançant l'orchestrateur)."""
    if control.get("signal") == "stop":
        return
    control["signal"] = "pause" if control.get("pause") else "run"


def save_control(d: Path, control: dict) -> None:
    """Écrit ``control.json`` de façon **atomique** (temp + ``os.replace``).

    ``os.replace`` est atomique sur le même système de fichiers (POSIX et Windows) :
    un lecteur voit soit l'ancien fichier, soit le nouveau, jamais un fichier
    tronqué en cours d'écriture.
    """
    control["updated"] = now_iso()
    path = control_path(d)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(control, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    os.replace(tmp, path)


def parse_when(text: str) -> float:
    """Une échéance de quota → epoch (float). Accepte epoch, ISO 8601, ou ``+90m``.

    Formes relatives : ``+30s`` / ``+90m`` / ``+2h`` (depuis maintenant).
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("échéance requise (epoch, ISO 8601, ou +90m)")
    m = re.fullmatch(r"\+(\d+)([smh])", text)
    if m:
        factor = {"s": 1, "m": 60, "h": 3600}[m.group(2)]
        return time.time() + int(m.group(1)) * factor
    try:
        return float(text)
    except ValueError:
        pass
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"échéance illisible : {text}") from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(float(epoch), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def human_delta(seconds: float) -> str:
    """Un délai lisible : ``1h 30m``, ``12m``, ``45s`` (jamais négatif)."""
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def quota_hold_active(control: dict, *, now: float | None = None) -> dict | None:
    """La retenue de quota **en cours**, ou ``None``.

    Une échéance dépassée n'est plus bloquante (la fenêtre a rouvert) mais n'est
    pas effacée ici : seul ``quota clear`` (ou ``unpause --all``) retire l'origine.
    """
    now = time.time() if now is None else now
    q = control.get("pause", {}).get("quota")
    if not isinstance(q, dict):
        return None
    until = q.get("until")
    if until is None or now >= float(until):
        return None
    return q


# --- Opérations de contrôle --------------------------------------------------


def _require_run(run_id: str | None = None) -> Path:
    d = run_dir(run_id)
    if d is None:
        raise RuntimeError("aucun run actif (NM_RUN_ID ?)")
    return d


def _control_for_write(d: Path) -> dict:
    """Charge le contrôle pour une écriture, en repartant du défaut s'il est
    illisible : un opérateur ne doit jamais rester bloqué par un fichier corrompu
    (il réécrit un état autoritatif). ``gate``/``status`` restent stricts."""
    try:
        return load_control(d)
    except ControlCorrupt:
        return _default_control()


def control_pause(by: str = "human", reason: str = "", run_id=None) -> dict:
    """Pose une pause d'origine **humaine** (jamais levée par une reprise auto)."""
    d = _require_run(run_id)
    control = _control_for_write(d)
    control["pause"]["human"] = {"since": now_iso(), "by": by or "human",
                                 "reason": reason or ""}
    control["author"] = by or "human"
    _recompute_signal(control)
    save_control(d, control)
    detail = f"pause posée par {by or 'human'}"
    if reason:
        detail += f" — {reason}"
    _log_run_event(d, "paused", by or "human", detail)
    return control


def control_unpause(all_origins: bool = False, by: str = "human", run_id=None) -> dict:
    """Lève la pause **humaine**. Avec ``--all``, lève aussi la pause ``quota``.

    Sans ``--all``, une pause ``quota`` reste active (seul ``quota clear`` la lève)."""
    d = _require_run(run_id)
    control = _control_for_write(d)
    control["pause"].pop("human", None)
    if all_origins:
        control["pause"].pop("quota", None)
    control["author"] = by or "human"
    _recompute_signal(control)
    save_control(d, control)
    if control.get("pause"):
        phase, detail = "paused", "pause humaine levée — quota toujours actif"
    else:
        phase, detail = "queued", "reprise — pauses levées"
    if all_origins:
        detail = "reprise — toutes pauses levées (--all)"
        phase = "queued" if not control.get("pause") else "paused"
    _log_run_event(d, phase, by or "human", detail)
    return control


def control_stop(by: str = "human", reason: str = "", run_id=None) -> dict:
    """Demande l'**arrêt** du run : gate rendra « arrêt » (ne rien lancer)."""
    d = _require_run(run_id)
    control = _control_for_write(d)
    control["signal"] = "stop"
    control["author"] = by or "human"
    if reason:
        control["stop_reason"] = reason
    save_control(d, control)
    detail = f"arrêt demandé par {by or 'human'}"
    if reason:
        detail += f" — {reason}"
    _log_run_event(d, "interrupted", by or "human", detail)
    return control


def control_quota_hold(until: str, by: str = "superviseur", reason: str = "",
                       run_id=None) -> dict:
    """Pose une retenue de **quota** (limite d'usage) avec échéance de reprise."""
    d = _require_run(run_id)
    epoch = parse_when(until)
    control = _control_for_write(d)
    control["pause"]["quota"] = {"since": now_iso(), "until": epoch,
                                 "until_iso": iso_utc(epoch), "reason": reason or ""}
    control["author"] = by or "superviseur"
    _recompute_signal(control)
    save_control(d, control)
    _log_run_event(d, "paused", by or "superviseur",
                   f"quota épuisé — reprise prévue à {iso_utc(epoch)}")
    return control


def control_quota_clear(by: str = "superviseur", run_id=None) -> dict:
    """Lève la retenue de **quota**. Ne touche **jamais** une pause ``human``."""
    d = _require_run(run_id)
    control = _control_for_write(d)
    control["pause"].pop("quota", None)
    control["author"] = by or "superviseur"
    _recompute_signal(control)
    save_control(d, control)
    if control.get("pause"):
        phase, detail = "paused", "quota levé — pause humaine toujours active"
    else:
        phase, detail = "queued", "reprise — quota levé"
    _log_run_event(d, phase, by or "superviseur", detail)
    return control


def gate(run_id=None, *, now: float | None = None) -> tuple[int, str]:
    """Décision d'avant-lot : (code de sortie, message). Priorité : arrêt > quota > pause.

    Fail-safe : run absent → ``GATE_IDLE`` ; ``control.json`` illisible → ``GATE_PAUSE``
    (jamais « continuer »)."""
    d = run_dir(run_id)
    if d is None:
        return GATE_IDLE, "aucun run actif — plus rien à faire"
    try:
        control = load_control(d)
    except ControlCorrupt as exc:
        return GATE_PAUSE, (f"control.json illisible ({exc}) — pause par sûreté "
                            "(fail-safe) ; corriger le fichier avant de reprendre")
    if control.get("signal") == "stop":
        who = control.get("author") or "?"
        reason = control.get("stop_reason")
        msg = f"arrêt demandé par {who} — ne lancer aucun agent, clore le run"
        if reason:
            msg += f" ({reason})"
        return GATE_STOP, msg
    hold = quota_hold_active(control, now=now)
    if hold:
        until = float(hold["until"])
        left = until - (time.time() if now is None else now)
        return GATE_QUOTA, (f"quota épuisé — ne lancer aucun agent ; reprise prévue "
                            f"à {hold.get('until_iso') or iso_utc(until)} "
                            f"(dans {human_delta(left)})")
    human = control.get("pause", {}).get("human")
    if isinstance(human, dict):
        who = human.get("by") or control.get("author") or "?"
        reason = human.get("reason")
        msg = (f"pause demandée par {who} — terminer le lot en cours, ne plus en "
               "lancer")
        if reason:
            msg += f" ({reason})"
        return GATE_PAUSE, msg
    return GATE_CONTINUE, "continuer — aucun frein actif"


def control_status(run_id=None, *, now: float | None = None) -> tuple[dict, list[str]]:
    """État de contrôle lisible : (control, lignes). ``control`` vide si pas de run."""
    d = run_dir(run_id)
    if d is None:
        return {}, ["aucun run actif"]
    try:
        control = load_control(d)
        corrupt = False
    except ControlCorrupt as exc:
        control, corrupt = {}, True
        err = str(exc)
    lines = [f"run : {d.name}"]
    if corrupt:
        lines.append(f"control.json ILLISIBLE ({err}) — gate rendra « pause »")
        return {}, lines
    signal = control.get("signal", "run")
    lines.append(f"signal : {signal}" + (f" (par {control['author']})"
                 if control.get("author") else ""))
    if signal == "stop" and control.get("stop_reason"):
        lines.append(f"  motif d'arrêt : {control['stop_reason']}")
    pause = control.get("pause", {})
    human = pause.get("human")
    if isinstance(human, dict):
        line = f"  pause human : depuis {human.get('since', '?')}"
        if human.get("by"):
            line += f", par {human['by']}"
        if human.get("reason"):
            line += f" — {human['reason']}"
        lines.append(line)
    quota = pause.get("quota")
    if isinstance(quota, dict):
        active = quota_hold_active(control, now=now) is not None
        etat = "active" if active else "expirée (fenêtre rouverte, non purgée)"
        lines.append(f"  pause quota : {etat} — reprise à "
                     f"{quota.get('until_iso', '?')}")
    code, msg = gate(run_id, now=now)
    lines.append(f"gate : code {code} — {msg}")
    return control, lines


# --- CLI ---------------------------------------------------------------------


def _cmd_init(argv: list[str]) -> int:
    milestone = argv[0] if argv else ""
    maxp = argv[1] if len(argv) > 1 else "2"
    if not milestone:
        print("run_journal init: milestone requis", file=sys.stderr)
        return 2
    try:
        print(run_init(milestone, maxp))
    except Exception as exc:  # fail-safe : pas de traceback vers l'appelant
        print(f"run_journal init: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_dir(argv: list[str]) -> int:
    d = run_dir(argv[0] if argv else None)
    if d is None:
        return 1
    print(str(d))
    return 0


def _cmd_root(_argv: list[str]) -> int:
    print(str(runs_root()))
    return 0


def _cmd_log(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="run_journal log", add_help=False)
    parser.add_argument("ticket")
    parser.add_argument("phase")
    parser.add_argument("--pr", default=None)
    parser.add_argument("--agent", default="")
    parser.add_argument("--detail", default="")
    try:  # parse_known_args : tolère un drapeau inconnu, comme l'ancien shell
        ns, _ignored = parser.parse_known_args(argv)
    except SystemExit:
        return 2
    try:
        log_phase(ns.ticket, ns.phase, ns.pr, ns.agent, ns.detail)
    except (ValueError, RuntimeError) as exc:
        print(f"run_journal log: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_pause(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="run_journal pause", add_help=False)
    parser.add_argument("--reason", default="")
    parser.add_argument("--by", default="human")
    try:
        ns, _ = parser.parse_known_args(argv)
    except SystemExit:
        return 2
    try:
        control_pause(ns.by, ns.reason)
    except (RuntimeError, OSError) as exc:
        print(f"run_journal pause: {exc}", file=sys.stderr)
        return 1
    print("run en pause (origine humaine).")
    return 0


def _cmd_unpause(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="run_journal unpause", add_help=False)
    parser.add_argument("--all", dest="all_origins", action="store_true")
    parser.add_argument("--by", default="human")
    try:
        ns, _ = parser.parse_known_args(argv)
    except SystemExit:
        return 2
    try:
        control = control_unpause(ns.all_origins, ns.by)
    except (RuntimeError, OSError) as exc:
        print(f"run_journal unpause: {exc}", file=sys.stderr)
        return 1
    if control.get("pause", {}).get("quota"):
        print("pause humaine levée — pause quota toujours active "
              "(`quota clear` ou `unpause --all`).")
    else:
        print("reprise du run.")
    return 0


def _cmd_stop(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="run_journal stop", add_help=False)
    parser.add_argument("--reason", default="")
    parser.add_argument("--by", default="human")
    try:
        ns, _ = parser.parse_known_args(argv)
    except SystemExit:
        return 2
    try:
        control_stop(ns.by, ns.reason)
    except (RuntimeError, OSError) as exc:
        print(f"run_journal stop: {exc}", file=sys.stderr)
        return 1
    print("arrêt demandé — le run ne lancera plus d'agent.")
    return 0


def _cmd_status(argv: list[str]) -> int:
    rid = argv[0] if argv and not argv[0].startswith("-") else None
    _control, lines = control_status(rid)
    print("\n".join(lines))
    return 0


def _cmd_gate(argv: list[str]) -> int:
    rid = argv[0] if argv and not argv[0].startswith("-") else None
    code, msg = gate(rid)
    print(msg)
    return code


def _cmd_quota(argv: list[str]) -> int:
    if not argv:
        print("run_journal quota: sous-commande requise (hold|clear)", file=sys.stderr)
        return 2
    action, rest = argv[0], argv[1:]
    parser = argparse.ArgumentParser(prog="run_journal quota", add_help=False)
    parser.add_argument("--until", default="")
    parser.add_argument("--reason", default="")
    parser.add_argument("--by", default="superviseur")
    try:
        ns, _ = parser.parse_known_args(rest)
    except SystemExit:
        return 2
    try:
        if action == "hold":
            if not ns.until:
                print("run_journal quota hold: --until requis "
                      "(iso|epoch|+90m)", file=sys.stderr)
                return 2
            control = control_quota_hold(ns.until, ns.by, ns.reason)
            q = control["pause"]["quota"]
            print(f"quota en attente jusqu'à {q['until_iso']}.")
        elif action == "clear":
            control_quota_clear(ns.by)
            print("quota levé.")
        else:
            print(f"run_journal quota: action inconnue « {action} »",
                  file=sys.stderr)
            return 2
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"run_journal quota: {exc}", file=sys.stderr)
        return 1
    return 0


_COMMANDS = {
    "init": _cmd_init, "dir": _cmd_dir, "root": _cmd_root, "log": _cmd_log,
    "pause": _cmd_pause, "unpause": _cmd_unpause, "stop": _cmd_stop,
    "status": _cmd_status, "gate": _cmd_gate, "quota": _cmd_quota,
}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    handler = _COMMANDS.get(cmd)
    if handler is None:
        print(f"run_journal: commande inconnue « {cmd} »", file=sys.stderr)
        return 2
    return handler(rest)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
