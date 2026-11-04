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

Fail-safe : en cas d'erreur, un message part sur stderr et le code de retour est
non nul, sans jamais lever d'exception vers l'appelant via la CLI.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PHASES = ("queued", "dev", "tests", "fix", "qa", "merge", "done", "blocked")

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


_COMMANDS = {"init": _cmd_init, "dir": _cmd_dir, "root": _cmd_root, "log": _cmd_log}


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
