#!/usr/bin/env python3
"""Dashboard terminal live du suivi de run (issue #40) — version Python.

Lit le journal NDJSON d'un run et affiche, en se rafraîchissant, quel ticket est
à quelle phase, depuis combien de temps, avec quel agent et quelle PR.
**Lecture seule** : n'écrit jamais dans le journal.

Tourne nativement dans PowerShell (pas besoin de Git Bash) ::

    python scripts/run_dashboard.py [<run_id|chemin journal>] [--once] [--interval N]

* (sans argument)  -> run le plus récent sous ``.nickmare/runs/`` ;
* ``<run_id>``      -> ``.nickmare/runs/<run_id>/journal.ndjson`` ;
* ``<chemin>``      -> ce fichier journal précis ;
* ``--once``        -> un seul rendu puis sortie (testable, sans TTY) ;
* ``--interval N``  -> période de rafraîchissement en secondes (défaut 1).

Couleurs activées si la sortie est un terminal (ou ``NM_FORCE_COLOR=1``).
Fail-safe : ligne JSON malformée ignorée ; run inexistant -> message + sortie 0.
La **phase courante** d'un ticket est son dernier événement ; sa **durée** est
``maintenant − ts`` de cet événement.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_journal  # noqa: E402  (même dossier)

# Sortie UTF-8 garantie, même si la console Windows est en cp1252 (accents,
# em-dash « — » du titre de jalon). Fail-safe si le flux ne sait pas se reconfigurer.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

PHASE_COLOR = {
    "queued": 90,   # gris
    "dev": 34,      # bleu
    "tests": 36,    # cyan
    "fix": 33,      # jaune
    "qa": 35,       # magenta
    "merge": 32,    # vert
    "done": 92,     # vert vif
    "blocked": 31,  # rouge
}
ACTIVE_PHASES = {"dev", "tests", "fix", "qa", "merge"}
SPIN = "|/-\\"
RULE = "-" * 78


# --- Lecture / réduction du journal ------------------------------------------


def read_events(journal: Path) -> list[dict]:
    """Événements valides du journal ; toute ligne non-JSON est ignorée."""
    events: list[dict] = []
    try:
        text = journal.read_text(encoding="utf-8")
    except OSError:
        return events
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue  # ligne corrompue -> ignorée (fail-safe)
        if isinstance(obj, dict) and "ticket" in obj and "phase" in obj:
            events.append(obj)
    return events


def reduce(events: list[dict]) -> list[dict]:
    """Dernier état par ticket, dans l'ordre de première apparition."""
    order: list[str] = []
    last: dict[str, dict] = {}
    for ev in events:
        t = str(ev.get("ticket"))
        if t not in last:
            order.append(t)
        last[t] = ev
    return [last[t] for t in order]


def load_titles(run_dir: Path) -> dict[str, str]:
    titles: dict[str, str] = {}
    tsv = run_dir / "titles.tsv"
    try:
        for line in tsv.read_text(encoding="utf-8").splitlines():
            num, _, title = line.partition("\t")
            if num and title:
                titles[num.strip()] = title.strip()
    except OSError:
        pass
    return titles


def meta_value(run_dir: Path, key: str) -> str:
    try:
        meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
        return str(meta.get(key, "") or "")
    except (OSError, ValueError):
        return ""


# --- Formatage ---------------------------------------------------------------


def fmt_elapsed(seconds: int | None) -> str:
    if seconds is None or seconds < 0:
        return "?"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def _elapsed_from_ts(ts: str, now: datetime) -> int | None:
    try:
        then = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return int((now - then).total_seconds())


def progress_bar(done: int, total: int, width: int = 24) -> str:
    if total <= 0:
        filled, pct = 0, 0
    else:
        filled, pct = done * width // total, done * 100 // total
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {done}/{total} ({pct}%)"


class _Painter:
    """Enrobe le texte de codes ANSI si la couleur est active."""

    def __init__(self, color: bool):
        self.color = color

    def __call__(self, code: int, text: str) -> str:
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"


def render(journal: Path, run_dir: Path, *, now: datetime | None = None,
           color: bool = False, frame: int = 0, show_hint: bool = False,
           interval: int = 1) -> str:
    now = now or datetime.now(timezone.utc)
    paint = _Painter(color)
    spin = SPIN[frame % len(SPIN)]
    milestone = meta_value(run_dir, "milestone") or "(jalon inconnu)"
    started = meta_value(run_dir, "started_at")
    titles = load_titles(run_dir)
    rows = reduce(read_events(journal))

    out: list[str] = []
    out.append(paint(1, "Nickmare · suivi de run"))
    out.append(paint(90, "Jalon : ") + milestone)
    header = paint(90, "Run   : ") + run_dir.name
    if started:
        header += paint(90, "   démarré ") + started
    out.append(header)
    out.append(RULE)

    done = blocked = 0
    if not rows:
        out.append(paint(90, f"Aucun événement pour l'instant… {spin}"))
    else:
        for ev in rows:
            phase = str(ev.get("phase", ""))
            if phase == "done":
                done += 1
            if phase == "blocked":
                blocked += 1
            ticket = str(ev.get("ticket", ""))
            elapsed = fmt_elapsed(_elapsed_from_ts(str(ev.get("ts", "")), now))
            agent = str(ev.get("agent") or "-")
            pr = ev.get("pr")
            pr_cell = f"PR#{pr}" if pr not in (None, "null") else "-"
            title = titles.get(ticket) or str(ev.get("detail") or "")
            badge = paint(PHASE_COLOR.get(phase, 37), f"{phase.upper():<7}")
            marker = f"{spin} " if phase in ACTIVE_PHASES else "  "
            out.append(
                f"  {paint(1, f'#{ticket:<4}')} {badge}{marker}"
                f"{elapsed:<7} {agent:<12} {pr_cell:<7} {title}".rstrip()
            )

    total = len(rows)
    out.append(RULE)
    line = "Progression: " + paint(92, progress_bar(done, total))
    if blocked:
        line += "   " + paint(31, f"{blocked} bloqué(s)")
    out.append(line)
    if show_hint:
        out.append(paint(90, f"(q pour quitter — rafraîchi toutes les {interval}s)"))
    return "\n".join(out) + "\n"


# --- Résolution de la cible --------------------------------------------------


def resolve(target: str | None) -> tuple[Path, Path] | None:
    """Renvoie (journal, run_dir) ou ``None`` si rien ne correspond."""
    if target:
        p = Path(target)
        if p.is_file():
            return p, p.parent
        d = run_journal.run_dir(target)
    else:
        d = run_journal.run_dir()
    if d is None:
        return None
    return d / "journal.ndjson", d


# --- Mode live ---------------------------------------------------------------


def _enable_vt() -> None:
    """Active le traitement ANSI de la console Windows (no-op ailleurs)."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _wait_key(interval: float) -> str | None:
    """Attend ``interval`` s ; renvoie la touche pressée si l'utilisateur tape."""
    if os.name == "nt":
        import msvcrt
        import time

        deadline = time.monotonic() + interval
        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                try:
                    return msvcrt.getwch()
                except Exception:
                    return None
            time.sleep(0.05)
        return None
    try:
        import select

        ready, _, _ = select.select([sys.stdin], [], [], interval)
        return sys.stdin.read(1) if ready else None
    except Exception:
        import time

        time.sleep(interval)
        return None


class _cbreak:
    """Lecture caractère par caractère sur POSIX (no-op sur Windows / sans TTY)."""

    def __enter__(self):
        self._fd = None
        if os.name == "nt":
            return self
        try:
            import termios
            import tty

            self._termios = termios
            self._fd = sys.stdin.fileno()
            self._saved = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)
        except Exception:
            self._fd = None
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            try:
                self._termios.tcsetattr(self._fd, self._termios.TCSADRAIN, self._saved)
            except Exception:
                pass


def live(journal: Path, run_dir: Path, interval: int, color: bool) -> int:
    _enable_vt()
    sys.stdout.write("\033[?25l")  # masque le curseur
    frame = 0
    try:
        with _cbreak():
            while True:
                sys.stdout.write("\033[2J\033[H")  # efface, curseur en haut
                sys.stdout.write(render(
                    journal, run_dir, color=color, frame=frame,
                    show_hint=True, interval=interval,
                ))
                sys.stdout.flush()
                frame += 1
                key = _wait_key(interval)
                if key and key.lower() == "q":
                    break
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\033[0m\033[?25h\n")
        sys.stdout.flush()
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=True, description="Dashboard de suivi de run.")
    parser.add_argument("target", nargs="?", default=None,
                        help="run_id ou chemin de journal (défaut : le plus récent)")
    parser.add_argument("--once", action="store_true", help="un seul rendu puis sortie")
    parser.add_argument("--interval", type=int, default=1, help="rafraîchissement (s)")
    ns = parser.parse_args(argv)
    interval = ns.interval if ns.interval and ns.interval > 0 else 1

    resolved = resolve(ns.target)
    if resolved is None:
        print(f"Aucun run trouvé sous {run_journal.runs_root()}. "
              "Lance d'abord scripts/run-jalon.sh.", file=sys.stderr)
        return 0
    journal, run_dir = resolved
    if not journal.is_file():
        print(f"Journal introuvable : {journal}", file=sys.stderr)
        return 0

    color = sys.stdout.isatty() or os.environ.get("NM_FORCE_COLOR") == "1"
    if ns.once:
        sys.stdout.write(render(journal, run_dir, color=color))
        return 0
    return live(journal, run_dir, interval, color)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
