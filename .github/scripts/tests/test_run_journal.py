#!/usr/bin/env python3
"""Tests de scripts/run_journal.py (issue #40). Aucun appel réseau.

Teste la CLI via subprocess (chemin réellement emprunté par le shim bash) sur une
racine de runs temporaire. Lancement : ``python .github/scripts/tests/test_run_journal.py``.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
JOURNAL_PY = ROOT / "scripts" / "run_journal.py"


def run(*args, env=None):
    base = dict(os.environ)
    base.pop("NM_RUN_ID", None)
    if env:
        base.update(env)
    return subprocess.run(
        [sys.executable, str(JOURNAL_PY), *args],
        capture_output=True, text=True, encoding="utf-8", env=base,
    )


class JournalTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.runs = Path(self._tmp.name) / "runs"
        self.env = {"NM_RUNS_ROOT": str(self.runs)}

    def tearDown(self):
        self._tmp.cleanup()

    # --- init -----------------------------------------------------------------
    def test_init_cree_dossier_et_meta(self):
        res = run("init", "Phase 0 — Fondations", "2", env=self.env)
        self.assertEqual(res.returncode, 0, res.stderr)
        rid = res.stdout.strip()
        d = self.runs / rid
        self.assertTrue(d.is_dir())
        self.assertTrue((d / "journal.ndjson").is_file())
        meta = (d / "meta.json").read_text(encoding="utf-8")
        self.assertIn('"milestone":"Phase 0 — Fondations"', meta)
        self.assertIn('"max_parallel":2', meta)
        # meta.json est un JSON valide.
        json.loads(meta)

    def test_init_sans_milestone_echoue(self):
        res = run("init", env=self.env)
        self.assertNotEqual(res.returncode, 0)

    # --- log ------------------------------------------------------------------
    def _init(self, rid="20260101T000000Z-test"):
        run("init", "Jalon", "2", env={**self.env, "NM_RUN_ID": rid})
        return self.runs / rid

    def test_log_ecrit_lignes_et_pr(self):
        d = self._init()
        env = {**self.env, "NM_RUN_ID": d.name}
        self.assertEqual(run("log", "12", "queued", "--agent", "orchestrateur",
                             "--detail", "en attente", env=env).returncode, 0)
        self.assertEqual(run("log", "12", "dev", "--agent", "dev-ticket", env=env).returncode, 0)
        self.assertEqual(run("log", "12", "tests", "--agent", "dev-ticket",
                             "--pr", "77", env=env).returncode, 0)
        lines = (d / "journal.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 3)
        blob = "\n".join(lines)
        self.assertIn('"ticket":12', blob)
        self.assertIn('"phase":"tests"', blob)
        self.assertIn('"pr":77', blob)
        self.assertIn('"pr":null', blob)
        for line in lines:  # chaque ligne est un JSON valide
            json.loads(line)

    def test_log_detail_echappe(self):
        d = self._init()
        env = {**self.env, "NM_RUN_ID": d.name}
        run("log", "13", "dev", "--detail", 'say "hi"', env=env)
        content = (d / "journal.ndjson").read_text(encoding="utf-8")
        self.assertIn(r'\"hi\"', content)
        self.assertEqual(json.loads(content.splitlines()[0])["detail"], 'say "hi"')

    def test_log_phase_inconnue_rejetee(self):
        d = self._init()
        env = {**self.env, "NM_RUN_ID": d.name}
        before = (d / "journal.ndjson").read_text(encoding="utf-8")
        res = run("log", "14", "wizz", env=env)
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual((d / "journal.ndjson").read_text(encoding="utf-8"), before)

    def test_log_ticket_non_numerique_rejete(self):
        d = self._init()
        res = run("log", "abc", "dev", env={**self.env, "NM_RUN_ID": d.name})
        self.assertNotEqual(res.returncode, 0)

    def test_log_sans_run_echoue_proprement(self):
        res = run("log", "1", "dev", env=self.env)  # aucun run
        self.assertNotEqual(res.returncode, 0)

    # --- dir ------------------------------------------------------------------
    def test_dir_plus_recent_explicite_inexistant(self):
        run("init", "A", env={**self.env, "NM_RUN_ID": "20260101T000000Z-aaaa"})
        run("init", "B", env={**self.env, "NM_RUN_ID": "20260101T000001Z-bbbb"})
        latest = run("dir", env=self.env)
        self.assertEqual(Path(latest.stdout.strip()).name, "20260101T000001Z-bbbb")
        explicit = run("dir", "20260101T000000Z-aaaa", env=self.env)
        self.assertEqual(Path(explicit.stdout.strip()).name, "20260101T000000Z-aaaa")
        self.assertNotEqual(run("dir", "nexiste-pas", env=self.env).returncode, 0)


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd, check=True, capture_output=True,
    )


class WorktreeTests(unittest.TestCase):
    """Les agents dev/QA tournent en worktree : ils doivent écrire dans le journal
    du dépôt principal, celui que lit le dashboard (#47)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name).resolve()
        self.main = base / "principal"
        self.wt = base / "agent-wt"
        self.main.mkdir()
        git(self.main, "init", "-q")
        git(self.main, "commit", "-q", "--allow-empty", "-m", "init")
        git(self.main, "worktree", "add", "-q", str(self.wt), "-b", "agent")
        # Ni NM_RUNS_ROOT ni NM_RUN_ID hérités : seule la résolution git compte.
        self.env = {k: v for k, v in os.environ.items() if k not in ("NM_RUNS_ROOT", "NM_RUN_ID")}

    def tearDown(self):
        self._tmp.cleanup()

    def cli(self, cwd, *args):
        return subprocess.run(
            [sys.executable, str(JOURNAL_PY), *args], cwd=cwd, env=self.env,
            capture_output=True, text=True, encoding="utf-8",
        )

    def test_root_depuis_worktree_vise_le_depot_principal(self):
        attendu = (self.main / ".nickmare" / "runs").resolve()
        depuis_wt = Path(self.cli(self.wt, "root").stdout.strip()).resolve()
        depuis_main = Path(self.cli(self.main, "root").stdout.strip()).resolve()
        self.assertEqual(depuis_wt, attendu)
        self.assertEqual(depuis_main, attendu)

    def test_log_depuis_worktree_ecrit_dans_le_journal_principal(self):
        rid = self.cli(self.main, "init", "Phase 0 — Fondations").stdout.strip()
        self.assertTrue(rid)
        res = self.cli(self.wt, "log", "7", "dev", "--agent", "dev-ticket")
        self.assertEqual(res.returncode, 0, res.stderr)
        journal = self.main / ".nickmare" / "runs" / rid / "journal.ndjson"
        lignes = journal.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lignes), 1)
        self.assertEqual(json.loads(lignes[0])["ticket"], 7)
        self.assertFalse((self.wt / ".nickmare").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
