#!/usr/bin/env python3
"""Tests de scripts/run_dashboard.py (issue #40). Aucun appel réseau.

Rendu en mode ``--once`` (sans couleur) pour pouvoir vérifier le texte.
Lancement : ``python .github/scripts/tests/test_run_dashboard.py``.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DASH_PY = ROOT / "scripts" / "run_dashboard.py"

JOURNAL = """\
{"ts":"2026-01-01T12:00:00Z","run_id":"r","ticket":1,"phase":"queued","agent":"orchestrateur","pr":null,"detail":"init"}
{"ts":"2026-01-01T12:01:00Z","run_id":"r","ticket":1,"phase":"dev","agent":"dev-ticket","pr":null,"detail":""}
{"ts":"2026-01-01T12:05:00Z","run_id":"r","ticket":1,"phase":"tests","agent":"dev-ticket","pr":55,"detail":""}
ligne corrompue à ignorer {pas du json}
{"ts":"2026-01-01T12:02:00Z","run_id":"r","ticket":2,"phase":"done","agent":"qa-ticket","pr":56,"detail":"fusionné"}
"""


def dash(*args, env=None):
    base = dict(os.environ)
    base.pop("NM_RUN_ID", None)
    base.pop("NM_FORCE_COLOR", None)
    if env:
        base.update(env)
    # Le dashboard émet de l'UTF-8 ; on décode pareil (sinon mojibake sur une
    # console Windows cp1252 et l'em-dash « — » ne correspond plus).
    return subprocess.run(
        [sys.executable, str(DASH_PY), *args],
        capture_output=True, text=True, encoding="utf-8", env=base,
    )


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.runs = Path(self._tmp.name) / "runs"
        self.rid = "20260101T120000Z-test"
        self.rdir = self.runs / self.rid
        self.rdir.mkdir(parents=True)
        (self.rdir / "meta.json").write_text(
            '{"run_id":"%s","milestone":"Phase 0 — Fondations",'
            '"started_at":"2026-01-01T12:00:00Z","max_parallel":2}\n' % self.rid,
            encoding="utf-8",
        )
        (self.rdir / "journal.ndjson").write_text(JOURNAL, encoding="utf-8")
        self.env = {"NM_RUNS_ROOT": str(self.runs)}

    def tearDown(self):
        self._tmp.cleanup()

    def test_once_sort_proprement(self):
        res = dash(self.rid, "--once", env=self.env)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_phase_courante_est_dernier_evenement(self):
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertRegex(out, r"#1 .*TESTS")   # dernier événement du ticket 1
        self.assertRegex(out, r"#2 .*DONE")

    def test_ligne_corrompue_ignoree(self):
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertIn("#1", out)
        self.assertIn("#2", out)

    def test_progression_1_sur_2(self):
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertRegex(out, r"Progression: .*1/2")

    def test_pr_affichee(self):
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertIn("PR#55", out)

    def test_jalon_dans_entete(self):
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertIn("Phase 0 — Fondations", out)

    def test_resolution_par_chemin(self):
        out = dash(str(self.rdir / "journal.ndjson"), "--once", env=self.env).stdout
        self.assertRegex(out, r"#1 .*TESTS")

    def test_resolution_plus_recent(self):
        out = dash("--once", env=self.env).stdout
        self.assertRegex(out, r"#1 .*TESTS")

    def test_run_inexistant_message_et_statut_0(self):
        empty = Path(self._tmp.name) / "vide"
        empty.mkdir()
        res = dash("--once", env={"NM_RUNS_ROOT": str(empty)})
        self.assertEqual(res.returncode, 0)
        self.assertIn("aucun run", (res.stdout + res.stderr).lower())

    def test_titre_depuis_titles_tsv(self):
        (self.rdir / "titles.tsv").write_text("1\tPhase 0 · core::model\n", encoding="utf-8")
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertIn("core::model", out)

    # --- Bannière de contrôle (issue #48) ------------------------------------
    def _write_control(self, obj):
        (self.rdir / "control.json").write_text(
            obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False),
            encoding="utf-8")

    def test_banniere_pause_humaine(self):
        self._write_control({
            "signal": "pause", "author": "alice",
            "pause": {"human": {"since": "2026-01-01T12:30:00Z",
                                "by": "alice", "reason": "revue manuelle"}},
        })
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertIn("PAUSE", out)
        self.assertIn("alice", out)
        self.assertIn("revue manuelle", out)

    def test_banniere_arret(self):
        self._write_control({"signal": "stop", "author": "bob",
                             "stop_reason": "fin de journée", "pause": {}})
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertIn("ARRÊT", out)
        self.assertIn("bob", out)

    def test_banniere_quota(self):
        self._write_control({
            "signal": "pause", "author": "superviseur",
            "pause": {"quota": {"since": "2026-01-01T12:00:00Z",
                                "until": 4102444800.0,  # 2100 : toujours futur
                                "until_iso": "2100-01-01T00:00:00Z",
                                "reason": "fenêtre 5h"}},
        })
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertIn("QUOTA", out)
        self.assertIn("2100-01-01T00:00:00Z", out)

    def test_banniere_absente_quand_run_tourne(self):
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertNotIn("PAUSE", out)
        self.assertNotIn("ARRÊT", out)

    def test_banniere_control_illisible_failsafe(self):
        self._write_control("{ pas du json")
        out = dash(self.rid, "--once", env=self.env).stdout
        self.assertIn("ILLISIBLE", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
