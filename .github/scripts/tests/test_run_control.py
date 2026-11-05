#!/usr/bin/env python3
"""Tests du contrôle de run de scripts/run_journal.py (issue #48). Aucun réseau.

Couvre les codes de sortie de ``gate`` et leur priorité (arrêt > quota > pause),
l'écriture atomique de ``control.json``, la sémantique de ``unpause`` /
``quota clear`` (une pause ``human`` n'est jamais levée par une reprise de quota),
et le fail-safe (``control.json`` illisible ⇒ gate rend « pause »).

La CLI est exercée via subprocess (chemin réellement emprunté par le shim bash),
sur une racine de runs temporaire. ``NM_RUNS_ROOT`` est passé dans l'environnement
du sous-processus (jamais via un run git). Les helpers de contrôle sont aussi
testés en direct (import), pour l'écriture atomique et les bornes de quota.

Lancement : ``python .github/scripts/tests/test_run_control.py``.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
JOURNAL_PY = ROOT / "scripts" / "run_journal.py"
sys.path.insert(0, str(ROOT / "scripts"))
import run_journal  # noqa: E402


def run(*args, env=None):
    base = dict(os.environ)
    base.pop("NM_RUN_ID", None)
    if env:
        base.update(env)
    return subprocess.run(
        [sys.executable, str(JOURNAL_PY), *args],
        capture_output=True, text=True, encoding="utf-8", env=base,
    )


class GateCliTests(unittest.TestCase):
    """Codes de sortie de gate et leur priorité, via la CLI (bout en bout)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.runs = Path(self._tmp.name) / "runs"
        self.rid = "20260101T000000Z-gate"
        self.env = {"NM_RUNS_ROOT": str(self.runs), "NM_RUN_ID": self.rid}
        self.assertEqual(run("init", "Jalon", "2", env=self.env).returncode, 0)
        self.d = self.runs / self.rid

    def tearDown(self):
        self._tmp.cleanup()

    def gate_code(self):
        return run("gate", env=self.env).returncode

    def test_run_neuf_continue(self):
        # Aucun control.json : run neuf → continuer (0).
        self.assertFalse((self.d / "control.json").exists())
        self.assertEqual(self.gate_code(), 0)

    def test_pause_rend_1(self):
        self.assertEqual(run("pause", "--reason", "revue", env=self.env).returncode, 0)
        self.assertEqual(self.gate_code(), 1)

    def test_stop_rend_2(self):
        self.assertEqual(run("stop", env=self.env).returncode, 0)
        self.assertEqual(self.gate_code(), 2)

    def test_idle_rend_3_sans_run(self):
        # Racine sans aucun run : plus rien à faire (3).
        res = run("gate", env={"NM_RUNS_ROOT": str(Path(self._tmp.name) / "vide")})
        self.assertEqual(res.returncode, 3)

    def test_quota_rend_4_et_imprime_reprise(self):
        self.assertEqual(run("quota", "hold", "--until", "+90m", env=self.env).returncode, 0)
        res = run("gate", env=self.env)
        self.assertEqual(res.returncode, 4)
        self.assertIn("quota", res.stdout.lower())
        self.assertRegex(res.stdout, r"reprise")

    # --- Priorité : arrêt > quota > pause ------------------------------------
    def test_priorite_arret_sur_quota_et_pause(self):
        run("pause", env=self.env)
        run("quota", "hold", "--until", "+90m", env=self.env)
        run("stop", env=self.env)
        self.assertEqual(self.gate_code(), 2)  # arrêt l'emporte

    def test_priorite_quota_sur_pause(self):
        run("pause", "--reason", "revue", env=self.env)
        run("quota", "hold", "--until", "+90m", env=self.env)
        self.assertEqual(self.gate_code(), 4)  # quota l'emporte sur la pause

    # --- unpause / quota clear : la pause humaine est tenace -----------------
    def test_unpause_laisse_la_pause_quota_active(self):
        run("pause", env=self.env)
        run("quota", "hold", "--until", "+90m", env=self.env)
        self.assertEqual(run("unpause", env=self.env).returncode, 0)
        control = json.loads((self.d / "control.json").read_text(encoding="utf-8"))
        self.assertNotIn("human", control["pause"])
        self.assertIn("quota", control["pause"])      # quota reste
        self.assertEqual(self.gate_code(), 4)          # toujours bloqué par le quota

    def test_quota_clear_ne_leve_pas_la_pause_humaine(self):
        run("pause", "--reason", "revue manuelle", env=self.env)
        run("quota", "hold", "--until", "+90m", env=self.env)
        self.assertEqual(run("quota", "clear", env=self.env).returncode, 0)
        control = json.loads((self.d / "control.json").read_text(encoding="utf-8"))
        self.assertIn("human", control["pause"])       # pause humaine intacte
        self.assertNotIn("quota", control["pause"])
        self.assertEqual(self.gate_code(), 1)           # pause humaine seule

    def test_unpause_all_leve_tout(self):
        run("pause", env=self.env)
        run("quota", "hold", "--until", "+90m", env=self.env)
        self.assertEqual(run("unpause", "--all", env=self.env).returncode, 0)
        control = json.loads((self.d / "control.json").read_text(encoding="utf-8"))
        self.assertEqual(control["pause"], {})
        self.assertEqual(self.gate_code(), 0)

    def test_quota_expire_ne_bloque_plus(self):
        # Échéance déjà passée : la fenêtre a rouvert, gate continue (0).
        run("quota", "hold", "--until", str(int(time.time()) - 10), env=self.env)
        self.assertEqual(self.gate_code(), 0)

    # --- Journalisation des changements de contrôle --------------------------
    def test_changements_journalises_phases_paused_interrupted(self):
        run("pause", "--reason", "revue", env=self.env)
        run("stop", env=self.env)
        lines = [json.loads(x) for x in
                 (self.d / "journal.ndjson").read_text(encoding="utf-8").splitlines() if x.strip()]
        phases = [(e["ticket"], e["phase"]) for e in lines]
        self.assertIn((0, "paused"), phases)
        self.assertIn((0, "interrupted"), phases)

    # --- status --------------------------------------------------------------
    def test_status_lisible(self):
        run("pause", "--reason", "revue", "--by", "alice", env=self.env)
        res = run("status", env=self.env)
        self.assertEqual(res.returncode, 0)
        self.assertIn("pause", res.stdout.lower())
        self.assertIn("alice", res.stdout)

    # --- Commandes de contrôle sans run actif --------------------------------
    def test_pause_sans_run_echoue_proprement(self):
        res = run("pause", env={"NM_RUNS_ROOT": str(Path(self._tmp.name) / "vide")})
        self.assertNotEqual(res.returncode, 0)


class FailSafeTests(unittest.TestCase):
    """Fail-safe : control.json illisible ⇒ gate rend « pause » (1), jamais 0."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.runs = Path(self._tmp.name) / "runs"
        self.rid = "20260101T000000Z-fs"
        self.env = {"NM_RUNS_ROOT": str(self.runs), "NM_RUN_ID": self.rid}
        run("init", "Jalon", "2", env=self.env)
        self.d = self.runs / self.rid

    def tearDown(self):
        self._tmp.cleanup()

    def test_control_corrompu_rend_pause(self):
        (self.d / "control.json").write_text("{ ceci n'est pas du json",
                                              encoding="utf-8")
        res = run("gate", env=self.env)
        self.assertEqual(res.returncode, 1)
        self.assertIn("fail-safe", (res.stdout + res.stderr).lower())

    def test_control_non_objet_rend_pause(self):
        (self.d / "control.json").write_text("[1,2,3]", encoding="utf-8")
        self.assertEqual(run("gate", env=self.env).returncode, 1)

    def test_mutation_sur_control_corrompu_ne_plante_pas(self):
        # Un opérateur ne doit jamais être bloqué par un control.json illisible :
        # `stop` repart d'un état par défaut et réécrit proprement (pas de traceback).
        (self.d / "control.json").write_text("{ corrompu", encoding="utf-8")
        res = run("stop", env=self.env)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        self.assertEqual(run("gate", env=self.env).returncode, 2)  # arrêt effectif


class AtomicWriteTests(unittest.TestCase):
    """Écriture atomique de control.json : pas de fichier temporaire résiduel,
    contenu toujours un JSON valide, et aucun demi-fichier observable."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name) / "run"
        self.d.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_control_atomique(self):
        control = run_journal._default_control()
        control["pause"]["human"] = {"since": "x", "by": "alice", "reason": "r"}
        run_journal.save_control(self.d, control)
        path = self.d / "control.json"
        self.assertTrue(path.is_file())
        # JSON valide + champ updated posé.
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("updated", data)
        self.assertEqual(data["pause"]["human"]["by"], "alice")
        # Aucun fichier temporaire ne subsiste.
        residus = [p.name for p in self.d.iterdir() if p.name != "control.json"]
        self.assertEqual(residus, [], f"résidus : {residus}")

    def test_remplacement_laisse_toujours_un_json_valide(self):
        for i in range(5):
            control = run_journal._default_control()
            control["author"] = f"it{i}"
            run_journal.save_control(self.d, control)
            data = json.loads((self.d / "control.json").read_text(encoding="utf-8"))
            self.assertEqual(data["author"], f"it{i}")


class ParseWhenTests(unittest.TestCase):
    def test_relatif(self):
        before = time.time()
        got = run_journal.parse_when("+90m")
        self.assertAlmostEqual(got, before + 90 * 60, delta=5)

    def test_epoch(self):
        self.assertEqual(run_journal.parse_when("1762300000"), 1762300000.0)

    def test_iso(self):
        got = run_journal.parse_when("2030-01-01T00:00:00Z")
        self.assertEqual(run_journal.iso_utc(got), "2030-01-01T00:00:00Z")

    def test_vide_rejete(self):
        with self.assertRaises(ValueError):
            run_journal.parse_when("")

    def test_illisible_rejete(self):
        with self.assertRaises(ValueError):
            run_journal.parse_when("demain matin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
