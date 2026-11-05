#!/usr/bin/env python3
"""Tests de la veille Windows & du préflight (scripts/run_supervise.py, issue #50).

Aucun réseau, aucun ``schtasks`` réel : les commandes externes (``schtasks``, ``gh``)
sont **bouchonnées** par de petits scripts Python passés sous forme de **liste**
(``[python, stub, …]``), ce qui évite tout souci de citation multiplateforme — ces
tests tournent sur ubuntu comme sur windows.

Couvre les critères d'acceptation de l'issue #50 :

* **Préflight** sur un ``~/.claude.json`` factice : approbation sous une **seule casse**
  ⇒ avertissement (leçon *hotelerie* : la casse exacte du chemin fait foi).
* **Armement idempotent** : réarmer ne crée pas de doublon (``schtasks /Create /F``),
  avec les réglages d'alimentation corrigés dans le XML (démarrage sur batterie,
  ``StartWhenAvailable``) et des chemins **entre guillemets** dans le ``.cmd``.
* **Auto-désarmement** : chacun des cas (jalon vidé, ``stop``, pause ``human``, run
  supprimé, armement > 14 jours).
* **Relance seulement si** (travail restant ∧ aucun battement ∧ quota revenu) —
  la décision pure et le réveil de bout en bout.

Lancement : ``python .github/scripts/tests/test_run_veille.py``.
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
sys.path.insert(0, str(ROOT / "scripts"))
import run_journal  # noqa: E402
import run_supervise as rs  # noqa: E402


# --- Bouchons : schtasks journalise ses arguments, gh répond en JSON -----------

FAKE_SCHTASKS = r'''
import sys
logf = sys.argv[1]
with open(logf, "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[2:]) + "\n")
sys.exit(0)
'''

# gh bouchonné : `issue list` → liste d'issues ouvertes du scénario ; `auth status` → 0.
FAKE_GH = r'''
import json, sys
argv = sys.argv[1:]
scen = argv[0]
rest = argv[1:]
data = json.loads(open(scen, encoding="utf-8").read())
if "issue" in rest and "list" in rest:
    sys.stdout.write(json.dumps(data.get("open_issues", [])))
    sys.exit(0)
if "auth" in rest and "status" in rest:
    sys.exit(0 if data.get("auth_ok", True) else 1)
sys.stdout.write("[]")
'''


class ApprovedDirTests(unittest.TestCase):
    """Approbation du dossier dans ~/.claude.json, lue sur la casse EXACTE."""

    def test_casse_exacte_approuvee(self):
        cj = {"projects": {"D:/spyle/nickmare": {"hasTrustDialogAccepted": True}}}
        ok, warns = rs.check_approved_dir(cj, "D:/spyle/nickmare")
        self.assertTrue(ok)
        self.assertEqual(warns, [])

    def test_casse_exacte_backslashes_normalises(self):
        cj = {"projects": {"D:/spyle/nickmare": {"hasTrustDialogAccepted": True}}}
        ok, _ = rs.check_approved_dir(cj, "D:\\spyle\\nickmare\\")
        self.assertTrue(ok)

    def test_approbation_sous_une_seule_casse_avertit(self):
        # Approuvé sous d:/… mais lancé sous D:/… → NON approuvé + avertissement.
        cj = {"projects": {"d:/spyle/nickmare": {"hasTrustDialogAccepted": True}}}
        ok, warns = rs.check_approved_dir(cj, "D:/spyle/nickmare")
        self.assertFalse(ok)
        self.assertEqual(len(warns), 1)
        self.assertIn("AUTRE casse", warns[0])
        self.assertIn("d:/spyle/nickmare", warns[0])

    def test_dossier_absent_avertit(self):
        cj = {"projects": {"D:/autre/projet": {"hasTrustDialogAccepted": True}}}
        ok, warns = rs.check_approved_dir(cj, "D:/spyle/nickmare")
        self.assertFalse(ok)
        self.assertIn("absent", warns[0])

    def test_present_mais_trust_refuse(self):
        cj = {"projects": {"D:/spyle/nickmare": {"hasTrustDialogAccepted": False}}}
        ok, warns = rs.check_approved_dir(cj, "D:/spyle/nickmare")
        self.assertFalse(ok)
        self.assertIn("hasTrustDialogAccepted=false", warns[0])


class PreflightTests(unittest.TestCase):
    """Préflight de bout en bout avec commandes bouchonnées + dépôt git réel."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        # gh bouchonné (présent + auth ok).
        self.gh = self.tmp / "fake_gh.py"
        self.gh.write_text(FAKE_GH, encoding="utf-8")
        self.scen = self.tmp / "gh.json"
        self.scen.write_text(json.dumps({"auth_ok": True, "open_issues": []}),
                             encoding="utf-8")
        self.gh_cmd = [sys.executable, str(self.gh), str(self.scen)]
        self.claude_json = self.tmp / "claude.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _write_cj(self, projects):
        self.claude_json.write_text(json.dumps({"projects": projects}), encoding="utf-8")

    def test_tout_vert_quand_approuve_casse_exacte(self):
        key = rs._norm_path_key(str(self.repo))
        self._write_cj({key: {"hasTrustDialogAccepted": True}})
        pf = rs.preflight(launch_dir=str(self.repo), claude_cmd=[sys.executable],
                          gh_cmd=self.gh_cmd, git_cmd="git",
                          claude_json_path=str(self.claude_json))
        self.assertTrue(pf.ok, "\n".join(pf.report()))
        self.assertEqual(pf.warnings, [])

    def test_echec_et_avertissement_si_casse_divergente(self):
        # Approuvé sous la casse tout-en-majuscules seulement → lancement NON approuvé.
        self._write_cj({rs._norm_path_key(str(self.repo)).upper():
                        {"hasTrustDialogAccepted": True}})
        pf = rs.preflight(launch_dir=str(self.repo), claude_cmd=[sys.executable],
                          gh_cmd=self.gh_cmd, git_cmd="git",
                          claude_json_path=str(self.claude_json))
        self.assertFalse(pf.ok)
        self.assertTrue(any("AUTRE casse" in w for w in pf.warnings))

    def test_claude_absent_fait_echouer(self):
        self._write_cj({rs._norm_path_key(str(self.repo)): {"hasTrustDialogAccepted": True}})
        pf = rs.preflight(launch_dir=str(self.repo),
                          claude_cmd=["/n/existe/pas/claude"],
                          gh_cmd=self.gh_cmd, git_cmd="git",
                          claude_json_path=str(self.claude_json))
        self.assertFalse(pf.ok)

    def test_gh_non_authentifie_fait_echouer(self):
        self.scen.write_text(json.dumps({"auth_ok": False, "open_issues": []}),
                             encoding="utf-8")
        self._write_cj({rs._norm_path_key(str(self.repo)): {"hasTrustDialogAccepted": True}})
        pf = rs.preflight(launch_dir=str(self.repo), claude_cmd=[sys.executable],
                          gh_cmd=self.gh_cmd, git_cmd="git",
                          claude_json_path=str(self.claude_json))
        self.assertFalse(pf.ok)

    def test_hors_depot_git_fait_echouer(self):
        self._write_cj({rs._norm_path_key(str(self.tmp)): {"hasTrustDialogAccepted": True}})
        pf = rs.preflight(launch_dir=str(self.tmp), claude_cmd=[sys.executable],
                          gh_cmd=self.gh_cmd, git_cmd="git",
                          claude_json_path=str(self.claude_json))
        self.assertFalse(pf.ok)


class PureDecisionTests(unittest.TestCase):
    """Décisions pures : relance et motifs d'auto-désarmement."""

    def test_relance_seulement_si_travail_sans_battement_et_quota(self):
        # Seul (travail restant ∧ aucun battement ∧ quota revenu) relance.
        for work in (True, False):
            for beat in (True, False):
                for quota in (True, False):
                    expected = work and not beat and quota
                    self.assertEqual(
                        rs.should_relaunch(work_remaining=work, heartbeat_alive=beat,
                                           quota_available=quota),
                        expected, f"work={work} beat={beat} quota={quota}")

    def test_disarm_run_supprime(self):
        self.assertEqual(
            rs.disarm_reason(run_present=False, milestone_empty=False, stopped=False,
                             human_paused=False, age_days=0),
            "run supprimé (plus de dossier de run)")

    def test_disarm_stop_prime_sur_le_reste(self):
        r = rs.disarm_reason(run_present=True, milestone_empty=True, stopped=True,
                             human_paused=True, age_days=99)
        self.assertIn("arrêt", r)

    def test_disarm_pause_humaine(self):
        r = rs.disarm_reason(run_present=True, milestone_empty=False, stopped=False,
                             human_paused=True, age_days=0)
        self.assertIn("pause humaine", r)

    def test_disarm_jalon_vide(self):
        r = rs.disarm_reason(run_present=True, milestone_empty=True, stopped=False,
                             human_paused=False, age_days=0)
        self.assertIn("jalon vidé", r)

    def test_disarm_age_depasse_14j(self):
        r = rs.disarm_reason(run_present=True, milestone_empty=False, stopped=False,
                             human_paused=False, age_days=14.5)
        self.assertIn("14 jours", r)

    def test_pas_de_disarm_quand_tout_va_bien(self):
        self.assertIsNone(
            rs.disarm_reason(run_present=True, milestone_empty=False, stopped=False,
                             human_paused=False, age_days=3))


class VeilleRunTests(unittest.TestCase):
    """Armement / désarmement / réveil sur un vrai run (schtasks + gh bouchonnés)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.runs = self.tmp / "runs"
        self.rid = "20260101T000000Z-veille"
        os.environ["NM_RUNS_ROOT"] = str(self.runs)
        os.environ["NM_RUN_ID"] = self.rid
        run_journal.run_init("Jalon", "2")
        self.d = self.runs / self.rid
        # schtasks bouchonné (journalise ses arguments).
        self.sch = self.tmp / "fake_schtasks.py"
        self.sch.write_text(FAKE_SCHTASKS, encoding="utf-8")
        self.schlog = self.tmp / "schtasks.log"
        self.sch_cmd = [sys.executable, str(self.sch), str(self.schlog)]
        # gh bouchonné (issues ouvertes configurables).
        self.gh = self.tmp / "fake_gh.py"
        self.gh.write_text(FAKE_GH, encoding="utf-8")
        self.ghscen = self.tmp / "gh.json"
        self._set_open_issues([{"number": 5}])
        self.gh_cmd = [sys.executable, str(self.gh), str(self.ghscen)]

    def tearDown(self):
        os.environ.pop("NM_RUNS_ROOT", None)
        os.environ.pop("NM_RUN_ID", None)
        self._tmp.cleanup()

    def _set_open_issues(self, issues):
        self.ghscen.write_text(json.dumps({"open_issues": issues, "auth_ok": True}),
                               encoding="utf-8")

    def _sch_lines(self):
        if not self.schlog.exists():
            return []
        return [ln for ln in self.schlog.read_text(encoding="utf-8").splitlines() if ln]

    def _alive(self, *, state="leg", age_seconds=0):
        ts = run_journal.iso_utc(time.time() - age_seconds)
        (self.d / "supervisor.alive").write_text(
            json.dumps({"state": state, "ts": ts, "pid": 1}), encoding="utf-8")

    def _arm(self, launch_dir=None):
        return rs.arm_watchdog(self.d, "Jalon", run_id=self.rid, max_parallel=2,
                               launch_dir=launch_dir or str(self.tmp / "Spa & Booking"),
                               schtasks_cmd=self.sch_cmd)

    # -- armement -------------------------------------------------------------

    def test_armement_ecrit_cmd_xml_et_etat(self):
        state, ok, _ = self._arm()
        self.assertTrue(ok)
        self.assertTrue(state["armed"])
        self.assertTrue((self.d / "veille.cmd").exists())
        self.assertTrue((self.d / "veille-task.xml").exists())
        # Le .cmd cite les chemins (espaces : « Spa & Booking ») et appelle --wake.
        cmd = (self.d / "veille.cmd").read_text(encoding="utf-8")
        self.assertIn('cd /d "', cmd)
        self.assertIn("Spa & Booking", cmd)
        self.assertIn("--wake", cmd)
        # Réglages d'alimentation corrigés dans le XML.
        xml = (self.d / "veille-task.xml").read_text(encoding="utf-16")
        self.assertIn("<StartWhenAvailable>true</StartWhenAvailable>", xml)
        self.assertIn("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>", xml)
        self.assertIn("<Interval>PT5M</Interval>", xml)
        # schtasks a bien été appelé en création forcée.
        self.assertTrue(any("/Create" in ln and "/F" in ln for ln in self._sch_lines()))

    def test_armement_idempotent(self):
        s1, _, _ = self._arm()
        s2, _, _ = self._arm()
        self.assertEqual(s1["task_name"], s2["task_name"])
        self.assertTrue(s2["armed"])
        creates = [ln for ln in self._sch_lines() if "/Create" in ln]
        self.assertEqual(len(creates), 2)                 # deux créations…
        self.assertTrue(all("/F" in ln for ln in creates))  # …toutes forcées (pas de doublon)
        # Un seul nom de tâche (déterministe) : réarmer n'empile pas.
        names = {ln.split("/TN")[1].split("/F")[0].strip() for ln in creates}
        self.assertEqual(len(names), 1)

    # -- désarmement manuel ---------------------------------------------------

    def test_disarm_supprime_la_tache_et_marque_etat(self):
        self._arm()
        removed = rs.disarm_watchdog(self.d, schtasks_cmd=self.sch_cmd, reason="test")
        self.assertTrue(removed)
        self.assertTrue(any("/Delete" in ln for ln in self._sch_lines()))
        state = rs.load_watchdog(self.d)
        self.assertFalse(state["armed"])
        self.assertEqual(state["disarm_reason"], "test")

    # -- heartbeat / quota helpers -------------------------------------------

    def test_heartbeat_frais_vivant_perime_mort(self):
        self._alive(state="leg", age_seconds=0)
        self.assertTrue(rs.heartbeat_alive(self.d, time.time()))
        self._alive(state="leg", age_seconds=1000)    # > 600 s
        self.assertFalse(rs.heartbeat_alive(self.d, time.time()))

    def test_heartbeat_stopped_compte_comme_mort(self):
        self._alive(state="stopped", age_seconds=0)
        self.assertFalse(rs.heartbeat_alive(self.d, time.time()))

    def test_heartbeat_absent_mort(self):
        self.assertFalse(rs.heartbeat_alive(self.d, time.time()))

    def test_quota_available(self):
        self.assertTrue(rs.quota_available(self.d))
        run_journal.control_quota_hold(run_journal.iso_utc(time.time() + 3600),
                                       by="superviseur", run_id=self.rid)
        self.assertFalse(rs.quota_available(self.d))

    # -- réveil : relance -----------------------------------------------------

    def test_wake_relance_si_travail_sans_battement_et_quota(self):
        self._arm()
        self._set_open_issues([{"number": 5}])    # travail restant
        # Pas de supervisor.alive → aucun battement ; pas de control → quota revenu.
        spawned = []
        status, msg = rs.wake(self.rid, gh_cmd=self.gh_cmd, schtasks_cmd=self.sch_cmd,
                              spawn_fn=spawned.append)
        self.assertEqual(status, rs.WAKE_RELAUNCHED, msg)
        self.assertEqual(len(spawned), 1)
        self.assertEqual(spawned[0]["milestone"], "Jalon")

    def test_wake_ne_relance_pas_si_battement(self):
        self._arm()
        self._alive(state="leg", age_seconds=0)    # un superviseur bat
        spawned = []
        status, _ = rs.wake(self.rid, gh_cmd=self.gh_cmd, schtasks_cmd=self.sch_cmd,
                            spawn_fn=spawned.append)
        self.assertEqual(status, rs.WAKE_IDLE)
        self.assertEqual(spawned, [])

    def test_wake_ne_relance_pas_si_quota_actif(self):
        self._arm()
        run_journal.control_quota_hold(run_journal.iso_utc(time.time() + 3600),
                                       by="superviseur", run_id=self.rid)
        spawned = []
        status, _ = rs.wake(self.rid, gh_cmd=self.gh_cmd, schtasks_cmd=self.sch_cmd,
                            spawn_fn=spawned.append)
        self.assertEqual(status, rs.WAKE_IDLE)
        self.assertEqual(spawned, [])

    # -- réveil : auto-désarmement -------------------------------------------

    def test_wake_desarme_si_jalon_vide(self):
        self._arm()
        self._set_open_issues([])     # plus d'issue ouverte
        spawned = []
        status, msg = rs.wake(self.rid, gh_cmd=self.gh_cmd, schtasks_cmd=self.sch_cmd,
                              spawn_fn=spawned.append)
        self.assertEqual(status, rs.WAKE_DISARMED)
        self.assertIn("jalon vidé", msg)
        self.assertEqual(spawned, [])
        self.assertFalse(rs.load_watchdog(self.d)["armed"])
        self.assertTrue(any("/Delete" in ln for ln in self._sch_lines()))

    def test_wake_desarme_si_stop(self):
        self._arm()
        run_journal.control_stop(by="bob", run_id=self.rid)
        status, msg = rs.wake(self.rid, gh_cmd=self.gh_cmd, schtasks_cmd=self.sch_cmd)
        self.assertEqual(status, rs.WAKE_DISARMED)
        self.assertIn("arrêt", msg)

    def test_wake_desarme_si_pause_humaine(self):
        self._arm()
        run_journal.control_pause(by="alice", reason="revue", run_id=self.rid)
        status, msg = rs.wake(self.rid, gh_cmd=self.gh_cmd, schtasks_cmd=self.sch_cmd)
        self.assertEqual(status, rs.WAKE_DISARMED)
        self.assertIn("pause humaine", msg)
        # La pause humaine est INTACTE : la veille ne lève jamais une pause human.
        control = run_journal.load_control(self.d)
        self.assertIn("human", control["pause"])

    def test_wake_desarme_si_armement_trop_ancien(self):
        state, _, _ = self._arm()
        state["armed_at"] = run_journal.iso_utc(time.time() - 15 * 86400)
        rs.save_watchdog(self.d, state)
        status, msg = rs.wake(self.rid, gh_cmd=self.gh_cmd, schtasks_cmd=self.sch_cmd)
        self.assertEqual(status, rs.WAKE_DISARMED)
        self.assertIn("14 jours", msg)

    def test_wake_se_supprime_si_non_armee(self):
        # Aucun watchdog.json (veille non armée) : la veille se supprime.
        status, _ = rs.wake(self.rid, gh_cmd=self.gh_cmd, schtasks_cmd=self.sch_cmd)
        self.assertEqual(status, rs.WAKE_DISARMED)
        self.assertTrue(any("/Delete" in ln for ln in self._sch_lines()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
