#!/usr/bin/env python3
"""Tests du superviseur de run (scripts/run_supervise.py, issue #49). Aucun réseau.

Couvre les critères d'acceptation de l'issue #49 :

* un **faux claude** rejouant des flux ``stream-json`` : refus de quota (avec et
  sans ``resetsAt``), fenêtre à 85 % à l'ouverture, appel muet coupé, appel sain ;
* une **pause humaine** posée pendant l'attente de quota n'est **pas** levée par la
  reprise (seul le quota l'est) ;
* **réconciliation** : une PR déjà ouverte n'est pas relancée de zéro, et un
  worktree **sale** n'est jamais supprimé ;
* les **bornes** (``--max-legs``, patience, délai/silence) et l'analyse du flux.

Le faux claude est un petit script Python piloté par un fichier de scénario JSON,
invoqué exactement comme le vrai (``-p … --output-format stream-json --verbose``) ;
il ignore ces drapeaux et rejoue le scénario. Le faux ``gh`` répond en JSON selon
l'état demandé. Les commandes bouchonnées sont passées sous forme de **liste**
(``[python, script, …]``), ce qui évite tout souci de citation multiplateforme.

Les attentes (quota) utilisent une **horloge virtuelle** injectée : ``sleep``
avance le temps, si bien que les tests sont déterministes et instantanés.

Lancement : ``python .github/scripts/tests/test_run_supervise.py``.
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


# --- Faux claude : rejoue un scénario stream-json ----------------------------

FAKE_CLAUDE = r'''
import json, sys, time
scenario = json.loads(open(sys.argv[1], encoding="utf-8").read())
time.sleep(scenario.get("initial_delay", 0))
for ev in scenario.get("events", []):
    time.sleep(ev.get("delay", 0))
    sys.stdout.write(json.dumps(ev["line"]) + "\n")
    sys.stdout.flush()
err = scenario.get("stderr")
if err:
    sys.stderr.write(err)
    sys.stderr.flush()
sys.exit(scenario.get("exit", 0))
'''

# --- Faux gh : répond selon --state (open / merged) --------------------------

FAKE_GH = r'''
import json, sys
argv = sys.argv[1:]
scen = argv[0]
rest = argv[1:]
def opt(name):
    return rest[rest.index(name) + 1] if name in rest else None
data = json.loads(open(scen, encoding="utf-8").read())
if "pr" in rest and "list" in rest:
    sys.stdout.write(json.dumps(data.get(opt("--state"), [])))
elif "issue" in rest and "list" in rest:
    sys.stdout.write(json.dumps(data.get("closed_issues", [])))
else:
    sys.stdout.write("[]")
'''


class Clock:
    """Horloge virtuelle : ``sleep`` avance le temps (attentes déterministes)."""

    def __init__(self, start: float = 1_000_000.0):
        self.t = start
        self.slept: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += max(0.0, seconds)


class FakeClaudeTests(unittest.TestCase):
    """run_leg contre un faux claude rejouant des flux stream-json."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.fake = self.tmp / "fake_claude.py"
        self.fake.write_text(FAKE_CLAUDE, encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def leg(self, scenario: dict, **kw):
        scen = self.tmp / "scenario.json"
        scen.write_text(json.dumps(scenario), encoding="utf-8")
        cmd = [sys.executable, str(self.fake), str(scen)]
        return rs.run_leg('/run-jalon "J" --authorize --max-lots 1',
                          claude_cmd=cmd, **kw)

    def test_appel_sain(self):
        out = self.leg({"events": [
            {"line": {"type": "system", "subtype": "init"}},
            {"line": {"type": "assistant", "message": "travaille"}},
            {"line": {"type": "result", "subtype": "success"}},
        ], "exit": 0})
        self.assertEqual(out.kind, rs.LEG_OK)

    def test_refus_quota_avec_resetsAt(self):
        resets = int(time.time()) + 3600
        out = self.leg({"events": [
            {"line": {"type": "system", "subtype": "init"}},
            {"line": {"type": "rate_limit_event", "status": "rejected",
                      "resetsAt": resets}},
        ], "exit": 1})
        self.assertEqual(out.kind, rs.LEG_QUOTA)
        self.assertIsNotNone(out.resets_at)
        self.assertAlmostEqual(out.resets_at, resets, delta=2)

    def test_refus_quota_sans_resetsAt(self):
        out = self.leg({"events": [
            {"line": {"type": "rate_limit_event", "status": "rejected"}},
        ], "exit": 1})
        self.assertEqual(out.kind, rs.LEG_QUOTA)
        self.assertIsNone(out.resets_at)

    def test_fenetre_85pc_a_l_ouverture(self):
        # Fenêtre déjà consommée à 85 % dès l'ouverture → abandon (garde d'ouverture).
        resets = int(time.time()) + 7200
        out = self.leg({"events": [
            {"line": {"type": "rate_limit_event", "status": "allowed",
                      "usedPercent": 85, "resetsAt": resets}},
            {"line": {"type": "assistant", "message": "ne devrait pas aller plus loin"}},
        ], "exit": 0})
        self.assertEqual(out.kind, rs.LEG_OPENING_ABORT)
        self.assertAlmostEqual(out.resets_at, resets, delta=2)

    def test_fenetre_85pc_tardive_ne_declenche_pas_la_garde(self):
        # ≥ 80 % mais hors des premières minutes (fenêtre d'ouverture négative) :
        # la garde ne se déclenche pas ; l'appel se termine normalement.
        out = self.leg({"events": [
            {"line": {"type": "rate_limit_event", "status": "allowed", "usedPercent": 85}},
            {"line": {"type": "result", "subtype": "success"}},
        ], "exit": 0}, opening_window=-1)
        self.assertEqual(out.kind, rs.LEG_OK)

    def test_appel_muet_coupe(self):
        # Aucune ligne émise pendant plus que max_silence → coupure.
        out = self.leg({"initial_delay": 3, "events": [], "exit": 0},
                       max_silence=0.5)
        self.assertEqual(out.kind, rs.LEG_SILENT)

    def test_filet_texte_usage_limit(self):
        # Pas d'événement structuré, mais le texte trahit la limite (stderr).
        out = self.leg({"events": [
            {"line": {"type": "result", "subtype": "error_during_execution"}},
        ], "stderr": "Claude usage limit reached. Try again later.", "exit": 1})
        self.assertEqual(out.kind, rs.LEG_QUOTA)
        self.assertIsNone(out.resets_at)

    def test_erreur_non_quota(self):
        out = self.leg({"events": [
            {"line": {"type": "result", "subtype": "error"}},
        ], "stderr": "boom", "exit": 3})
        self.assertEqual(out.kind, rs.LEG_ERROR)
        self.assertEqual(out.returncode, 3)

    def test_claude_introuvable(self):
        out = rs.run_leg("/run-jalon", claude_cmd=["/n/existe/pas/claude"])
        self.assertEqual(out.kind, rs.LEG_ERROR)


class StreamParsingTests(unittest.TestCase):
    """Fonctions pures d'analyse du flux stream-json."""

    def test_extract_rate_limit_a_plat(self):
        rl = rs.extract_rate_limit({"type": "rate_limit_event", "status": "rejected"})
        self.assertEqual(rl["status"], "rejected")

    def test_extract_rate_limit_imbrique(self):
        rl = rs.extract_rate_limit({"type": "system", "rate_limit": {"status": "allowed"}})
        self.assertEqual(rl["status"], "allowed")

    def test_extract_rate_limit_absent(self):
        self.assertIsNone(rs.extract_rate_limit({"type": "assistant"}))
        self.assertIsNone(rs.extract_rate_limit("pas un dict"))

    def test_fraction_pourcentage(self):
        self.assertAlmostEqual(rs.rate_limit_usage_fraction({"usedPercent": 85}), 0.85)

    def test_fraction_used_limit(self):
        self.assertAlmostEqual(rs.rate_limit_usage_fraction({"used": 9, "limit": 10}), 0.9)

    def test_fraction_remaining(self):
        self.assertAlmostEqual(
            rs.rate_limit_usage_fraction({"remaining": 2, "limit": 10}), 0.8)

    def test_fraction_inconnue(self):
        self.assertIsNone(rs.rate_limit_usage_fraction({"foo": 1}))

    def test_resets_at_epoch(self):
        self.assertEqual(rs.parse_resets_at({"resetsAt": 1762300000}), 1762300000.0)

    def test_resets_at_iso(self):
        got = rs.parse_resets_at({"resets_at": "2030-01-01T00:00:00Z"})
        self.assertEqual(run_journal.iso_utc(got), "2030-01-01T00:00:00Z")

    def test_resets_at_absent(self):
        self.assertIsNone(rs.parse_resets_at({"status": "rejected"}))

    def test_texte_usage_limit(self):
        self.assertTrue(rs.text_signals_quota("Claude usage limit reached"))

    def test_texte_hit_your_limit(self):
        self.assertTrue(rs.text_signals_quota("You've hit your 5-hour limit"))

    def test_texte_429_en_contexte(self):
        self.assertTrue(rs.text_signals_quota("HTTP 429: rate limit exceeded"))

    def test_texte_429_hors_contexte_ignore(self):
        self.assertFalse(rs.text_signals_quota("429 fichiers analysés, tout va bien"))

    def test_texte_sain(self):
        self.assertFalse(rs.text_signals_quota("run terminé, 2 PR mergées"))


class QuotaHoldAndResumeTests(unittest.TestCase):
    """Retenue de quota + reprise, sur un vrai run (délègue à run_journal, issue #48).

    Vérifie surtout : une **pause humaine** posée pendant l'attente de quota n'est
    **pas** levée par la reprise automatique (seul le quota l'est)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.runs = Path(self._tmp.name) / "runs"
        self.rid = "20260101T000000Z-sup"
        os.environ["NM_RUNS_ROOT"] = str(self.runs)
        os.environ["NM_RUN_ID"] = self.rid
        run_journal.run_init("Jalon", "2")
        self.d = self.runs / self.rid
        self.clock = Clock()

    def tearDown(self):
        os.environ.pop("NM_RUNS_ROOT", None)
        os.environ.pop("NM_RUN_ID", None)
        self._tmp.cleanup()

    def make(self, **kw):
        opt = rs.SuperviseOptions(**kw)
        return rs.Supervisor("Jalon", opt, run_id=self.rid,
                             now=self.clock.now, sleep=self.clock.sleep,
                             gate_fn=lambda: run_journal.gate(self.rid, now=self.clock.now()),
                             progress_fn=lambda: 0, reconcile_fn=lambda: True)

    def test_hold_pose_une_echeance_avec_marge(self):
        sup = self.make(margin=120)
        resets = self.clock.now() + 3600
        until = sup._hold_quota(resets, "refus de quota")
        self.assertAlmostEqual(until, resets + 120, delta=2)
        control = run_journal.load_control(self.d)
        self.assertIn("quota", control["pause"])
        self.assertEqual(run_journal.gate(self.rid, now=self.clock.now())[0],
                         run_journal.GATE_QUOTA)

    def test_hold_sans_resetsAt_utilise_la_fenetre(self):
        sup = self.make(window=5 * 3600, margin=0)
        before = self.clock.now()
        until = sup._hold_quota(None, "sans resetsAt")
        self.assertGreaterEqual(until, before + 5 * 3600 - 2)

    def test_reprise_leve_le_quota(self):
        sup = self.make(margin=0)
        sup._hold_quota(self.clock.now() + 1800, "fenêtre à rouvrir")
        self.assertEqual(sup._wait_for_quota(), "resumed")
        self.assertTrue(self.clock.slept)                   # a bien attendu
        control = run_journal.load_control(self.d)
        self.assertNotIn("quota", control["pause"])
        self.assertEqual(run_journal.gate(self.rid, now=self.clock.now())[0],
                         run_journal.GATE_CONTINUE)

    def test_pause_humaine_pendant_attente_non_levee_par_reprise(self):
        sup = self.make(margin=0)
        # Pause humaine posée, puis retenue de quota : on attend, la reprise ne
        # lève QUE le quota — la pause humaine reste.
        run_journal.control_pause(by="alice", reason="revue manuelle", run_id=self.rid)
        sup._hold_quota(self.clock.now() + 600, "quota")
        self.assertEqual(sup._wait_for_quota(), "resumed")
        control = run_journal.load_control(self.d)
        self.assertNotIn("quota", control["pause"])   # quota levé par la reprise
        self.assertIn("human", control["pause"])       # pause humaine INTACTE
        self.assertEqual(run_journal.gate(self.rid, now=self.clock.now())[0],
                         run_journal.GATE_PAUSE)

    def test_pause_humaine_posee_PENDANT_l_attente_non_levee(self):
        # Variante fidèle à l'issue : la pause humaine arrive *pendant* l'attente
        # de quota (via un hook de sommeil). La reprise ne lève que le quota.
        sup = self.make(margin=0)
        sup._hold_quota(self.clock.now() + 120, "quota")  # retenue active → attente
        posed = {"done": False}
        advance = self.clock.sleep

        def sleep_then_pause(seconds):
            advance(seconds)
            if not posed["done"]:
                posed["done"] = True
                run_journal.control_pause(by="alice", reason="revue", run_id=self.rid)

        sup.sleep = sleep_then_pause
        self.assertEqual(sup._wait_for_quota(), "resumed")
        self.assertTrue(posed["done"])                  # la pause a bien été posée en vol
        control = run_journal.load_control(self.d)
        self.assertNotIn("quota", control["pause"])      # quota levé
        self.assertIn("human", control["pause"])          # pause humaine INTACTE
        self.assertEqual(run_journal.gate(self.rid, now=self.clock.now())[0],
                         run_journal.GATE_PAUSE)

    def test_wait_interrompu_par_arret(self):
        sup = self.make()
        run_journal.control_quota_hold(run_journal.iso_utc(self.clock.now() + 3600),
                                       by="superviseur", run_id=self.rid)
        run_journal.control_stop(by="bob", reason="fin de journée", run_id=self.rid)
        self.assertEqual(sup._wait_for_quota(), rs.RUN_STOPPED)
        # L'arrêt pendant l'attente ne lève pas le quota (on n'enchaîne pas).
        control = run_journal.load_control(self.d)
        self.assertIn("quota", control["pause"])


class SupervisorLoopTests(unittest.TestCase):
    """Boucle principale avec gate / leg_runner / progress injectés (déterministe)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.runs = Path(self._tmp.name) / "runs"
        self.rid = "20260101T000000Z-loop"
        os.environ["NM_RUNS_ROOT"] = str(self.runs)
        os.environ["NM_RUN_ID"] = self.rid
        run_journal.run_init("Jalon", "2")
        self.d = self.runs / self.rid
        self.clock = Clock()

    def tearDown(self):
        os.environ.pop("NM_RUNS_ROOT", None)
        os.environ.pop("NM_RUN_ID", None)
        self._tmp.cleanup()

    def build(self, *, gate_seq=None, legs=None, progress=None, **opt_kw):
        gates = list(gate_seq or [(run_journal.GATE_CONTINUE, "go")])
        leg_outcomes = list(legs or [rs.LegOutcome(rs.LEG_OK)])

        def gate_fn():
            return gates.pop(0) if gates else (run_journal.GATE_IDLE, "fini")

        def leg_runner():
            return leg_outcomes.pop(0) if leg_outcomes else rs.LegOutcome(rs.LEG_OK)

        prog = {"v": 0}
        progress = progress or []

        def progress_fn():
            return progress.pop(0) if progress else prog["v"]

        opt = rs.SuperviseOptions(**opt_kw)
        # Réconciliation neutralisée : les tests de boucle ne doivent jamais
        # appeler un vrai `gh`/`git` (déterminisme, aucun réseau).
        return rs.Supervisor("Jalon", opt, run_id=self.rid,
                             now=self.clock.now, sleep=self.clock.sleep,
                             leg_runner=leg_runner, gate_fn=gate_fn,
                             progress_fn=progress_fn, reconcile_fn=lambda: True)

    def test_gate_idle_termine_aussitot(self):
        sup = self.build(gate_seq=[(run_journal.GATE_IDLE, "rien")])
        self.assertEqual(sup.run(), rs.RUN_DONE)
        self.assertEqual(sup.legs, 0)

    def test_gate_stop_termine(self):
        sup = self.build(gate_seq=[(run_journal.GATE_STOP, "arrêt")])
        self.assertEqual(sup.run(), rs.RUN_STOPPED)

    def test_un_lot_par_appel_puis_idle(self):
        sup = self.build(gate_seq=[(run_journal.GATE_CONTINUE, "go"),
                                   (run_journal.GATE_IDLE, "fini")],
                         legs=[rs.LegOutcome(rs.LEG_OK)])
        self.assertEqual(sup.run(), rs.RUN_DONE)
        self.assertEqual(sup.legs, 1)

    def test_max_legs_borne(self):
        sup = self.build(gate_seq=[(run_journal.GATE_CONTINUE, "go")] * 5,
                         legs=[rs.LegOutcome(rs.LEG_OK)] * 5, max_legs=2)
        self.assertEqual(sup.run(), rs.RUN_MAX_LEGS)
        self.assertEqual(sup.legs, 2)

    def test_patience_epuisee(self):
        # Aucun progrès (progress constant) sur 2 appels → patience 2 déclenche.
        sup = self.build(gate_seq=[(run_journal.GATE_CONTINUE, "go")] * 5,
                         legs=[rs.LegOutcome(rs.LEG_OK)] * 5, patience=2)
        self.assertEqual(sup.run(), rs.RUN_PATIENCE)
        self.assertEqual(sup.legs, 2)

    def test_patience_remise_a_zero_par_un_merge(self):
        # Progrès à chaque appel → la patience ne se déclenche jamais ; max_legs borne.
        sup = self.build(gate_seq=[(run_journal.GATE_CONTINUE, "go")] * 5,
                         legs=[rs.LegOutcome(rs.LEG_OK)] * 5,
                         progress=[1, 2, 3], patience=2, max_legs=3)
        self.assertEqual(sup.run(), rs.RUN_MAX_LEGS)

    def test_reconciliation_incoherente_arrete(self):
        # État incohérent (réconciliation KO) → fail-safe : on s'arrête sans lancer.
        sup = self.build(gate_seq=[(run_journal.GATE_CONTINUE, "go")],
                         legs=[rs.LegOutcome(rs.LEG_OK)], max_legs=5)
        sup._reconcile_fn = lambda: False
        self.assertEqual(sup.run(), rs.RUN_INCOHERENT)
        self.assertEqual(sup.legs, 0)

    def test_quota_dans_la_boucle_pose_hold_attend_et_reprend(self):
        # 1er appel : refus de quota ; le superviseur pose la retenue, attend
        # (horloge virtuelle), lève, puis relance ; 2e appel sain ; puis idle.
        quota = rs.LegOutcome(rs.LEG_QUOTA, resets_at=self.clock.now() + 600)
        sup = self.build(
            gate_seq=[(run_journal.GATE_CONTINUE, "go"),
                      (run_journal.GATE_CONTINUE, "go"),
                      (run_journal.GATE_IDLE, "fini")],
            legs=[quota, rs.LegOutcome(rs.LEG_OK)], margin=0, max_legs=5)
        self.assertEqual(sup.run(), rs.RUN_DONE)
        self.assertEqual(sup.legs, 2)
        self.assertTrue(self.clock.slept)                   # a bien attendu la reprise
        control = run_journal.load_control(self.d)
        self.assertNotIn("quota", control.get("pause", {}))  # quota levé au final

    def test_battement_et_journal_superviseur(self):
        # Observabilité : battement supervisor.alive (horodaté) + journal du superviseur.
        sup = self.build(gate_seq=[(run_journal.GATE_CONTINUE, "go"),
                                   (run_journal.GATE_IDLE, "fini")],
                         legs=[rs.LegOutcome(rs.LEG_OK)])
        sup.run()
        alive = json.loads((self.d / "supervisor.alive").read_text(encoding="utf-8"))
        self.assertEqual(alive["state"], "stopped")
        self.assertIn("ts", alive)
        self.assertTrue((self.d / "supervisor.log").read_text(encoding="utf-8").strip())
        # Les transitions marquantes rejoignent aussi le journal de run (ticket 0).
        journal = (self.d / "journal.ndjson").read_text(encoding="utf-8")
        self.assertIn('"agent":"superviseur"', journal)

    def test_opening_abort_traite_comme_quota(self):
        abort = rs.LegOutcome(rs.LEG_OPENING_ABORT, resets_at=self.clock.now() + 600)
        sup = self.build(
            gate_seq=[(run_journal.GATE_CONTINUE, "go"),
                      (run_journal.GATE_IDLE, "fini")],
            legs=[abort], margin=0, max_legs=5)
        self.assertEqual(sup.run(), rs.RUN_DONE)
        self.assertEqual(sup.legs, 1)
        control = run_journal.load_control(self.d)
        self.assertNotIn("quota", control.get("pause", {}))


class ReconcileTests(unittest.TestCase):
    """Réconciliation sur un dépôt temporaire + faux gh. Le dépôt fait foi."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        (self.repo / "README.md").write_text("x\n", encoding="utf-8")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "init")
        # Worktree sur une branche de ticket, rendu SALE (fichier non suivi).
        self.wt = self.tmp / "wt-49"
        self._git("worktree", "add", "-q", "-b", "feat/49-x", str(self.wt))
        (self.wt / "dirty.txt").write_text("travail non commité\n", encoding="utf-8")
        # Faux gh : PR mergée #99 (ticket 49) et PR ouverte #100 (ticket 50).
        self.gh = self.tmp / "fake_gh.py"
        self.gh.write_text(FAKE_GH, encoding="utf-8")
        self.scen = self.tmp / "gh.json"
        self.scen.write_text(json.dumps({
            "open": [{"number": 100, "headRefName": "infra/50-y", "body": "Closes #50"}],
            "merged": [{"number": 99, "headRefName": "feat/49-x", "body": "Closes #49"}],
            "closed_issues": [{"number": 49}],
        }), encoding="utf-8")
        self.gh_cmd = [sys.executable, str(self.gh), str(self.scen)]

    def tearDown(self):
        self._tmp.cleanup()

    def _git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args],
                              capture_output=True, text=True, check=True)

    def recon(self):
        return rs.reconcile("Jalon", gh_cmd=self.gh_cmd, git_cmd="git",
                            repo=str(self.repo))

    def test_pr_ouverte_ticket_non_relance(self):
        recon = self.recon()
        self.assertIn(50, recon.tickets_in_progress())   # PR ouverte → pas de relance
        self.assertEqual(recon.merged_tickets(), {49})

    def test_worktree_sale_jamais_prunable(self):
        recon = self.recon()
        dirty = [wt for wt in recon.worktrees if wt.branch == "feat/49-x"]
        self.assertEqual(len(dirty), 1)
        self.assertTrue(dirty[0].dirty)
        # Même si le ticket 49 est mergé, le worktree SALE n'est pas prunable.
        self.assertNotIn(dirty[0], recon.prunable_worktrees())

    def test_prune_ne_supprime_pas_un_worktree_sale(self):
        recon = self.recon()
        removed = rs.prune_worktrees(recon, git_cmd="git", repo=str(self.repo))
        self.assertEqual(removed, [])               # rien à purger (sale)
        self.assertTrue(self.wt.exists())           # worktree conservé

    def test_worktree_propre_merge_est_prunable(self):
        # On nettoie le worktree (plus de fichier sale) : il devient prunable.
        (self.wt / "dirty.txt").unlink()
        recon = self.recon()
        prunable = recon.prunable_worktrees()
        self.assertEqual([wt.branch for wt in prunable], ["feat/49-x"])

    def test_git_injoignable_leve_reconcile_error(self):
        with self.assertRaises(rs.ReconcileError):
            rs.list_worktrees(git_cmd="git", repo=str(self.tmp / "pas-un-depot"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
