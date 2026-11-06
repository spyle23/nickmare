//! Mode `--dry-run` (issue #26, cf. `docs/ARCHITECTURE.md` §11.1).
//!
//! Affiche **exactement ce qui serait émis** (cibles, actions, volumétrie)
//! **sans rien envoyer**. Recommandé avant tout run offensif : l'opérateur voit
//! la liste des actions prévues, aucune n'atteint le réseau.
//!
//! Le mécanisme sépare la **décision d'émettre** de l'**émission** elle-même :
//! un [`Dispatcher`] reçoit des [`Action`](crate::gate::Action)s et, selon le
//! [`DispatchMode`], soit les **consigne** dans un [`DryRunPlan`] (dry-run, zéro
//! I/O), soit les transmet à un [`ActionEmitter`] réel (live). Un mock d'émetteur
//! prouve en test qu'en dry-run **aucune** émission n'a lieu.

use crate::gate::Action;

/// Mode de dispatch des actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchMode {
    /// Simulation : les actions sont consignées, jamais émises.
    DryRun,
    /// Exécution réelle : les actions sont transmises à l'émetteur.
    Live,
}

impl DispatchMode {
    /// Vrai en mode simulation (aucune émission).
    #[must_use]
    pub fn is_dry_run(self) -> bool {
        matches!(self, DispatchMode::DryRun)
    }
}

/// Action qui **aurait** été émise, telle qu'affichée en dry-run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    /// Verbe métier de l'action (cf. [`Action::verb`]).
    pub verb: String,
    /// Cible visée.
    pub target: String,
    /// Détail optionnel (ports, technique…).
    pub detail: Option<String>,
}

/// Plan de dry-run : la liste ordonnée des actions qui auraient été émises.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DryRunPlan {
    actions: Vec<PlannedAction>,
}

impl DryRunPlan {
    /// Plan vide.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consigne une action prévue (sans jamais l'émettre).
    pub fn record(&mut self, action: &Action, detail: Option<String>) {
        self.actions.push(PlannedAction {
            verb: action.verb(),
            target: action.target().to_string(),
            detail,
        });
    }

    /// Actions prévues, dans l'ordre.
    #[must_use]
    pub fn actions(&self) -> &[PlannedAction] {
        &self.actions
    }

    /// Nombre d'actions prévues.
    #[must_use]
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Vrai si aucune action n'est prévue.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Rendu lisible du plan : une ligne d'en-tête rappelant que rien n'est émis,
    /// puis une ligne par action prévue.
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines = Vec::with_capacity(self.actions.len() + 1);
        lines.push(format!(
            "Dry-run — {} action(s) simulée(s), rien n'est émis :",
            self.actions.len()
        ));
        for action in &self.actions {
            let detail = match &action.detail {
                Some(detail) => format!(" ({detail})"),
                None => String::new(),
            };
            lines.push(format!("  {} → {}{detail}", action.verb, action.target));
        }
        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

/// Émetteur réel d'actions. L'implémentation live atteint le réseau/moteur ;
/// un mock de test ne fait que compter. Infaillible ici : la gestion d'erreur
/// réseau vit dans les couches qui l'implémentent.
pub trait ActionEmitter {
    /// Émet réellement une action.
    fn emit(&mut self, action: &Action);
}

/// Aiguilleur d'actions : consigne (dry-run) ou émet (live), selon le mode.
#[derive(Debug)]
pub struct Dispatcher<E: ActionEmitter> {
    mode: DispatchMode,
    emitter: E,
    plan: DryRunPlan,
}

impl<E: ActionEmitter> Dispatcher<E> {
    /// Aiguilleur dans le mode donné, au-dessus de l'émetteur fourni.
    pub fn new(mode: DispatchMode, emitter: E) -> Self {
        Self {
            mode,
            emitter,
            plan: DryRunPlan::new(),
        }
    }

    /// Traite une action : en dry-run elle est **consignée** (rien émis, renvoie
    /// `false`) ; en live elle est **émise** (renvoie `true`).
    pub fn dispatch(&mut self, action: &Action, detail: Option<String>) -> bool {
        match self.mode {
            DispatchMode::DryRun => {
                self.plan.record(action, detail);
                false
            }
            DispatchMode::Live => {
                self.emitter.emit(action);
                true
            }
        }
    }

    /// Plan accumulé (vide en mode live).
    #[must_use]
    pub fn plan(&self) -> &DryRunPlan {
        &self.plan
    }

    /// Récupère l'émetteur sous-jacent (pour inspection en test).
    pub fn into_emitter(self) -> E {
        self.emitter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ExploitMode;
    use std::net::IpAddr;

    /// Émetteur mock : il ne touche à rien, il compte les émissions réelles.
    #[derive(Default)]
    struct CountingEmitter {
        emitted: Vec<String>,
    }

    impl ActionEmitter for CountingEmitter {
        fn emit(&mut self, action: &Action) {
            self.emitted.push(action.verb());
        }
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn recon(target: &str) -> Action {
        Action::Recon { target: ip(target) }
    }

    fn actions() -> Vec<Action> {
        vec![
            recon("192.168.10.25"),
            Action::Exploit {
                target: ip("192.168.10.25"),
                mode: ExploitMode::Validate,
            },
            Action::Emulate {
                target: ip("192.168.10.25"),
                technique: "T1021".to_string(),
            },
        ]
    }

    #[test]
    fn dry_run_consigne_tout_sans_rien_emettre() {
        let mut dispatcher = Dispatcher::new(DispatchMode::DryRun, CountingEmitter::default());
        for action in actions() {
            let emitted = dispatcher.dispatch(&action, None);
            assert!(!emitted, "le dry-run ne doit jamais émettre");
        }
        assert_eq!(dispatcher.plan().len(), 3);
        // Preuve forte : l'émetteur réel n'a rien reçu.
        let emitter = dispatcher.into_emitter();
        assert!(emitter.emitted.is_empty());
    }

    #[test]
    fn live_emet_chaque_action() {
        let mut dispatcher = Dispatcher::new(DispatchMode::Live, CountingEmitter::default());
        for action in actions() {
            assert!(dispatcher.dispatch(&action, None));
        }
        // En live, rien n'est consigné et tout est émis.
        assert!(dispatcher.plan().is_empty());
        let emitter = dispatcher.into_emitter();
        assert_eq!(emitter.emitted.len(), 3);
        assert_eq!(emitter.emitted[0], "recon.active");
    }

    #[test]
    fn le_plan_s_affiche_avec_le_detail() {
        let mut plan = DryRunPlan::new();
        let detail = Some("ports 22,80".to_string());
        plan.record(&recon("192.168.10.25"), detail);
        let out = plan.render();
        assert!(out.contains("rien n'est émis"));
        assert!(out.contains("recon.active → 192.168.10.25 (ports 22,80)"));
    }

    #[test]
    fn plan_vide_est_vide() {
        let plan = DryRunPlan::new();
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
    }
}
