//! Circuit-breaker par cible (issue #26, cf. `docs/ARCHITECTURE.md` §11.1).
//!
//! Au-delà d'un **seuil d'anomalies** sur une cible (un service qui cesse de
//! répondre après nos requêtes, par exemple), les actions actives sur cette
//! cible sont **suspendues** et l'opérateur **alerté**, plutôt que de poursuivre
//! à l'aveugle et de risquer de casser la cible (*primum non nocere*, §1).
//!
//! Trois phases par cible, inspirées du disjoncteur classique :
//!
//! - **Closed** — tout va bien, les actions passent ; les anomalies sont
//!   comptées et remises à zéro par un succès.
//! - **Open** — seuil atteint : les actions sont **suspendues** ; une alerte
//!   opérateur est émise (journalisable via [`crate::audit`]).
//! - **HalfOpen** — après un délai de refroidissement, une **sonde** unique est
//!   autorisée : si elle réussit on referme (Closed), si elle échoue on rouvre.
//!
//! Le disjoncteur est **déterministe vis-à-vis de l'instant fourni** : il ne lit
//! aucune horloge, un test contrôle entièrement le temps.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};

use crate::audit::{AuditRecord, CapabilityLevel};

/// Phase du disjoncteur pour une cible donnée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Fonctionnement nominal : les actions passent.
    Closed,
    /// Seuil d'anomalies franchi : actions suspendues.
    Open,
    /// Fenêtre de sonde après refroidissement : une action d'essai est permise.
    HalfOpen,
}

/// Verdict du disjoncteur pour une action sur une cible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerDecision {
    /// L'action peut être tentée (phase `Closed` ou sonde `HalfOpen`).
    Proceed,
    /// L'action est suspendue : la cible est jugée instable.
    Suspended,
}

impl BreakerDecision {
    /// Vrai si l'action est autorisée à être tentée.
    #[must_use]
    pub fn is_proceed(self) -> bool {
        matches!(self, BreakerDecision::Proceed)
    }
}

/// Alerte opérateur émise quand une cible passe en suspension (phase `Open`).
///
/// Jamais silencieuse : destinée à être **journalisée** (via [`Self::audit_record`])
/// et remontée à l'opérateur. `reopened` distingue une première ouverture d'une
/// ré-ouverture après l'échec d'une sonde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub target: IpAddr,
    pub anomalies: u32,
    pub reopened: bool,
}

impl Alert {
    /// Message lisible pour l'opérateur.
    #[must_use]
    pub fn message(&self) -> String {
        let cause = if self.reopened {
            "ré-ouverture après échec de la sonde"
        } else {
            "seuil d'anomalies franchi"
        };
        let target = self.target;
        let n = self.anomalies;
        format!("circuit-breaker : cible {target} suspendue ({cause}, {n} anomalie(s))")
    }

    /// Entrée d'audit pour l'alerte : action `safety.circuit_open`, résultat
    /// `suspended`. Rien n'échappe au journal (§11.3).
    #[must_use]
    pub fn audit_record(&self, operator: &str, level: CapabilityLevel) -> AuditRecord {
        AuditRecord::new(
            operator,
            self.target.to_string(),
            "safety.circuit_open",
            "suspended",
            level,
        )
    }
}

/// État interne d'une cible.
#[derive(Debug, Clone)]
struct TargetState {
    anomalies: u32,
    phase: Phase,
    opened_at: Option<DateTime<Utc>>,
}

impl Default for TargetState {
    fn default() -> Self {
        Self {
            anomalies: 0,
            phase: Phase::Closed,
            opened_at: None,
        }
    }
}

/// Disjoncteur multi-cibles. Chaque cible a son propre compteur et sa propre
/// phase : suspendre une cible instable n'affecte pas les autres.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    threshold: u32,
    cooldown: TimeDelta,
    targets: HashMap<IpAddr, TargetState>,
}

impl CircuitBreaker {
    /// Disjoncteur ouvrant après `threshold` anomalies, avec un refroidissement
    /// `cooldown` avant d'autoriser une sonde. Le seuil est ramené à au moins 1.
    #[must_use]
    pub fn new(threshold: u32, cooldown: TimeDelta) -> Self {
        Self {
            threshold: threshold.max(1),
            cooldown,
            targets: HashMap::new(),
        }
    }

    /// Phase courante d'une cible (jamais vue → `Closed`).
    #[must_use]
    pub fn phase(&self, target: IpAddr) -> Phase {
        match self.targets.get(&target) {
            Some(state) => state.phase,
            None => Phase::Closed,
        }
    }

    /// Décide si une action sur `target` peut être tentée à l'instant `now`.
    ///
    /// Gère la transition `Open → HalfOpen` une fois le refroidissement écoulé :
    /// une sonde unique est alors autorisée pour tester si la cible s'est
    /// rétablie.
    pub fn allow(&mut self, target: IpAddr, now: DateTime<Utc>) -> BreakerDecision {
        let state = self.targets.entry(target).or_default();
        match state.phase {
            Phase::Closed | Phase::HalfOpen => BreakerDecision::Proceed,
            Phase::Open => {
                let ready = state.opened_at.is_some_and(|at| now - at >= self.cooldown);
                if ready {
                    state.phase = Phase::HalfOpen;
                    BreakerDecision::Proceed
                } else {
                    BreakerDecision::Suspended
                }
            }
        }
    }

    /// Enregistre une anomalie observée sur `target`. Renvoie une [`Alert`] si
    /// cette anomalie fait **basculer** la cible en suspension (ouverture ou
    /// ré-ouverture), sinon `None`.
    pub fn record_anomaly(&mut self, target: IpAddr, now: DateTime<Utc>) -> Option<Alert> {
        let threshold = self.threshold;
        let state = self.targets.entry(target).or_default();
        match state.phase {
            Phase::HalfOpen => {
                // La sonde a échoué : on rouvre immédiatement.
                state.phase = Phase::Open;
                state.opened_at = Some(now);
                Some(Alert {
                    target,
                    anomalies: state.anomalies,
                    reopened: true,
                })
            }
            Phase::Open => {
                // Déjà suspendue : on continue de compter, sans réalerter.
                state.anomalies = state.anomalies.saturating_add(1);
                None
            }
            Phase::Closed => {
                state.anomalies = state.anomalies.saturating_add(1);
                if state.anomalies >= threshold {
                    state.phase = Phase::Open;
                    state.opened_at = Some(now);
                    Some(Alert {
                        target,
                        anomalies: state.anomalies,
                        reopened: false,
                    })
                } else {
                    None
                }
            }
        }
    }

    /// Enregistre une interaction **réussie** sur `target` : referme un circuit
    /// en sonde (`HalfOpen → Closed`) et remet le compteur d'anomalies à zéro.
    pub fn record_success(&mut self, target: IpAddr) {
        let state = self.targets.entry(target).or_default();
        match state.phase {
            Phase::HalfOpen => {
                state.phase = Phase::Closed;
                state.anomalies = 0;
                state.opened_at = None;
            }
            Phase::Closed => {
                state.anomalies = 0;
            }
            Phase::Open => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn sous_le_seuil_tout_passe_sans_alerte() {
        let mut cb = CircuitBreaker::new(3, TimeDelta::seconds(30));
        let target = ip("192.168.10.25");
        assert_eq!(cb.allow(target, t0()), BreakerDecision::Proceed);
        assert!(cb.record_anomaly(target, t0()).is_none());
        assert!(cb.record_anomaly(target, t0()).is_none());
        assert_eq!(cb.phase(target), Phase::Closed);
        assert_eq!(cb.allow(target, t0()), BreakerDecision::Proceed);
    }

    #[test]
    fn seuil_atteint_ouvre_et_alerte_et_suspend() {
        let mut cb = CircuitBreaker::new(3, TimeDelta::seconds(30));
        let target = ip("192.168.10.25");
        cb.record_anomaly(target, t0());
        cb.record_anomaly(target, t0());
        let maybe = cb.record_anomaly(target, t0());
        let alert = maybe.expect("3e anomalie alerte");
        assert_eq!(alert.target, target);
        assert!(!alert.reopened);
        assert_eq!(cb.phase(target), Phase::Open);
        // Les actions sont désormais suspendues sur cette cible.
        assert_eq!(cb.allow(target, t0()), BreakerDecision::Suspended);
    }

    #[test]
    fn refroidissement_autorise_une_sonde_puis_succes_referme() {
        let mut cb = CircuitBreaker::new(2, TimeDelta::seconds(30));
        let target = ip("192.168.10.25");
        cb.record_anomaly(target, t0());
        cb.record_anomaly(target, t0());
        assert_eq!(cb.phase(target), Phase::Open);

        // Avant la fin du refroidissement : toujours suspendue.
        let presque = t0() + TimeDelta::seconds(29);
        assert_eq!(cb.allow(target, presque), BreakerDecision::Suspended);

        // Après le refroidissement : une sonde est autorisée (HalfOpen).
        let apres = t0() + TimeDelta::seconds(31);
        assert_eq!(cb.allow(target, apres), BreakerDecision::Proceed);
        assert_eq!(cb.phase(target), Phase::HalfOpen);

        // La sonde réussit : le circuit se referme et le compteur repart à zéro.
        cb.record_success(target);
        assert_eq!(cb.phase(target), Phase::Closed);
        assert_eq!(cb.allow(target, apres), BreakerDecision::Proceed);
    }

    #[test]
    fn sonde_qui_echoue_rouvre_avec_alerte() {
        let mut cb = CircuitBreaker::new(2, TimeDelta::seconds(30));
        let target = ip("192.168.10.25");
        cb.record_anomaly(target, t0());
        cb.record_anomaly(target, t0());
        let apres = t0() + TimeDelta::seconds(31);
        assert_eq!(cb.allow(target, apres), BreakerDecision::Proceed);

        // La sonde échoue → ré-ouverture + nouvelle alerte.
        let maybe = cb.record_anomaly(target, apres);
        let alert = maybe.expect("échec de sonde alerte");
        assert!(alert.reopened);
        assert_eq!(cb.phase(target), Phase::Open);
        assert_eq!(cb.allow(target, apres), BreakerDecision::Suspended);
    }

    #[test]
    fn un_succes_remet_le_compteur_a_zero() {
        let mut cb = CircuitBreaker::new(3, TimeDelta::seconds(30));
        let target = ip("192.168.10.25");
        cb.record_anomaly(target, t0());
        cb.record_anomaly(target, t0());
        // Un succès efface les anomalies accumulées : il faut tout recompter.
        cb.record_success(target);
        assert!(cb.record_anomaly(target, t0()).is_none());
        assert!(cb.record_anomaly(target, t0()).is_none());
        assert_eq!(cb.phase(target), Phase::Closed);
    }

    #[test]
    fn suspension_isolee_par_cible() {
        // Suspendre une cible instable n'affecte pas une autre cible saine.
        let mut cb = CircuitBreaker::new(2, TimeDelta::seconds(30));
        let instable = ip("192.168.10.25");
        let saine = ip("192.168.10.26");
        cb.record_anomaly(instable, t0());
        cb.record_anomaly(instable, t0());
        assert_eq!(cb.allow(instable, t0()), BreakerDecision::Suspended);
        assert_eq!(cb.allow(saine, t0()), BreakerDecision::Proceed);
    }

    #[test]
    fn alerte_produit_une_entree_audit_suspended() {
        let mut cb = CircuitBreaker::new(1, TimeDelta::seconds(30));
        let target = ip("192.168.10.25");
        let alert = cb.record_anomaly(target, t0()).expect("seuil 1 alerte");
        let record = alert.audit_record("op", CapabilityLevel::Recon);
        assert_eq!(record.action, "safety.circuit_open");
        assert_eq!(record.result, "suspended");
        assert_eq!(record.target, "192.168.10.25");
        assert!(alert.message().contains("suspendue"));
    }
}
