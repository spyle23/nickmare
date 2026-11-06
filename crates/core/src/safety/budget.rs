//! Budgets globaux par engagement (issue #26, cf. `docs/ARCHITECTURE.md` §11.2).
//!
//! Plafond de **durée** et de **volume** (nombre d'actions, octets émis) par
//! engagement : au-delà, l'orchestrateur **s'arrête proprement** plutôt que de
//! laisser un run s'emballer. C'est un garde-fou de dernier recours, distinct du
//! débit instantané (`max_rate_pps`, [`crate::rate`]) et des plafonds du gate.
//!
//! La consommation est tenue dans un [`BudgetLedger`] alimenté au fil de l'eau ;
//! l'évaluation est **déterministe vis-à-vis de l'instant fourni** (aucune
//! horloge lue), donc testable sans attente.

use std::fmt;

use chrono::{DateTime, TimeDelta, Utc};

/// Plafonds d'un engagement. Chaque dimension est optionnelle : `None` = pas de
/// limite sur cette dimension.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Budget {
    max_duration: Option<TimeDelta>,
    max_actions: Option<u64>,
    max_bytes: Option<u64>,
}

impl Budget {
    /// Budget sans aucune limite (toutes dimensions ouvertes).
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Fixe la durée maximale de l'engagement.
    #[must_use]
    pub fn with_max_duration(mut self, max: TimeDelta) -> Self {
        self.max_duration = Some(max);
        self
    }

    /// Fixe le nombre maximal d'actions.
    #[must_use]
    pub fn with_max_actions(mut self, max: u64) -> Self {
        self.max_actions = Some(max);
        self
    }

    /// Fixe le volume maximal émis, en octets.
    #[must_use]
    pub fn with_max_bytes(mut self, max: u64) -> Self {
        self.max_bytes = Some(max);
        self
    }

    /// Évalue l'état du budget à l'instant `now`, au vu de la consommation
    /// `ledger`. Renvoie la **première** dimension épuisée (durée, puis actions,
    /// puis volume), ou [`BudgetStatus::Within`].
    #[must_use]
    pub fn status(&self, ledger: &BudgetLedger, now: DateTime<Utc>) -> BudgetStatus {
        if let Some(max) = self.max_duration {
            if now - ledger.started_at >= max {
                return BudgetStatus::Exhausted(BudgetReason::Duration);
            }
        }
        if let Some(max) = self.max_actions {
            if ledger.actions >= max {
                return BudgetStatus::Exhausted(BudgetReason::Actions);
            }
        }
        if let Some(max) = self.max_bytes {
            if ledger.bytes >= max {
                return BudgetStatus::Exhausted(BudgetReason::Volume);
            }
        }
        BudgetStatus::Within
    }

    /// Raccourci : vrai si le budget est épuisé à l'instant `now`.
    #[must_use]
    pub fn is_exhausted(&self, ledger: &BudgetLedger, now: DateTime<Utc>) -> bool {
        matches!(self.status(ledger, now), BudgetStatus::Exhausted(_))
    }
}

/// Consommation cumulée d'un engagement, alimentée au fil de l'eau.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetLedger {
    started_at: DateTime<Utc>,
    actions: u64,
    bytes: u64,
}

impl BudgetLedger {
    /// Registre neuf démarrant à l'instant `started_at`.
    #[must_use]
    pub fn start(started_at: DateTime<Utc>) -> Self {
        Self {
            started_at,
            actions: 0,
            bytes: 0,
        }
    }

    /// Reconstruit un registre depuis un état persistant (reprise, §11.2).
    #[must_use]
    pub fn restore(started_at: DateTime<Utc>, actions: u64, bytes: u64) -> Self {
        Self {
            started_at,
            actions,
            bytes,
        }
    }

    /// Enregistre `actions` actions et `bytes` octets émis supplémentaires.
    pub fn record(&mut self, actions: u64, bytes: u64) {
        self.actions = self.actions.saturating_add(actions);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    /// Instant de démarrage.
    #[must_use]
    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Nombre d'actions consommées.
    #[must_use]
    pub fn actions(&self) -> u64 {
        self.actions
    }

    /// Volume émis, en octets.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Dimension du budget qui a été épuisée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetReason {
    /// Durée maximale atteinte.
    Duration,
    /// Nombre d'actions maximal atteint.
    Actions,
    /// Volume maximal atteint.
    Volume,
}

impl fmt::Display for BudgetReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BudgetReason::Duration => write!(f, "durée maximale de l'engagement atteinte"),
            BudgetReason::Actions => write!(f, "nombre d'actions maximal atteint"),
            BudgetReason::Volume => write!(f, "volume maximal émis atteint"),
        }
    }
}

/// État d'un budget à un instant donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetStatus {
    /// Dans les limites : le run peut continuer.
    Within,
    /// Épuisé : l'orchestrateur doit s'arrêter proprement.
    Exhausted(BudgetReason),
}

impl BudgetStatus {
    /// Vrai si le run peut continuer.
    #[must_use]
    pub fn is_within(self) -> bool {
        matches!(self, BudgetStatus::Within)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn budget_illimite_toujours_dans_les_limites() {
        let budget = Budget::unlimited();
        let mut ledger = BudgetLedger::start(t0());
        ledger.record(1_000_000, 1_000_000_000);
        let tard = t0() + TimeDelta::days(365);
        assert_eq!(budget.status(&ledger, tard), BudgetStatus::Within);
    }

    #[test]
    fn duree_depassee_arrete_proprement() {
        let budget = Budget::unlimited().with_max_duration(TimeDelta::hours(2));
        let ledger = BudgetLedger::start(t0());
        let une_heure = budget.status(&ledger, t0() + TimeDelta::hours(1));
        assert!(une_heure.is_within());
        assert_eq!(
            budget.status(&ledger, t0() + TimeDelta::hours(2)),
            BudgetStatus::Exhausted(BudgetReason::Duration)
        );
    }

    #[test]
    fn plafond_d_actions_arrete_proprement() {
        let budget = Budget::unlimited().with_max_actions(10);
        let mut ledger = BudgetLedger::start(t0());
        ledger.record(9, 0);
        assert!(budget.status(&ledger, t0()).is_within());
        ledger.record(1, 0);
        assert_eq!(
            budget.status(&ledger, t0()),
            BudgetStatus::Exhausted(BudgetReason::Actions)
        );
    }

    #[test]
    fn plafond_de_volume_arrete_proprement() {
        let budget = Budget::unlimited().with_max_bytes(1024);
        let mut ledger = BudgetLedger::start(t0());
        ledger.record(0, 1023);
        assert!(budget.status(&ledger, t0()).is_within());
        ledger.record(0, 1);
        assert!(budget.is_exhausted(&ledger, t0()));
    }

    #[test]
    fn la_duree_prime_sur_les_autres_dimensions() {
        // Toutes les limites dépassées : la durée est signalée en premier.
        let budget = Budget::unlimited()
            .with_max_duration(TimeDelta::hours(1))
            .with_max_actions(1)
            .with_max_bytes(1);
        let mut ledger = BudgetLedger::start(t0());
        ledger.record(100, 100);
        assert_eq!(
            budget.status(&ledger, t0() + TimeDelta::hours(2)),
            BudgetStatus::Exhausted(BudgetReason::Duration)
        );
    }

    #[test]
    fn registre_se_restaure_pour_la_reprise() {
        // Après une coupure, la consommation déjà faite est reprise telle quelle.
        let budget = Budget::unlimited().with_max_actions(10);
        let ledger = BudgetLedger::restore(t0(), 10, 0);
        assert_eq!(
            budget.status(&ledger, t0()),
            BudgetStatus::Exhausted(BudgetReason::Actions)
        );
        assert_eq!(ledger.actions(), 10);
    }
}
