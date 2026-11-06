//! Back-off adaptatif (issue #26, cf. `docs/ARCHITECTURE.md` §11.1).
//!
//! *Primum non nocere* : si la cible montre des signes de stress (latence qui
//! grimpe, RST en rafale, timeouts), le débit **diminue automatiquement**,
//! en-deçà même de `max_rate_pps`. À l'inverse, une suite de réponses saines le
//! laisse **remonter progressivement** vers le plafond, sans jamais le dépasser.
//!
//! Le contrôleur est **entièrement déterministe** : il ne lit aucune horloge et
//! ne travaille qu'en **paquets par seconde entiers** (pas de flottant), de
//! sorte qu'un test pilote la séquence d'observations et vérifie le débit sans
//! rien attendre. Il s'appuie sur [`crate::rate::TokenBucket`] : le débit
//! courant produit le seau à jetons qui plafonne réellement l'émission (un seul
//! code de limitation dans tout l'outil, §3.2 étape 7).

use crate::rate::TokenBucket;

/// Signe observé après une interaction avec la cible, qui règle le débit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StressSignal {
    /// Réponse normale et rapide : la cible encaisse, on peut remonter.
    Healthy,
    /// Latence anormalement haute : la cible peine, on ralentit.
    SlowResponse,
    /// Connexion coupée par la cible (RST) : signe de surcharge, on ralentit.
    Reset,
    /// Aucune réponse dans le délai imparti : on ralentit.
    Timeout,
}

impl StressSignal {
    /// Vrai si le signe traduit un stress de la cible (tout sauf `Healthy`).
    #[must_use]
    pub fn is_stress(self) -> bool {
        !matches!(self, StressSignal::Healthy)
    }
}

/// Contrôleur de back-off adaptatif, en paquets/seconde entiers.
///
/// Décroissance **multiplicative** (on divise le débit par deux à chaque signe
/// de stress) et remontée **additive** (petits paliers quand tout va bien) : la
/// réaction au stress est franche, la reprise prudente (AIMD, comme un contrôle
/// de congestion). Le débit reste borné dans `[min_pps, max_pps]`.
#[derive(Debug, Clone)]
pub struct AdaptiveBackoff {
    max_pps: u32,
    min_pps: u32,
    step_pps: u32,
    current_pps: u32,
}

impl AdaptiveBackoff {
    /// Contrôleur neuf partant du plafond `max_rate_pps`. Le plancher vaut au
    /// moins 1 pps (on ne s'arrête jamais totalement de progresser) et le palier
    /// de remontée un dixième du plafond (au moins 1).
    #[must_use]
    pub fn new(max_rate_pps: u32) -> Self {
        let max_pps = max_rate_pps.max(1);
        let min_pps = (max_pps / 20).max(1);
        let step_pps = (max_pps / 10).max(1);
        Self {
            max_pps,
            min_pps,
            step_pps,
            current_pps: max_pps,
        }
    }

    /// Débit plafond configuré (jamais dépassé).
    #[must_use]
    pub fn max_pps(&self) -> u32 {
        self.max_pps
    }

    /// Débit courant autorisé, toujours dans `[min_pps, max_pps]`.
    #[must_use]
    pub fn effective_pps(&self) -> u32 {
        self.current_pps
    }

    /// Vrai si le débit est actuellement bridé sous le plafond.
    #[must_use]
    pub fn is_throttled(&self) -> bool {
        self.current_pps < self.max_pps
    }

    /// Intègre une observation : stress → on divise le débit par deux (plancher
    /// `min_pps`) ; sain → on remonte d'un palier (plafond `max_pps`).
    pub fn observe(&mut self, signal: StressSignal) {
        if signal.is_stress() {
            self.current_pps = (self.current_pps / 2).max(self.min_pps);
        } else {
            let raised = self.current_pps.saturating_add(self.step_pps);
            self.current_pps = raised.min(self.max_pps);
        }
    }

    /// Seau à jetons calé sur le **débit courant** : c'est lui qui plafonne
    /// réellement l'émission (réutilise [`TokenBucket`], §3.2 étape 7). À
    /// reconstruire après un changement de débit.
    #[must_use]
    pub fn throttled_bucket(&self) -> TokenBucket {
        TokenBucket::new(self.current_pps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_du_plafond_et_non_bride() {
        let backoff = AdaptiveBackoff::new(200);
        assert_eq!(backoff.effective_pps(), 200);
        assert!(!backoff.is_throttled());
    }

    #[test]
    fn le_stress_fait_chuter_le_debit_sous_le_plafond() {
        // Latence/RST/timeout : chacun divise le débit par deux.
        let mut backoff = AdaptiveBackoff::new(200);
        backoff.observe(StressSignal::SlowResponse);
        assert_eq!(backoff.effective_pps(), 100);
        backoff.observe(StressSignal::Reset);
        assert_eq!(backoff.effective_pps(), 50);
        backoff.observe(StressSignal::Timeout);
        assert_eq!(backoff.effective_pps(), 25);
        assert!(backoff.is_throttled());
    }

    #[test]
    fn remonte_progressivement_quand_tout_va_bien() {
        let mut backoff = AdaptiveBackoff::new(200);
        // On casse d'abord le débit…
        for _ in 0..5 {
            backoff.observe(StressSignal::Timeout);
        }
        let bas = backoff.effective_pps();
        assert!(bas < 200);
        // …puis une réponse saine ne remonte que d'un palier (200/10 = 20).
        backoff.observe(StressSignal::Healthy);
        assert_eq!(backoff.effective_pps(), bas + 20);
    }

    #[test]
    fn ne_depasse_jamais_le_plafond() {
        // Plein de réponses saines ne font jamais franchir max_rate_pps.
        let mut backoff = AdaptiveBackoff::new(50);
        for _ in 0..100 {
            backoff.observe(StressSignal::Healthy);
        }
        assert_eq!(backoff.effective_pps(), 50);
        assert!(!backoff.is_throttled());
    }

    #[test]
    fn ne_tombe_jamais_a_zero() {
        // Même sous un stress continu, le débit garde un plancher strictement
        // positif : l'outil ralentit, il ne se fige pas.
        let mut backoff = AdaptiveBackoff::new(200);
        for _ in 0..50 {
            backoff.observe(StressSignal::Reset);
        }
        assert!(backoff.effective_pps() >= 1);
        assert!(backoff.effective_pps() <= backoff.max_pps());
    }

    #[test]
    fn le_seau_suit_le_debit_courant() {
        use chrono::{DateTime, TimeDelta, Utc};
        fn t0() -> DateTime<Utc> {
            DateTime::from_timestamp(1_700_000_000, 0).unwrap()
        }

        // Débit ramené à 2 pps : le seau n'accorde que 2 jetons au même instant.
        let mut backoff = AdaptiveBackoff::new(8);
        backoff.observe(StressSignal::Timeout); // 8 -> 4
        backoff.observe(StressSignal::Timeout); // 4 -> 2
        assert_eq!(backoff.effective_pps(), 2);

        let mut bucket = backoff.throttled_bucket();
        let now = t0();
        assert!(bucket.available(now));
        bucket.consume(now);
        assert!(bucket.available(now));
        bucket.consume(now);
        assert!(!bucket.available(now), "seau bridé épuisé après 2 jetons");
        // Il se recharge au débit courant (2 pps) une seconde plus tard.
        assert!(bucket.available(now + TimeDelta::seconds(1)));
    }
}
