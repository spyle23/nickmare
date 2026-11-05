//! Seau à jetons (`TokenBucket`) — brique de limitation de débit `max_rate_pps`
//! partagée (cf. `docs/ARCHITECTURE.md` §3.2 étape 7, §11.1).
//!
//! Extrait du gate (issue #4) pour être **réutilisé sans réimplémentation** par
//! la découverte réseau passive (issue #7, `net::discovery`) :
//!
//! - le **gate** plafonne les actions **actives** (étape 7, consommation d'un
//!   jeton par action autorisée) ;
//! - la **découverte passive** — qui ne traverse pas le gate (§3.0/§3.2) —
//!   plafonne elle-même l'émission de ses sondes ARP/ICMP, au même débit, via
//!   ce même seau.
//!
//! Un seul code, deux usages : le débit plafonné a une définition unique dans
//! tout l'outil.
//!
//! Le seau est **déterministe vis-à-vis de l'instant fourni** : il ne lit aucune
//! horloge réelle, de sorte qu'un test contrôle entièrement le temps et vérifie
//! le plafonnement sans rien attendre.

use chrono::{DateTime, Utc};

/// Seau à jetons pour `max_rate_pps` : capacité = débit, remplissage linéaire au
/// même débit. Chaque action/sonde consomme un jeton. Déterministe vis-à-vis de
/// l'instant fourni (testable sans horloge réelle).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    rate_per_sec: f64,
    tokens: f64,
    last: Option<DateTime<Utc>>,
}

impl TokenBucket {
    /// Seau plein pour un débit de `pps` paquets/seconde.
    #[must_use]
    pub fn new(pps: u32) -> Self {
        let capacity = f64::from(pps);
        Self {
            capacity,
            rate_per_sec: capacity,
            tokens: capacity,
            last: None,
        }
    }

    /// Jetons disponibles à l'instant `now`, après remplissage (sans mutation).
    fn refilled(&self, now: DateTime<Utc>) -> f64 {
        match self.last {
            // Jamais utilisé : le seau est plein.
            None => self.capacity,
            Some(last) => {
                let elapsed_secs = (now - last).num_milliseconds().max(0) as f64 / 1000.0;
                (self.tokens + elapsed_secs * self.rate_per_sec).min(self.capacity)
            }
        }
    }

    /// Vrai s'il reste au moins un jeton à l'instant `now`.
    #[must_use]
    pub fn available(&self, now: DateTime<Utc>) -> bool {
        self.refilled(now) >= 1.0
    }

    /// Consomme un jeton à l'instant `now` (remplit puis retranche). À n'appeler
    /// qu'après avoir vérifié [`available`](Self::available) : le seau ne descend
    /// jamais sous zéro, mais consommer un seau vide ne « crée » pas de jeton.
    pub fn consume(&mut self, now: DateTime<Utc>) {
        self.tokens = (self.refilled(now) - 1.0).max(0.0);
        self.last = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn seau_plein_au_depart() {
        // Un seau neuf dispose de `pps` jetons sans avoir rien consommé.
        let bucket = TokenBucket::new(3);
        assert!(bucket.available(t0()));
    }

    #[test]
    fn debit_nul_jamais_disponible() {
        // Capacité 0 : aucun jeton, jamais disponible (l'appelant traite 0 comme
        // « pas de limite » en amont ; ici la sémantique brute est : seau vide).
        let bucket = TokenBucket::new(0);
        assert!(!bucket.available(t0()));
    }

    #[test]
    fn consomme_jusqua_epuisement_au_meme_instant() {
        // Débit 2 : deux consommations au même instant, la 3e trouve le seau vide.
        let mut bucket = TokenBucket::new(2);
        let now = t0();
        assert!(bucket.available(now));
        bucket.consume(now);
        assert!(bucket.available(now));
        bucket.consume(now);
        assert!(!bucket.available(now), "le seau doit être vide après 2 jetons");
    }

    #[test]
    fn se_remplit_avec_le_temps() {
        // Après épuisement, le seau se recharge au débit configuré (2 pps).
        let mut bucket = TokenBucket::new(2);
        let now = t0();
        bucket.consume(now);
        bucket.consume(now);
        assert!(!bucket.available(now));
        // Une demi-seconde plus tard : 1 jeton rechargé (2 pps × 0,5 s).
        assert!(bucket.available(now + TimeDelta::milliseconds(500)));
    }

    #[test]
    fn ne_depasse_jamais_la_capacite() {
        // Resté inactif longtemps, le seau plafonne à sa capacité : exactement
        // `capacity` jetons disponibles, pas davantage.
        let mut bucket = TokenBucket::new(2);
        let now = t0();
        bucket.consume(now);
        // Dix secondes d'inactivité (largement de quoi « déborder »).
        let later = now + TimeDelta::seconds(10);
        bucket.consume(later);
        bucket.consume(later);
        // Deux jetons consommés au plafond, le 3e au même instant est refusé.
        assert!(!bucket.available(later));
    }
}
