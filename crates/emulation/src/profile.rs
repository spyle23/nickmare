//! Profils d'adversaire (N4) : `noisy | balanced | stealth` et le **comportement
//! d'évasion** associé (issue #22, cf. `docs/ARCHITECTURE.md` §9 Phase 8, §11.3,
//! US-G3).
//!
//! # L'évasion joue vis-à-vis de la CIBLE, jamais de l'opérateur
//!
//! Le profil règle l'agressivité/furtivité rejouée **vis-à-vis de la cible** :
//! en `stealth`, l'évasion tente réellement de passer sous le radar de la défense
//! (timing low-and-slow, fragmentation, obfuscation de trafic), ce qui est la
//! seule manière de mesurer honnêtement la détection (§1). Ce comportement décrit
//! ce que l'outil **tente contre la cible** — il ne touche **jamais** au traçage
//! côté opérateur : quel que soit le profil, chaque exécution reste horodatée en
//! clair au journal d'audit N4 (invariant §11.3, appliqué par `attack.rs`).
//!
//! Ici, l'« évasion » est **purement descriptive** (des drapeaux déterministes) :
//! aucune évasion réelle d'EDR n'est exécutée, en CI comme ailleurs dans ce crate.

use nickmare_core::model::AdversaryProfile;
use nickmare_core::scope::ScopeProfile;

/// Comportement d'évasion **vis-à-vis de la cible** associé à un profil. Les
/// drapeaux décrivent les catégories ATT&CK d'évasion tentées (timing,
/// fragmentation, obfuscation) ; ils ne modifient **jamais** le traçage opérateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileBehavior {
    profile: AdversaryProfile,
    timing_jitter: bool,
    fragmentation: bool,
    traffic_obfuscation: bool,
}

impl ProfileBehavior {
    /// Comportement d'évasion canonique d'un profil.
    ///
    /// - `noisy` : aucune évasion — l'activité est volontairement visible ;
    /// - `balanced` : timing low-and-slow seul ;
    /// - `stealth` : timing + fragmentation + obfuscation de trafic (évasion
    ///   effective vis-à-vis de la cible).
    #[must_use]
    pub fn for_profile(profile: AdversaryProfile) -> Self {
        match profile {
            AdversaryProfile::Noisy => Self {
                profile,
                timing_jitter: false,
                fragmentation: false,
                traffic_obfuscation: false,
            },
            AdversaryProfile::Balanced => Self {
                profile,
                timing_jitter: true,
                fragmentation: false,
                traffic_obfuscation: false,
            },
            AdversaryProfile::Stealth => Self {
                profile,
                timing_jitter: true,
                fragmentation: true,
                traffic_obfuscation: true,
            },
        }
    }

    /// Comportement dérivé d'un profil tel qu'écrit dans le scope.
    #[must_use]
    pub fn from_scope(profile: ScopeProfile) -> Self {
        Self::for_profile(profile.into())
    }

    /// Profil d'adversaire sous-jacent.
    #[must_use]
    pub fn profile(&self) -> AdversaryProfile {
        self.profile
    }

    /// Vrai si un décalage temporel (low-and-slow) est appliqué vers la cible.
    #[must_use]
    pub fn timing_jitter(&self) -> bool {
        self.timing_jitter
    }

    /// Vrai si la fragmentation est appliquée vers la cible.
    #[must_use]
    pub fn fragmentation(&self) -> bool {
        self.fragmentation
    }

    /// Vrai si l'obfuscation de trafic est appliquée vers la cible.
    #[must_use]
    pub fn traffic_obfuscation(&self) -> bool {
        self.traffic_obfuscation
    }

    /// Vrai si le profil tente **effectivement** une évasion vis-à-vis de la cible
    /// (tout profil autre que `noisy`).
    #[must_use]
    pub fn attempts_evasion(&self) -> bool {
        self.timing_jitter || self.fragmentation || self.traffic_obfuscation
    }

    /// Résumé **opérateur** (en clair) des catégories d'évasion tentées vers la
    /// cible. Destiné à la note de l'`AttackExecution` et au journal — jamais à
    /// masquer quoi que ce soit côté opérateur.
    #[must_use]
    pub fn evasion_summary(&self) -> String {
        if !self.attempts_evasion() {
            return "aucune (profil bruyant, activité visible de la cible)".to_string();
        }
        let mut parts: Vec<&str> = Vec::new();
        if self.timing_jitter {
            parts.push("timing low-and-slow");
        }
        if self.fragmentation {
            parts.push("fragmentation");
        }
        if self.traffic_obfuscation {
            parts.push("obfuscation de trafic");
        }
        parts.join(", ")
    }
}

/// Analyse un libellé de profil (CLI/scope), insensible à la casse et aux espaces.
/// Inconnu → `None` (fail-safe : on ne devine pas un profil d'adversaire).
#[must_use]
pub fn parse_profile(raw: &str) -> Option<AdversaryProfile> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "noisy" => Some(AdversaryProfile::Noisy),
        "balanced" => Some(AdversaryProfile::Balanced),
        "stealth" => Some(AdversaryProfile::Stealth),
        _ => None,
    }
}

/// Libellé stable (minuscule) d'un profil, pour l'affichage et les rapports.
#[must_use]
pub fn profile_label(profile: AdversaryProfile) -> &'static str {
    match profile {
        AdversaryProfile::Noisy => "noisy",
        AdversaryProfile::Balanced => "balanced",
        AdversaryProfile::Stealth => "stealth",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noisy_ne_tente_aucune_evasion() {
        let behavior = ProfileBehavior::for_profile(AdversaryProfile::Noisy);
        assert!(!behavior.attempts_evasion());
        assert!(!behavior.timing_jitter());
        assert!(!behavior.fragmentation());
        assert!(!behavior.traffic_obfuscation());
        assert!(behavior.evasion_summary().contains("aucune"));
    }

    #[test]
    fn balanced_applique_un_timing_low_and_slow() {
        let behavior = ProfileBehavior::for_profile(AdversaryProfile::Balanced);
        assert!(behavior.attempts_evasion());
        assert!(behavior.timing_jitter());
        assert!(!behavior.fragmentation());
    }

    #[test]
    fn stealth_tente_une_evasion_effective_complete() {
        let behavior = ProfileBehavior::for_profile(AdversaryProfile::Stealth);
        assert_eq!(behavior.profile(), AdversaryProfile::Stealth);
        assert!(behavior.attempts_evasion());
        assert!(behavior.timing_jitter());
        assert!(behavior.fragmentation());
        assert!(behavior.traffic_obfuscation());
        let summary = behavior.evasion_summary();
        assert!(summary.contains("fragmentation"));
        assert!(summary.contains("obfuscation"));
    }

    #[test]
    fn depuis_le_profil_de_scope() {
        let behavior = ProfileBehavior::from_scope(ScopeProfile::Stealth);
        assert_eq!(behavior.profile(), AdversaryProfile::Stealth);
    }

    #[test]
    fn parse_profil_insensible_a_la_casse_et_fail_safe() {
        assert_eq!(parse_profile("STEALTH"), Some(AdversaryProfile::Stealth));
        assert_eq!(parse_profile("  noisy "), Some(AdversaryProfile::Noisy));
        assert_eq!(parse_profile("balanced"), Some(AdversaryProfile::Balanced));
        assert_eq!(parse_profile("inconnu"), None);
    }

    #[test]
    fn libelle_de_profil_stable() {
        assert_eq!(profile_label(AdversaryProfile::Noisy), "noisy");
        assert_eq!(profile_label(AdversaryProfile::Balanced), "balanced");
        assert_eq!(profile_label(AdversaryProfile::Stealth), "stealth");
    }
}
