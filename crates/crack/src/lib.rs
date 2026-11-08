//! Crate `crack` de Nickmare — **craquage de credentials** (N3), délégué à
//! **hashcat / John** et confiné par le gate (issue #21, cf.
//! `docs/ARCHITECTURE.md` §5, §9 Phase 7, §11.1, US-F1/F2/F3).
//!
//! # Principe : la valeur livrable est la **politique**, pas les secrets
//!
//! Nickmare **ne réimplémente pas** un moteur de craquage (§5) : il orchestre un
//! moteur éprouvé — hashcat ou John — en **sous-processus**, parse sa sortie et en
//! tire une **évaluation de politique de mots de passe**. Le rapport porte des
//! **statistiques** (taux de craquage, patterns faibles) et **jamais** les mots de
//! passe en clair (§1, §7, US-F1). Le type [`MaskedSecret`](engine::MaskedSecret)
//! garantit ce masquage par défaut dans `Debug`, `Display` et `serde` — le clair
//! n'est révélé que derrière une décision explicite
//! ([`SecretDisclosure`](engine::SecretDisclosure)).
//!
//! # Trois modules
//!
//! - [`engine`] — le trait [`CrackEngine`](engine::CrackEngine) (craquage **hors
//!   ligne**) + [`SprayEngine`](engine::SprayEngine) (spray **en ligne**, borné)
//!   et leurs **mocks déterministes** ; l'orchestration qui fait **traverser le
//!   gate** à chaque action (§3.2/§4) et produit un [`CrackResult`] + une entrée
//!   d'audit. Aucun craquage réel en CI.
//! - [`hashcat`] — l'orchestration hashcat/John en sous-processus au-dessus d'une
//!   **abstraction injectable** du lanceur ([`ProcessRunner`](hashcat::ProcessRunner),
//!   comme le transport MSF de #19) : construction de l'invocation (mapping des
//!   **modes** NTLM/Kerberos/Unix/WPA), parsing de la sortie `--show`, détection
//!   de présence de l'outil (absent → **désactivation propre**), et **teardown
//!   garanti** des fichiers temporaires de hashes (RAII, §11.1).
//! - [`policy`] — l'évaluation → [`PolicyVerdict`] : patterns faibles (mot de dico
//!   + année, réutilisation, longueur insuffisante) et taux de craquage (US-F2).
//!
//! # Les garde-fous restent dans le gate (le « mur »)
//!
//! Ce crate **ne porte aucun** garde-fou : capacité `cracking`, opt-in
//! `online_spray`, confirmation humaine du spray et plafond
//! `max_attempts_per_account` (anti-lockout) sont l'affaire exclusive de
//! [`nickmare_core::gate`] (§3.2, §4), seul chemin vers un moteur. Le spray en
//! ligne est **désactivé par défaut** et n'est actionné qu'après un
//! `Decision::Allow`. Un refus (capacité off, dépassement du plafond) se produit
//! **avant** toute action et donne un audit `blocked_*`.
//!
//! # Aucun craquage réel en CI
//!
//! Le lanceur de sous-processus est une **abstraction injectable** : en CI, un
//! [`ScriptedRunner`](hashcat::ScriptedRunner) rejoue des sorties de **fixtures**
//! (`testdata/crack/`) **sans jamais lancer hashcat/John** (§10.2). Le scénario
//! « craquage de hashes de test connus » (lab §10.3) est une **procédure
//! manuelle** hors CI (cf. `testdata/crack/README.md`).
//!
//! [`CrackResult`]: nickmare_core::model::CrackResult
//! [`PolicyVerdict`]: nickmare_core::model::PolicyVerdict

pub mod engine;
pub mod hashcat;
pub mod policy;

/// Nom de la crate — jalon trivial « hello workspace » (issue #1), conservé pour
/// la matrice CI.
#[must_use]
pub fn nom_crate() -> &'static str {
    "crack"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_workspace() {
        assert_eq!(nom_crate(), "crack");
    }
}
