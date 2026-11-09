//! Crate `emulation` de Nickmare — **émulation d'adversaire & test de détection**
//! (N4, issue #22, cf. `docs/ARCHITECTURE.md` §2, §9 Phase 8, §11.3,
//! US-G1/G2/G3). Finalité **défensive** : mesurer la capacité de détection de la
//! blue team (purple teaming autorisé), pas attaquer furtivement.
//!
//! # Invariant central : transparence opérateur absolue
//!
//! « Évasion **effective** vis-à-vis de la **cible**, exécution **toujours en
//! clair** au journal **opérateur**. » L'outil peut tenter de ne pas se faire
//! détecter par la cible/son SOC — c'est le sujet même du test — mais il ne se
//! cache **jamais** de l'opérateur : chaque exécution de technique produit un
//! [`AttackExecution`](nickmare_core::model::AttackExecution) horodaté en clair
//! **quel que soit le profil, y compris `stealth`**, et une entrée d'audit N4 est
//! **toujours** émise. C'est l'asymétrie — furtif dehors, transparent dedans — qui
//! distingue cet outil d'un malware (§11.3), et elle n'est pas paramétrable.
//!
//! # Quatre modules
//!
//! - [`techniques`] — mapping **statique JSON** des techniques ATT&CK
//!   (identifiants + libellés, aucune implémentation d'exploit) ;
//! - [`profile`] — profils d'adversaire `noisy | balanced | stealth` et le
//!   comportement d'évasion rejoué **vis-à-vis de la cible** ;
//! - [`attack`] — l'orchestration qui fait **traverser le gate** à chaque
//!   technique (§3.2/§4), trace un `AttackExecution` et rappelle le contact SOC ;
//! - [`verdict`] — collecte des verdicts de détection, calcul du **MTTD** et
//!   **matrice de couverture ATT&CK** (JSON + structurée, comparaison des profils).
//!
//! # Les garde-fous restent dans le gate (le « mur »)
//!
//! Ce crate **ne porte aucun** garde-fou : la whitelist `emulation.attack_techniques`
//! (seules les techniques listées sont exécutables), le confinement au périmètre et
//! les plafonds sont l'affaire exclusive de [`nickmare_core::gate`] (§3.2, étape 3),
//! seul chemin vers le moteur. Une technique non listée est **refusée + auditée**.
//!
//! # Aucune technique réelle en CI
//!
//! Le moteur d'émission est une **abstraction injectable** : en test,
//! [`attack::MockEmulationEngine`] rejoue une émission **déterministe sans vrai
//! payload, sans réseau et sans vraie évasion d'EDR** (§10.2). Les tests valident
//! le filtrage, le traçage, le MTTD et la matrice — jamais une attaque réelle.

pub mod attack;
pub mod profile;
pub mod techniques;
pub mod verdict;

/// Nom de la crate — jalon trivial « hello workspace » (issue #1), conservé pour
/// la matrice CI.
#[must_use]
pub fn nom_crate() -> &'static str {
    "emulation"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_workspace() {
        assert_eq!(nom_crate(), "emulation");
    }
}
